// Copyright 2019 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"sigs.k8s.io/kustomize/kyaml/errors"
	runtimeexec "sigs.k8s.io/kustomize/kyaml/fn/runtime/exec"
	"sigs.k8s.io/kustomize/kyaml/fn/runtime/runtimeutil"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

// Filter filters Resources using a container image.
// The container must start a process that reads the list of
// input Resources from stdin, reads the Configuration from the env
// API_CONFIG, and writes the filtered Resources to stdout.
// If there is a error or validation failure, the process must exit
// non-zero.
// The full set of environment variables from the parent process
// are passed to the container.
//
// Function Scoping:
// Filter applies the function only to Resources to which it is scoped.
//
// Resources are scoped to a function if any of the following are true:
//   - the Resource were read from the same directory as the function config
//   - the Resource were read from a subdirectory of the function config directory
//   - the function config is in a directory named "functions" and
//     they were read from a subdirectory of "functions" parent
//   - the function config doesn't have a path annotation (considered globally scoped)
//   - the Filter has GlobalScope == true
//
// In Scope Examples:
//
// Example 1: deployment.yaml and service.yaml in function.yaml scope
//
//	       same directory as the function config directory
//	.
//	├── function.yaml
//	├── deployment.yaml
//	└── service.yaml
//
// Example 2: apps/deployment.yaml and apps/service.yaml in function.yaml scope
//
//	       subdirectory of the function config directory
//	.
//	├── function.yaml
//	└── apps
//	    ├── deployment.yaml
//	    └── service.yaml
//
// Example 3: apps/deployment.yaml and apps/service.yaml in functions/function.yaml scope
//
//	       function config is in a directory named "functions"
//	.
//	├── functions
//	│   └── function.yaml
//	└── apps
//	    ├── deployment.yaml
//	    └── service.yaml
//
// Out of Scope Examples:
//
// Example 1: apps/deployment.yaml and apps/service.yaml NOT in stuff/function.yaml scope
//
//	.
//	├── stuff
//	│   └── function.yaml
//	└── apps
//	    ├── deployment.yaml
//	    └── service.yaml
//
// Example 2: apps/deployment.yaml and apps/service.yaml NOT in stuff/functions/function.yaml scope
//
//	   .
//	   ├── stuff
//	   │   └── functions
//	   │       └── function.yaml
//	   └── apps
//	       ├── deployment.yaml
//	       └── service.yaml
//
// Default Paths:
// Resources emitted by functions will have default path applied as annotations
// if none is present.
// The default path will be the function-dir/ (or parent directory in the case of "functions")
// + function-file-name/ + namespace/ + kind_name.yaml
//
// Example 1: Given a function in fn.yaml that produces a Deployment name foo and a Service named bar
//
//	dir
//	└── fn.yaml
//
// Would default newly generated Resources to:
//
//	dir
//	├── fn.yaml
//	└── fn
//	    ├── deployment_foo.yaml
//	    └── service_bar.yaml
//
// Example 2: Given a function in functions/fn.yaml that produces a Deployment name foo and a Service named bar
//
//	dir
//	└── fn.yaml
//
// Would default newly generated Resources to:
//
//	dir
//	├── functions
//	│   └── fn.yaml
//	└── fn
//	    ├── deployment_foo.yaml
//	    └── service_bar.yaml
//
// Example 3: Given a function in fn.yaml that produces a Deployment name foo, namespace baz and a Service named bar namespace baz
//
//	dir
//	└── fn.yaml
//
// Would default newly generated Resources to:
//
//	dir
//	├── fn.yaml
//	└── fn
//	    └── baz
//	        ├── deployment_foo.yaml
//	        └── service_bar.yaml
type Filter struct {
	runtimeutil.ContainerSpec `json:",inline" yaml:",inline"`

	Exec runtimeexec.Filter

	UIDGID string
}

func (c Filter) String() string {
	if c.Exec.DeferFailure {
		return fmt.Sprintf("%s deferFailure: %v", c.Image, c.Exec.DeferFailure)
	}
	return c.Image
}
func (c Filter) GetExit() error {
	return c.Exec.GetExit()
}

func (c *Filter) Filter(nodes []*yaml.RNode) ([]*yaml.RNode, error) {
	if err := c.setupExec(); err != nil {
		return nil, err
	}
	return c.Exec.Filter(nodes)
}

func (c *Filter) setupExec() error {
	// don't init 2x
	if c.Exec.Path != "" {
		return nil
	}

	if c.Exec.WorkingDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return errors.Wrap(err)
		}
		c.Exec.WorkingDir = wd
	}

	path, args := c.getCommand()
	c.Exec.Path = path
	c.Exec.Args = args
	return nil
}

// getCommand returns the command + args to run to spawn the container
func (c *Filter) getCommand() (string, []string) {
	// if EnableKubernetes is true, use kubectl to run the container
	if c.ContainerSpec.EnableKubernetes {
		return c.getKubernetesCommand()
	}

	// otherwise use docker
	return c.getDockerCommand()
}

// getDockerCommand returns the command + args to run to spawn the container in docker
func (c *Filter) getDockerCommand() (string, []string) {
	network := runtimeutil.NetworkNameNone
	if c.ContainerSpec.Network {
		network = runtimeutil.NetworkNameHost
	}
	// run the container using docker.  this is simpler than using the docker
	// libraries, and ensures things like auth work the same as if the container
	// was run from the cli.
	args := []string{"run",
		"--rm",                                              // delete the container afterward
		"-i", "-a", "STDIN", "-a", "STDOUT", "-a", "STDERR", // attach stdin, stdout, stderr
		"--network", string(network),

		// added security options
		"--user", c.UIDGID,
		"--security-opt=no-new-privileges", // don't allow the user to escalate privileges
		// note: don't make fs readonly because things like heredoc rely on writing tmp files
	}

	for _, storageMount := range c.StorageMounts {
		// convert declarative relative paths to absolute (otherwise docker will throw an error)
		if !filepath.IsAbs(storageMount.Src) {
			storageMount.Src = filepath.Join(c.Exec.WorkingDir, storageMount.Src)
		}
		args = append(args, "--mount", storageMount.String())
	}

	args = append(args, runtimeutil.NewContainerEnvFromStringSlice(c.Env).GetDockerFlags()...)
	a := append(args, c.Image) //nolint:gocritic
	return "docker", a
}

// getKubernetesCommand returns the command + args to run to spawn the container in kubernetes
func (c *Filter) getKubernetesCommand() (string, []string) {
	// Use the image name as the pod name
	podName := strings.Split(path.Base(c.Image), ":")[0]

	// Define envs
	envs := []map[string]interface{}{}
	for k, v := range runtimeutil.NewContainerEnvFromStringSlice(c.Env).EnvVars {
		envs = append(envs, map[string]interface{}{
			"name":  k,
			"value": v,
		})
	}

	// Convert envs to JSON
	envsJSON, _ := json.Marshal(envs)

	// Handle UID and GID, default to 65534 (nobody) if c.UIDGID is "nobody"
	uid := "65534"
	gid := "65534"
	if c.UIDGID != "nobody" && c.UIDGID != "" {
		uidgid := strings.Split(c.UIDGID, ":")
		if len(uidgid) == 2 {
			uid = uidgid[0]
			gid = uidgid[1]
		}
	}

	// Define volumes and volume mounts
	volumes := []map[string]interface{}{}
	volumeMounts := []map[string]interface{}{}

	for _, storageMount := range c.StorageMounts {
		// Convert declarative relative paths to absolute
		absPath := storageMount.Src
		if !filepath.IsAbs(storageMount.Src) {
			absPath = filepath.Join(c.Exec.WorkingDir, storageMount.Src)
		}

		// Generate a unique volume name based on the storage mount
		volumeHash := sha256.Sum256([]byte(storageMount.String()))
		volumeName := hex.EncodeToString(volumeHash[:])[:32]

		switch storageMount.MountType {
		case "bind":
			volumes = append(volumes, map[string]interface{}{
				"name": volumeName,
				"hostPath": map[string]interface{}{
					"path": absPath,
				},
			})
		case "tmpfs":
			volumes = append(volumes, map[string]interface{}{
				"name": volumeName,
				"emptyDir": map[string]interface{}{
					"medium": "Memory",
				},
			})
		case "volume":
			volumes = append(volumes, map[string]interface{}{
				"name": volumeName,
				"persistentVolumeClaim": map[string]interface{}{
					"claimName": storageMount.Src,
				},
			})
		default:
			continue
		}

		volumeMounts = append(volumeMounts, map[string]interface{}{
			"name":      volumeName,
			"mountPath": storageMount.DstPath,
		})
	}

	// Convert volumes and volume mounts to JSON
	volumesJSON, _ := json.Marshal(volumes)
	volumeMountsJSON, _ := json.Marshal(volumeMounts)

	// Base kubectl run command
	args := []string{"run", podName,
		"--rm", "--stdin", "--quiet", // Automatically remove the pod, attach stdin, and suppress output
		"--image", c.Image, // Specify the container image
		"--restart=Never", // Do not restart the pod
		"--overrides", fmt.Sprintf(`{
		"apiVersion": "v1",
		"spec": {
			"containers": [{
				"name": "krm-function",
				"image": "%s",
				"stdin": true,
				"stdinOnce": true,
				"env": %s,
				"volumeMounts": %s
			}],
			"securityContext": {
				"runAsUser": %s,
				"runAsGroup": %s,
				"privileged": false,
				"allowPrivilegeEscalation": false
			},
			"hostNetwork": %t,
			"volumes": %s
		}
	}`, c.Image, envsJSON, volumeMountsJSON, uid, gid, c.ContainerSpec.Network, volumesJSON),
	}

	return "kubectl", args
}

// NewContainer returns a new container filter
func NewContainer(spec runtimeutil.ContainerSpec, uidgid string) Filter {
	f := Filter{ContainerSpec: spec, UIDGID: uidgid}

	return f
}
