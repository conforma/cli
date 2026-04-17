// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package kind

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	imagespecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	v1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	"oras.land/oras-go/v2"
	orasFile "oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/acceptance/testenv"
)

// buildCliImage builds the ec and kubectl binaries locally, then constructs a
// minimal container image and pushes it to the Kind cluster registry. The image
// is pushed to `localhost:<registry-port>/cli:latest-<os>-<arch>`. Building the
// binaries on the host leverages the warm Go build cache, avoiding the
// redundant Go compilation that the multi-stage production Dockerfile performs.
func (k *kindCluster) buildCliImage(ctx context.Context) error {
	// Build into a directory not excluded by .dockerignore (which excludes
	// dist/) and not conflicting with the versioned binary from make build.
	buildDir := ".acceptance-build"
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		return fmt.Errorf("creating build directory: %w", err)
	}
	defer os.RemoveAll(buildDir)

	// Derive version the same way as the Makefile
	versionCmd := exec.CommandContext(ctx, "hack/derive-version.sh") // #nosec G204
	versionOut, err := versionCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[WARN] Failed to derive version, building without: %v\n", err)
		versionOut = nil
	}
	version := strings.TrimSpace(string(versionOut))

	// Build ec binary locally
	ldflags := "-s -w"
	if version != "" {
		ldflags += " -X github.com/conforma/cli/internal/version.Version=" + version
	}
	ecBinary := filepath.Join(buildDir, "ec")
	ecBuildCmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "--mod=readonly", fmt.Sprintf("-ldflags=%s", ldflags), "-o", ecBinary) // #nosec G204
	if out, err := ecBuildCmd.CombinedOutput(); err != nil {
		fmt.Printf("[ERROR] Failed to build ec binary, %q returned an error: %v\nCommand output:\n", ecBuildCmd, err)
		fmt.Print(string(out))
		return err
	}

	// Build kubectl binary locally
	kubectlBinary := filepath.Join(buildDir, "kubectl")
	kubectlBuildCmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "--mod=readonly", "-modfile", "tools/kubectl/go.mod", "-o", kubectlBinary, "k8s.io/kubernetes/cmd/kubectl") // #nosec G204
	if out, err := kubectlBuildCmd.CombinedOutput(); err != nil {
		fmt.Printf("[ERROR] Failed to build kubectl binary, %q returned an error: %v\nCommand output:\n", kubectlBuildCmd, err)
		fmt.Print(string(out))
		return err
	}

	// Build the container image using the minimal acceptance Dockerfile
	imgTag, err := getTag(ctx)
	if err != nil {
		return fmt.Errorf("getting image tag: %w", err)
	}
	imageRef := fmt.Sprintf("localhost:%d/cli:%s", k.registryPort, imgTag)

	buildImgCmd := exec.CommandContext(ctx, "podman", "build", // #nosec G204
		"-t", imageRef,
		"-f", "acceptance/kubernetes/kind/acceptance.Dockerfile",
		"--build-arg", fmt.Sprintf("EC_BINARY=%s", ecBinary),
		"--build-arg", fmt.Sprintf("KUBECTL_BINARY=%s", kubectlBinary),
		".")
	if out, err := buildImgCmd.CombinedOutput(); err != nil {
		fmt.Printf("[ERROR] Failed to build CLI image, %q returned an error: %v\nCommand output:\n", buildImgCmd, err)
		fmt.Print(string(out))
		return err
	}

	// Push the image to the Kind registry (no TLS)
	pushCmd := exec.CommandContext(ctx, "podman", "push", "--tls-verify=false", imageRef) // #nosec G204
	if out, err := pushCmd.CombinedOutput(); err != nil {
		fmt.Printf("[ERROR] Failed to push CLI image, %q returned an error: %v\nCommand output:\n", pushCmd, err)
		fmt.Print(string(out))
		return err
	}

	return nil
}

// buildTaskBundleImage runs `make task-bundle` for each version of the Task in
// the `$REPOSITORY_ROOT/task` directory to push the Tekton Task bundle to the
// registry running on the Kind cluster. The image is pushed to image reference:
// `localhost:<registry-port>/ec-task-bundle:<version>`, so each bundle contains
// only the task of a particular version. The image reference to the ec
// image is replaced with the image reference from buildCliImage.
func (k *kindCluster) buildTaskBundleImage(ctx context.Context) error {
	taskBundles := make(map[string][]string)

	basePath := "tasks/"
	taskDirs, err := os.ReadDir(basePath)
	if err != nil {
		return err
	}

	for _, task := range taskDirs {
		if !task.IsDir() {
			continue
		}

		taskName := filepath.Clean(task.Name())

		// once all the directories under tasks/ are collected, gather all the versions
		versions, err := filepath.Glob(filepath.Join(basePath, taskName, "*.*"))
		if err != nil {
			return err
		}
		for _, versionPath := range versions {
			pathSplit := strings.Split(versionPath, "/")
			// there should only be versions under the task path i.e. tasks/verify-enterprise-contract/0.1
			version := pathSplit[len(pathSplit)-1]
			// assume the task definition file is named the same as the task directory
			fileName := filepath.Join(versionPath, fmt.Sprintf("%s.yaml", taskName))
			if _, err := os.Stat(fileName); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
			var bytes []byte
			if bytes, err = os.ReadFile(fileName); err != nil {
				return err
			}

			var taskDefinition v1.Task
			if err := yaml.Unmarshal(bytes, &taskDefinition); err != nil {
				return err
			}

			imgTag, err := getTag(ctx)
			if err != nil {
				return err
			}
			// using registry.image-registry.svc.cluster.local instead of 127.0.0.1
			// leads to "dial tcp: lookup registry.image-registry.svc.cluster.local:
			// Temporary failure in name resolution" in Tekton Pipeline controller
			img := fmt.Sprintf("127.0.0.1:%d/cli:%s", k.registryPort, imgTag)
			steps := taskDefinition.Spec.Steps
			for i, step := range steps {
				if strings.Contains(step.Image, "/cli:") {
					steps[i].Image = img
				}
			}

			out, err := yaml.Marshal(taskDefinition)
			if err != nil {
				return err
			}

			tempTask, err := os.CreateTemp("", "v-e-c-*.yaml")
			if err != nil {
				return err
			}
			defer os.Remove(tempTask.Name())

			if _, err = tempTask.Write(out); err != nil {
				return err
			}

			taskBundles[version] = append(taskBundles[version], tempTask.Name())
		}
	}

	for version, tasks := range taskBundles {
		tasksPath := strings.Join(tasks, ",")
		cmd := exec.CommandContext(ctx, "make", "task-bundle", fmt.Sprintf("TASK_REPO=localhost:%d/ec-task-bundle", k.registryPort), fmt.Sprintf("TASKS=%s", tasksPath), fmt.Sprintf("TASK_TAG=%s", version)) /* #nosec */
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("[ERROR] Unable to build and push the Task bundle image, %q returned an error: %v\nCommand output:\n", cmd, err)
			fmt.Print(string(out))
			return err
		}
	}

	return nil
}

// builds a snapshot oci artifact for use with build trusted artifacts
func (k *kindCluster) BuildSnapshotArtifact(ctx context.Context, content string) (context.Context, error) {
	filePath := "snapshotartifact"

	// #nosec G306 -- reduce-snapshot.sh needs these permissions
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return ctx, fmt.Errorf("failed to write JSON to file: %w", err)
	}

	tarGzPath := filePath + ".tar.gz"
	if err := tarGzipFile(filePath, tarGzPath); err != nil {
		return ctx, fmt.Errorf("failed to tar and gzip file: %w", err)
	}

	fs, err := orasFile.New(".")
	if err != nil {
		return ctx, fmt.Errorf("falied to create . dir: %w", err)
	}
	defer fs.Close()

	mediaType := "application/vnd.test.file"
	fileNames := []string{tarGzPath}
	fileDescriptors := make([]imagespecv1.Descriptor, 0, len(fileNames))
	for _, name := range fileNames {
		fileDescriptor, err := fs.Add(ctx, name, mediaType, "")
		if err != nil {
			return ctx, fmt.Errorf("failed to add file %s: %w", name, err)
		}
		fileDescriptors = append(fileDescriptors, fileDescriptor)
		t := testenv.FetchState[testState](ctx)
		if t != nil {
			t.snapshotDigest = fileDescriptor.Digest.String()
		}
		fmt.Printf("file descriptor for %s: %v\n", name, fileDescriptor)
	}

	artifactType := "application/vnd.test.artifact"
	opts := oras.PackManifestOptions{
		Layers: fileDescriptors,
	}
	manifestDescriptor, err := oras.PackManifest(ctx, fs, oras.PackManifestVersion1_1, artifactType, opts)
	if err != nil {
		return ctx, fmt.Errorf("failed creating manifestDescriptor: %w", err)
	}
	fmt.Println("manifest descriptor:", manifestDescriptor)

	tag := "latest"
	if err = fs.Tag(ctx, manifestDescriptor, tag); err != nil {
		return ctx, fmt.Errorf("failed to tag image: %w", err)
	}

	artifactRepo := fmt.Sprintf("127.0.0.1:%d/acceptance/%s", k.registryPort, filePath)
	repo, err := remote.NewRepository(artifactRepo)
	if err != nil {
		return ctx, fmt.Errorf("failed to create repo: %w", err)
	}
	fmt.Println("artifactRepo:", artifactRepo)

	// the registry is insecure
	repo.PlainHTTP = true

	orasDesc, err := oras.Copy(ctx, fs, tag, repo, tag, oras.DefaultCopyOptions)
	if err != nil {
		return ctx, fmt.Errorf("failed to copy %s: %w", filePath, err)
	}
	fmt.Println("snapshotDigest:", orasDesc.Digest)

	return ctx, nil
}

func getTag(ctx context.Context) (string, error) {
	archCmd := exec.CommandContext(ctx, "podman", "version", "-f", "{{.Server.OsArch}}")
	archOut, archErr := archCmd.CombinedOutput()
	if archErr != nil {
		return "", archErr
	}

	return fmt.Sprintf("latest-%s", strings.Replace(strings.TrimSuffix(string(archOut), "\n"), "/", "-", -1)), nil
}

// Tar and gzip a file. Used with trusted artifacts.
func tarGzipFile(source, target string) error {
	srcFile, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("opening source file: %w", err)
	}
	defer srcFile.Close()

	outFile, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("creating target file: %w", err)
	}
	defer outFile.Close()

	gzw := gzip.NewWriter(outFile)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	info, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("getting source file info: %w", err)
	}

	header := &tar.Header{
		Name:    filepath.Base(source),
		Mode:    int64(info.Mode()),
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("writing tar header: %w", err)
	}

	if _, err := io.Copy(tw, srcFile); err != nil {
		return fmt.Errorf("copying file content into tar: %w", err)
	}

	return nil
}
