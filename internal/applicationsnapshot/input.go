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

package applicationsnapshot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/trace"
	"sort"
	"strconv"

	"github.com/google/go-containerregistry/pkg/name"
	app "github.com/konflux-ci/application-api/api/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/yaml"

	"github.com/conforma/cli/internal/kubernetes"
	"github.com/conforma/cli/internal/utils"
	"github.com/conforma/cli/internal/utils/oci"
)

const (
	unnamed        = "Unnamed"
	workersEnvVar  = "IMAGE_INDEX_WORKERS"
	defaultWorkers = 5
)

type Input struct {
	File     string // Deprecated: replaced by images
	JSON     string // Deprecated: replaced by images
	Image    string
	Snapshot string
	Images   string
}

type snapshot struct {
	app.SnapshotSpec
	Expansion *ExpansionInfo
}

func (s *snapshot) merge(snap app.SnapshotSpec) {
	if s.Application == "" {
		s.Application = snap.Application
	}

	if s.DisplayName == "" {
		s.DisplayName = snap.DisplayName
	}

	if s.DisplayDescription == "" {
		s.DisplayDescription = snap.DisplayDescription
	}

	images := map[string]string{}
	for _, c := range s.Components {
		images[c.ContainerImage] = c.Name
	}
	for _, c := range snap.Components {
		if name, ok := images[c.ContainerImage]; !ok || name == "" || name == unnamed {
			if ok {
				images[c.ContainerImage] = c.Name
				i := slices.IndexFunc(s.Components, func(x app.SnapshotComponent) bool {
					return x.ContainerImage == c.ContainerImage
				})
				s.Components[i].Name = c.Name
			} else {
				images[c.ContainerImage] = c.Name
				s.Components = append(s.Components, c)
			}
		}
	}
}

func DetermineInputSpec(ctx context.Context, input Input) (*app.SnapshotSpec, *ExpansionInfo, error) {
	return DetermineInputSpecWithExpansion(ctx, input, false)
}

func DetermineInputSpecWithExpansion(ctx context.Context, input Input, skipExpansion bool) (*app.SnapshotSpec, *ExpansionInfo, error) {
	var snapshot snapshot
	provided := false

	if input.Images != "" {
		var content []byte
		var err error
		fs := utils.FS(ctx)
		content, err = afero.ReadFile(fs, input.Images)
		if err != nil {
			log.Debugf("could not read images from file: %v", err)
			// could not read as file so expecting string
			content = []byte(input.Images)
		}

		file, err := readSnapshotSource(content)
		if err != nil {
			return nil, nil, err
		}
		snapshot.merge(file)
		provided = true
	}

	// read Snapshot provided as a file
	if input.File != "" {
		fs := utils.FS(ctx)
		content, err := afero.ReadFile(fs, input.File)
		if err != nil {
			return nil, nil, err
		}
		file, err := readSnapshotSource(content)
		if err != nil {
			return nil, nil, err
		}
		snapshot.merge(file)
		provided = true
	}

	// read Snapshot provided as a string
	if input.JSON != "" {
		json, err := readSnapshotSource([]byte(input.JSON))
		if err != nil {
			return nil, nil, err
		}
		snapshot.merge(json)
		provided = true
	}

	// create Snapshot with a single image
	if input.Image != "" {
		log.Debugf("Generating application snapshot from image reference %s", input.Image)
		imageSnapshot := app.SnapshotSpec{
			Components: []app.SnapshotComponent{
				{
					Name:           unnamed,
					ContainerImage: input.Image,
				},
			},
		}
		snapshot.merge(imageSnapshot)
		provided = true
	}

	if input.Snapshot != "" {
		client, err := kubernetes.NewClient(ctx)
		if err != nil {
			log.Debugf("Unable to initialize Kubernetes Client: %v", err)
			return nil, nil, err
		}

		cluster, err := client.FetchSnapshot(ctx, input.Snapshot)
		if err != nil {
			log.Debugf("Unable to fetch snapshot %s from Kubernetes cluster: %v", input.Snapshot, err)
			return nil, nil, err
		}
		snapshot.merge(cluster.Spec)
		provided = true
	}

	if !provided {
		log.Debug("No application snapshot available")
		return nil, nil, errors.New("neither Snapshot nor image reference provided to validate")
	}
	var exp *ExpansionInfo
	if !skipExpansion {
		exp = expandImageIndex(ctx, &snapshot.SnapshotSpec)
	}

	// Store expansion info in the snapshot for later use
	// This will be used when building the Report
	if exp != nil {
		snapshot.Expansion = exp
	}

	return &snapshot.SnapshotSpec, exp, nil
}

func readSnapshotSource(input []byte) (app.SnapshotSpec, error) {
	var file app.SnapshotSpec
	err := yaml.Unmarshal(input, &file)
	if err != nil {
		log.Debugf("Problem parsing application snapshot from file %s", input)
		return app.SnapshotSpec{}, fmt.Errorf("unable to parse Snapshot specification from %s: %w", input, err)
	}

	log.Debugf("Read application snapshot from file %s", input)
	return file, nil
}

// For an image index, remove the original component and replace it with an expanded component with all its image manifests
// Do not raise an error if the image is inaccessible, it will be handled as a violation when evaluated against the policy
// This is to retain the original behavior of the `ec validate` command.
func imageIndexWorker(client oci.Client, component app.SnapshotComponent, componentChan chan<- []app.SnapshotComponent, errorsChan chan<- error, exp *ExpansionInfo) {
	var components []app.SnapshotComponent
	components = append(components, component)
	// to avoid adding to componentsChan before each return
	defer func() {
		componentChan <- components
	}()

	ref, err := name.ParseReference(component.ContainerImage)
	if err != nil {
		errorsChan <- fmt.Errorf("unable to parse container image %s: %w", component.ContainerImage, err)
		return
	}

	desc, err := client.Head(ref)
	if err != nil {
		errorsChan <- fmt.Errorf("unable to fetch descriptior for container image %s: %w", ref, err)
		return
	}

	if !desc.MediaType.IsIndex() {
		return
	}

	index, err := client.Index(ref)
	if err != nil {
		errorsChan <- fmt.Errorf("unable to fetch index for container image %s: %w", component.ContainerImage, err)
		return
	}

	indexManifest, err := index.IndexManifest()
	if err != nil {
		errorsChan <- fmt.Errorf("unable to fetch index manifest for container image %s: %w", component.ContainerImage, err)
		return
	}

	// Track expansion metadata
	idxPinned := fmt.Sprintf("%s@%s", ref.Context().Name(), desc.Digest)
	exp.IndexAliases[ref.Name()] = idxPinned

	// Add the platform-specific image references (Image Manifests) to the list of components so
	// each is validated as well as the multi-platform image reference (Image Index).
	for i, manifest := range indexManifest.Manifests {
		var arch string
		if manifest.Platform != nil && manifest.Platform.Architecture != "" {
			arch = manifest.Platform.Architecture
		} else {
			arch = fmt.Sprintf("noarch-%d", i)
		}
		archComponent := component
		archComponent.Name = fmt.Sprintf("%s-%s-%s", component.Name, manifest.Digest, arch)
		archComponent.ContainerImage = fmt.Sprintf("%s@%s", ref.Context().Name(), manifest.Digest)
		components = append(components, archComponent)

		// Track parent-child relationships
		childPinned := archComponent.ContainerImage
		exp.ChildrenByIndex[idxPinned] = append(exp.ChildrenByIndex[idxPinned], childPinned)
		exp.ParentByChild[childPinned] = idxPinned
	}
}

func expandImageIndex(ctx context.Context, snap *app.SnapshotSpec) *ExpansionInfo {
	if trace.IsEnabled() {
		region := trace.StartRegion(ctx, "ec:expand-image-index")
		defer region.End()
	}

	exp := NewExpansionInfo()
	client := oci.NewClient(ctx)

	componentChan := make(chan []app.SnapshotComponent, len(snap.Components))
	errorsChan := make(chan error, len(snap.Components))
	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(imageWorkers())
	for _, component := range snap.Components {
		// fetch manifests concurrently
		g.Go(func() error {
			imageIndexWorker(client, component, componentChan, errorsChan, exp)
			return nil
		})
	}

	go func() {
		_ = g.Wait()
		close(componentChan)
		close(errorsChan)
	}()

	var components []app.SnapshotComponent
	for component := range componentChan {
		components = append(components, component...)
	}
	snap.Components = components

	sort.Slice(snap.Components, func(i, j int) bool {
		return snap.Components[i].ContainerImage < snap.Components[j].ContainerImage
	})

	var allErrors error = nil
	for err := range errorsChan {
		allErrors = errors.Join(allErrors, err)
	}

	if allErrors != nil {
		log.Warnf("Encountered error while checking for Image Index: %v", allErrors)
	}
	log.Debugf("Snap component after expanding the image index is %v", snap.Components)

	return exp
}

func imageWorkers() int {
	workers := defaultWorkers
	if value, exists := os.LookupEnv(workersEnvVar); exists {
		if parsed, err := strconv.Atoi(value); err == nil {
			workers = parsed
		}
	}
	return workers
}
