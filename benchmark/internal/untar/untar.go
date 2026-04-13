//go:build benchmark

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

package untar

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"

	"github.com/google/safearchive/tar"
)

func UnTar(a string) (string, error) {
	dir, err := os.MkdirTemp("", "ec-benchmark")
	if err != nil {
		return "", err
	}

	archive, err := os.Open(a)
	if err != nil {
		return "", err
	}
	defer archive.Close()

	gz, err := gzip.NewReader(archive)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	t := tar.NewReader(gz)
	for {
		hdr, err := t.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}

		dst := path.Join(dir, path.Clean(hdr.Name))
		if hdr.Mode < 0 || hdr.Mode > math.MaxUint32 {
			panic(fmt.Sprintf("weird tar header mode: %d", hdr.Mode))
		}
		mode := fs.FileMode(hdr.Mode)

		switch hdr.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(dst, mode)
		case tar.TypeLink:
			err = os.Symlink(path.Join(dir, path.Clean(hdr.Linkname)), dst)
		case tar.TypeReg:
			var f io.WriteCloser
			f, err = os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, mode)
			if err != nil {
				break
			}

			_, err = io.Copy(f, t)
			if err != nil && !errors.Is(err, io.EOF) {
				break
			}
			err = f.Close()
		}

		if err != nil {
			return "", err
		}
	}

	return dir, nil
}
