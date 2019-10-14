// Copyright © 2019 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registry

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	imagev1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestInMemoryImageCache_Get(t *testing.T) {
	type fields struct {
		cache map[string]imagev1.ImageConfig
	}
	type args struct {
		image string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *imagev1.ImageConfig
	}{
		{name: "Can get inserted image",
			fields: fields{
				cache: map[string]imagev1.ImageConfig{
					"ImageA": imagev1.ImageConfig{
						Cmd: []string{"/bin/bash"},
					}, "ImageB": imagev1.ImageConfig{
						Cmd: []string{"entrypoint.sh"},
					},
				},
			},
			args: args{
				image: "ImageA",
			},
			want: &imagev1.ImageConfig{
				Cmd: []string{"/bin/bash"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &InMemoryImageCache{
				cache: tt.fields.cache,
			}
			if got := c.Get(tt.args.image); !cmp.Equal(got, tt.want) {
				t.Errorf("InMemoryImageCache.Get() != Want \n %v", cmp.Diff(got, tt.want))
			}
		})
	}
}

func TestInMemoryImageCache_Put(t *testing.T) {
	type fields struct {
		cache map[string]imagev1.ImageConfig
	}
	type args struct {
		image       string
		imageConfig *imagev1.ImageConfig
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *imagev1.ImageConfig
	}{
		{name: "Can put, then get inserted image",
			fields: fields{
				cache: make(map[string]imagev1.ImageConfig),
			},
			args: args{
				image: "ImageA",
				imageConfig: &imagev1.ImageConfig{
					Cmd: []string{"/bin/bash"},
				},
			},
			want: &imagev1.ImageConfig{
				Cmd: []string{"/bin/bash"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &InMemoryImageCache{
				cache: tt.fields.cache,
			}
			c.Put(tt.args.image, tt.args.imageConfig)
			if got := c.Get(tt.args.image); !cmp.Equal(got, tt.want) {
				t.Errorf("InMemoryImageCache.Put() != Get \n %v", cmp.Diff(got, tt.want))
			}
		})
	}
}
