// Copyright 2017, OpenCensus Authors
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
//

package tag

import (
	"context"
	"reflect"
	"sort"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	k1, _ := NewKey("k1")
	k2, _ := NewKey("k2")
	k3, _ := NewKey("k3 is very weird <>.,?/'\";:`~!@#$%^&*()_-+={[}]|\\")
	k4, _ := NewKey("k4")

	type keyValue struct {
		k Key
		v string
	}

	testCases := []struct {
		label string
		pairs []keyValue
	}{
		{
			"0",
			[]keyValue{},
		},
		{
			"1",
			[]keyValue{
				{k1, "v1"},
			},
		},
		{
			"2",
			[]keyValue{
				{k1, "v1"},
				{k2, "v2"},
			},
		},
		{
			"3",
			[]keyValue{
				{k1, "v1"},
				{k2, "v2"},
				{k3, "v3"},
			},
		},
		{
			"4",
			[]keyValue{
				{k1, "v1"},
				{k2, "v2"},
				{k3, "数据库着火了 🔥🔥🔥"},
				{k4, "v4 is very weird <>.,?/'\";:`~!@#$%^&*()_-+={[}]|\\"},
			},
		},
	}

	for _, tc := range testCases {
		mods := make([]Mutator, len(tc.pairs))
		for i, pair := range tc.pairs {
			mods[i] = Upsert(pair.k, pair.v)
		}
		ctx, err := New(context.Background(), mods...)
		if err != nil {
			t.Errorf("%v: NewMap = %v", tc.label, err)
		}

		encoded := Encode(FromContext(ctx))
		decoded, err := Decode(encoded)
		if err != nil {
			t.Errorf("%v: decoding encoded tag map failed: %v", tc.label, err)
		}

		got := make([]keyValue, 0)
		for k, v := range decoded.m {
			got = append(got, keyValue{k, string(v)})
		}
		want := tc.pairs

		sort.Slice(got, func(i, j int) bool { return got[i].k.name < got[j].k.name })
		sort.Slice(want, func(i, j int) bool { return got[i].k.name < got[j].k.name })

		if !reflect.DeepEqual(got, tc.pairs) {
			t.Errorf("%v: decoded tag map = %#v; want %#v", tc.label, got, want)
		}
	}
}

func TestDecode(t *testing.T) {
	k1, _ := NewKey("k1")
	ctx, _ := New(context.Background(), Insert(k1, "v1"))
	ctx2, _ := New(context.Background(), Insert(k1, "数据库着火了 🔥🔥🔥"))

	tests := []struct {
		name    string
		bytes   []byte
		want    *Map
		wantErr bool
	}{
		{
			name:    "valid",
			bytes:   []byte{0, 0, 2, 107, 49, 2, 118, 49},
			want:    FromContext(ctx),
			wantErr: false,
		},
		{
			name:    "valid (non-ascii value)",
			bytes:   []byte{0x0, 0x0, 0x2, 0x6b, 0x31, 0x1f, 0xe6, 0x95, 0xb0, 0xe6, 0x8d, 0xae, 0xe5, 0xba, 0x93, 0xe7, 0x9d, 0x80, 0xe7, 0x81, 0xab, 0xe4, 0xba, 0x86, 0x20, 0xf0, 0x9f, 0x94, 0xa5, 0xf0, 0x9f, 0x94, 0xa5, 0xf0, 0x9f, 0x94, 0xa5},
			want:    FromContext(ctx2),
			wantErr: false,
		},
		{
			name:    "non-ascii key",
			bytes:   []byte{0, 0, 2, 107, 49, 2, 118, 49, 0, 2, 107, 25, 2, 118, 49},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "long value",
			bytes:   []byte{0, 0, 2, 107, 49, 2, 118, 49, 0, 2, 107, 50, 172, 2, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.bytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				var encoded []byte
				if tt.want != nil {
					encoded = Encode(tt.want)
				}
				t.Errorf("Decode() = %v, want %v = Decode(%#v)", got, tt.want, encoded)
			}
		})
	}
}
