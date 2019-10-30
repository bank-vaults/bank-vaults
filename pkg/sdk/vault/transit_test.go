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

package vault

import "testing"

func TestIsEncrypted(t *testing.T) {
	// value to valid map
	tests := []struct {
		value string
		valid bool
	}{
		{
			value: "vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==",
			valid: true,
		},
		{
			value: "vault:v100:aGVsbG8=",
			valid: true,
		},
		{
			value: "vault:",
			valid: false,
		},
		{
			value: "vault:v0",
			valid: false,
		},
		{
			value: "vault:v0:",
			valid: false,
		},
		{
			value: "vault:secret/data/accounts/aws#AWS_SECRET_ACCESS_KEY",
			valid: false,
		},
		{
			value: "vault:secret/data/accounts/aws#AWS_SECRET_ACCESS_KEY#version",
			valid: false,
		},
	}
	transit := &Transit{}
	for _, test := range tests {
		if result := transit.IsEncrypted(test.value); result != test.valid {
			t.Errorf("Must be %v, but got %v", test.valid, result)
		}
	}
}
