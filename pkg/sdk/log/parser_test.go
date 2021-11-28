// Copyright © 2021 Banzai Cloud
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

package log

import (
	"reflect"
	"testing"

	"gopkg.in/mcuadros/go-syslog.v2/format"
)

func generateTestLogparts() (format.LogParts, format.LogParts) {
	logMessageOK := map[string]string{
		"client":  "10.124.1.33:36977",
		"content": "2021-10-28T09:31:18Z token-inj /vault/vault-env[1]: time=\"2021-10-28T09:31:18Z\" level=fatal msg=\"failed to inject secrets from vault: key 'value' not found under path: secret/data/dynamodbToken\" app=vault-env facility:0 hostname:10.124.1.33 priority:2 severity:2 tag: timestamp:2021-10-28 09:31:18 +0000 UTC tls_peer:",
	}
	logPartsOK := make(map[string]interface{}, len(logMessageOK))
	for k, v := range logMessageOK {
		logPartsOK[k] = v
	}
	logMessageFailed := map[string]string{
		"client":  "",
		"content": "",
	}
	logPartsFailed := make(map[string]interface{}, len(logMessageFailed))
	for k, v := range logMessageFailed {
		logPartsFailed[k] = v
	}
	return logPartsOK, logPartsFailed
}

func TestGetClientFromLog(t *testing.T) {
	logPartsOK, logPartsFailed := generateTestLogparts()
	type args struct {
		logParts format.LogParts
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "ip found",
			args: args{
				logParts: logPartsOK,
			},
			want:    "10.124.1.33",
			wantErr: false,
		},
		{
			name: "client is empty",
			args: args{
				logParts: logPartsFailed,
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "missing client",
			args: args{
				logParts: format.LogParts{},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetClientFromLog(tt.args.logParts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetClientFromLog() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetClientFromLog() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetContentFromLog(t *testing.T) {
	logPartsOK, logPartsFailed := generateTestLogparts()
	type args struct {
		logParts format.LogParts
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "parse message OK",
			args: args{
				logParts: logPartsOK,
			},
			want: []string{
				"level=fatal msg=\"failed to inject secrets from vault: key 'value' not found under path: secret/data/dynamodbToken\" app=vault-env facility:0 hostname:10.124.1.33 priority:2 severity:2 tag: timestamp:2021-10-28 09:31:18 +0000 UTC tls_peer:",
				"level=fatal",
				"msg=\"failed to inject secrets from vault: key 'value' not found under path: secret/data/dynamodbToken\"",
				" app=vault-env facility:0 hostname:10.124.1.33 priority:2 severity:2 tag: timestamp:2021-10-28 09:31:18 +0000 UTC tls_peer:",
			},
			wantErr: false,
		},
		{
			name: "unknown message",
			args: args{
				logParts: logPartsFailed,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "content is missing",
			args: args{
				logParts: format.LogParts{},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetContentFromLog(tt.args.logParts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetContentFromLog() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetContentFromLog() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseLogMessage(t *testing.T) {
	type args struct {
		content []string
	}
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "vault path not found",
			args: args{
				content: []string{
					"level=fatal msg=\"failed to inject secrets from vault: path not found: secret/data/dynamodbToken\" app=vault-env facility:0 hostname:10.124.1.33 priority:2 severity:2 tag: timestamp:2021-10-28 09:31:18 +0000 UTC tls_peer:",
					"level=fatal",
					"msg=\"failed to inject secrets from vault: path not found: secret/data/dynamodbToken\"",
					" app=vault-env facility:0 hostname:10.124.1.33 priority:2 severity:2 tag: timestamp:2021-10-28 09:31:18 +0000 UTC tls_peer:",
				},
			},
			want: map[string]string{
				"secret/data/dynamodbToken": "msg=\"failed to inject secrets from vault: path not found: secret/data/dynamodbToken\"",
			},
		},
		{
			name: "key not found on vault path",
			args: args{
				content: []string{
					"level=fatal msg=\"failed to inject secrets from vault: key 'value' not found under path: secret/data/dynamodbToken\" app=vault-env facility:0 hostname:10.124.1.33 priority:2 severity:2 tag: timestamp:2021-10-28 09:31:18 +0000 UTC tls_peer:",
					"level=fatal",
					"msg=\"failed to inject secrets from vault: key 'value' not found under path: secret/data/dynamodbToken\"",
					" app=vault-env facility:0 hostname:10.124.1.33 priority:2 severity:2 tag: timestamp:2021-10-28 09:31:18 +0000 UTC tls_peer:",
				},
			},
			want: map[string]string{
				"secret/data/dynamodbToken#value": "msg=\"failed to inject secrets from vault: key 'value' not found under path: secret/data/dynamodbToken\"",
			},
		},
		{
			name: "tls error",
			args: args{
				content: []string{
					"level=error msg=\"failed to request new Vault token\" app=vault-env err=\"Put \\\"https://vault.securecn-vault:8200/v1/auth/kubernetes/login\\\": x509: certificate signed by unknown authority (possibly because of \\\"crypto/rsa: verification error\\\" while trying to verify candidate authority certificate \\\"Root CA\\\")\"",
					"level=error",
					"msg=\"failed to request new Vault token\"",
					" app=vault-env err=\"Put \\\"https://vault.securecn-vault:8200/v1/auth/kubernetes/login\\\": x509: certificate signed by unknown authority (possibly because of \\\"crypto/rsa: verification error\\\" while trying to verify candidate authority certificate \\\"Root CA\\\")\"",
				},
			},
			want: map[string]string{
				ConnectionError: "msg=\"failed to request new Vault token\"  app=vault-env err=\"Put \\\"https://vault.securecn-vault:8200/v1/auth/kubernetes/login\\\": x509: certificate signed by unknown authority (possibly because of \\\"crypto/rsa: verification error\\\" while trying to verify candidate authority certificate \\\"Root CA\\\")\"",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseLogMessage(tt.args.content); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseLogMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}
