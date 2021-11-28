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
	"fmt"
	"regexp"
	"strings"

	"emperror.dev/errors"
	syslogformat "gopkg.in/mcuadros/go-syslog.v2/format"
)

const ConnectionError = "connection_error"

var (
	logParserRegexp    = regexp.MustCompile("(level=[a-z]+) (msg=\\\".*\\\")( app=.*)")
	pathNotFoundRegexp = regexp.MustCompile("(path not found:) ([a-z]+/[a-z]+/.*)(\\\")")
	keyNotFoundRegexp  = regexp.MustCompile("('.*') (not found under path:) ([a-z]+/[a-z]+/.*)(\\\")")
)

func GetClientFromLog(logParts syslogformat.LogParts) (string, error) {
	ip := strings.Split(fmt.Sprintf("%s", logParts["client"]), ":")
	if len(ip) < 2 {
		return "", errors.New("failed to get client ip from error message")
	}
	return ip[0], nil
}

func GetContentFromLog(logParts syslogformat.LogParts) ([]string, error) {
	content := logParserRegexp.FindStringSubmatch(fmt.Sprintf("%v", logParts["content"]))
	if content == nil {
		return nil, errors.New("parse error message failed")
	}
	return content, nil
}

func ParseLogMessage(content []string) map[string]string {
	parsedError := make(map[string]string)
	if !(strings.Contains(content[1], "error") || strings.Contains(content[1], "fatal")) {
		return nil
	}
	if path := pathNotFoundRegexp.FindStringSubmatch(content[2]); path != nil {
		parsedError[path[2]] = content[2]
	} else if path := keyNotFoundRegexp.FindStringSubmatch(content[2]); path != nil {
		parsedError[fmt.Sprintf("%s#%s", path[3], strings.Trim(path[1], "'"))] = content[2]
	} else {
		parsedError[ConnectionError] = fmt.Sprintf("%v %v", content[2], content[3])
	}

	return parsedError
}
