#!/usr/bin/env bash

read -r -d '' EXPECTED <<EOF
// Copyright © DATE Banzai Cloud
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
EOF

STATUS=0
FILES=$(find . -name "*.go" -not -path "./vendor/*")

for FILE in $FILES; do
    # Replace the actual year with DATE so we can ignore the year when
    # checking for the license header.
    HEADER=$(head -n 13 $FILE | sed -E -e 's/Copyright © [0-9]+/Copyright © DATE/')
    if [ "$HEADER" != "$EXPECTED" ]; then
        echo "incorrect license header: $FILE"
        STATUS=1
    fi
done

exit $STATUS
