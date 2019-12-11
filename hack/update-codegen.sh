#!/bin/bash

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

function finish {
  rm -rf ${CODEGEN_DIR}
}

trap finish EXIT

CODEGEN_DIR=$(mktemp -d)

VERSION=$1

git clone git@github.com:kubernetes/code-generator.git ${CODEGEN_DIR}
cd ${CODEGEN_DIR} && git checkout $VERSION && cd -

# generate the code with:
# --output-base    because this script should also be able to run inside the vendor dir of
#                  k8s.io/kubernetes. The output-base is needed for the generators to output into the vendor dir
#                  instead of the $GOPATH directly. For normal projects this can be dropped.
${CODEGEN_DIR}/generate-groups.sh all \
  github.com/banzaicloud/bank-vaults/operator/pkg/client github.com/banzaicloud/bank-vaults/operator/pkg/apis \
  vault:v1alpha1 \
  --go-header-file ./hack/custom-boilerplate.go.txt
