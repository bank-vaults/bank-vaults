#!/bin/bash

for chart in vault vault-operator vault-secrets-webhook
do
    version=$(grep version: ./charts/${chart}/Chart.yaml | cut -f2 -d' ')
    git tag chart/${chart}/${version}
    git push origin chart/${chart}/${version}
done
