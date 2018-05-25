#!/usr/bin/env bash

# misspell
bad_files=$(echo $PKGS | xargs $MISSPELL)
echo $bad_files
if [[ -n "${bad_files}" ]]; then
  echo "✖ misspell needs to be run on the following files: "
  echo "${bad_files}"
  exit 1
fi
