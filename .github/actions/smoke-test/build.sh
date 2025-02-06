#!/bin/bash
IMAGE="$1"

set -e

export DOCKER_BUILDKIT=1
echo "(*) Installing @devcontainer/cli"
npm install -g @devcontainers/cli

echo "(*) Building image - ${IMAGE}"
id_label="test-container=${IMAGE}"

echo "USER_UID: $USER_UID"
echo "USER_GID: $USER_GID"

if [ $IMAGE == "universal" ]; then
    devcontainer up --id-label ${id_label} --workspace-folder "src/${IMAGE}/" 

else
    devcontainer up --id-label ${id_label} --workspace-folder "src/${IMAGE}/"
fi
 
