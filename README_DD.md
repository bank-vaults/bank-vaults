# Bank Vaults

## Tests

### Image build
```bash
PLATFORMS="linux/arm64"
IMAGE_NAME="vault-banks"
IMAGE_TAG="test"
BUILDER_IMAGE="images/mirror/golang:1.23.2"
CONTEXT_DIR="."
DOCKERFILE_NAME=Dockerfile.dd
docker buildx build --platform $PLATFORMS --tag registry.ddbuild.io/$IMAGE_NAME:$IMAGE_TAG --build-arg="BUILDER_IMAGE=registry.ddbuild.io/$BUILDER_IMAGE" --build-arg="BASE_IMAGE=registry.ddbuild.io/images/base/gbi-ubuntu_2204:release" -f "$DOCKERFILE_NAME" "$CONTEXT_DIR"
```

You can then run it:
```bash
IMAGE_ID="TODO"
CONTAINER_NAME="dummy"
docker run --name "$CONTAINER_NAME" -it "$IMAGE_ID"
```

### Create a tag and test build pipeline
```bash
VERSION_NAME="dummy"
COMMIT_HASH="TODO"
git tag -a "$VERSION_NAME" "$COMMIT_HASH" -m "Vault banks image release"
git push origin "$VERSION_NAME"
```
