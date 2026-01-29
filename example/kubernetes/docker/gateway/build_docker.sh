#!/bin/zsh
set -e # Exit immediately if a command exits with a non-zero status.

DOCKER_DIR="$(dirname "$0")"
DOCKER_DIR=${DOCKER_DIR:A}

# To common root of pvxs and p4p projects
PROJECTS=${DOCKER_DIR}/../../../../..
PROJECTS=${PROJECTS:A}
pushd "${PROJECTS}"
RELATIVE_DOCKER_DIR=pvxs/example/kubernetes/docker/gateway

# Add trap to ensure we return to original directory on exit
trap "popd" EXIT

BASE_IMAGE_NAME="lab_base"
BASE_IMAGE_TAG="latest"
TARGET_IMAGE_NAME="gateway"
TARGET_IMAGE_TAG="latest"

echo "--- Building ${TARGET_IMAGE_NAME} Docker image ---"

docker build \
  --build-arg BASE_IMAGE=${BASE_IMAGE_NAME} \
  --build-arg BASE_IMAGE_TAG=${BASE_IMAGE_TAG} \
  --build-arg RELATIVE_DOCKER_DIR=${RELATIVE_DOCKER_DIR} \
  ${*} \
  -t "${DOCKER_USERNAME:-georgeleveln}/${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG}" \
  -f "${DOCKER_DIR}/Dockerfile" \
  .

echo "--- Successfully built ${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG} ---"
