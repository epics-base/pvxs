#!/bin/zsh
set -e # Exit immediately if a command exits with a non-zero status.

DOCKER_DIR="$(dirname "$0")"
DOCKER_DIR=${DOCKER_DIR:A}
PROJECTS=${DOCKER_DIR}/../../../..
PROJECTS=${PROJECTS:A}

pushd "${PROJECTS}"

# Add trap to ensure we return to original directory on exit
trap "popd" EXIT

IMAGE_NAME="epics-base"
IMAGE_TAG="local"

echo "--- Building ${IMAGE_NAME} Docker image ---"

docker build \
  -t "${DOCKER_USERNAME:-georgeleveln}/${IMAGE_NAME}:${IMAGE_TAG}" \
  -f "${DOCKER_DIR}/Dockerfile" \
  .

echo "--- Successfully built ${IMAGE_NAME}:${IMAGE_TAG} ---"
