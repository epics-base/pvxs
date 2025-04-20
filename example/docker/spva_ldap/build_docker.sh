#!/bin/zsh
set -e # Exit immediately if a command exits with a non-zero status.

DOCKER_DIR="$(dirname "$0")"
DOCKER_DIR=${DOCKER_DIR:A}
PROJECTS=${DOCKER_DIR}/../../../..
PROJECTS=${PROJECTS:A}

pushd "${DOCKER_DIR}"

# Add trap to ensure we return to original directory on exit
trap "popd" EXIT

BASE_IMAGE_NAME="spva_std"
BASE_IMAGE_TAG="local"
TARGET_IMAGE_NAME="spva_krb"
TARGET_IMAGE_TAG="local"

echo "--- Building ${TARGET_IMAGE_NAME} Docker image ---"

docker build \
  --build-arg BASE_IMAGE=${BASE_IMAGE_NAME} \
  --build-arg BASE_IMAGE_TAG=${BASE_IMAGE_TAG} \
  -t "${DOCKER_USERNAME:-georgeleveln}/${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG}" \
  -f "${DOCKER_DIR}/Dockerfile" \
  .

echo "--- Successfully built ${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG} ---"
