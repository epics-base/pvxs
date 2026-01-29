#!/bin/zsh
DOCKER_ROOT_DIR="$(dirname "$0")"
DOCKER_ROOT_DIR=${DOCKER_ROOT_DIR:A}

${DOCKER_ROOT_DIR}/lab_base/build_docker.sh ${*}

${DOCKER_ROOT_DIR}/lab/build_docker.sh ${*}

${DOCKER_ROOT_DIR}/testioc/build_docker.sh ${*}
${DOCKER_ROOT_DIR}/tstioc/build_docker.sh ${*}

${DOCKER_ROOT_DIR}/pvacms/build_docker.sh ${*}

${DOCKER_ROOT_DIR}/gateway/build_docker.sh ${*}
