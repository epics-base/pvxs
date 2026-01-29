#!/bin/zsh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Running KDC in local network on ports 8888 and 8749"
echo "Mapping HOME dir onto /opt/home inside container"
echo "Set config as follows:"
echo ""
echo "export KRB5_CONFIG=${SCRIPT_DIR}/krb5-epics-local.conf"

TARGET_IMAGE_NAME="spva_krb"
TARGET_IMAGE_TAG="latest"

docker run -d \
  --name kerberos-kdc \
  -p 8888:88/udp \
  -p 8749:749 \
  -v $HOME/Projects:/opt/home \
  ${DOCKER_USERNAME:-georgeleveln}/${TARGET_IMAGE_NAME}:${TARGET_IMAGE_TAG}
