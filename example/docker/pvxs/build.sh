#!/bin/bash

# Build the Docker image and tag it, login, then push it
docker build --no-cache -t ${DOCKER_USERNAME}/pvxs:tls-dev . && \
docker login && \
docker push ${DOCKER_USERNAME}/pvxs:tls-dev
