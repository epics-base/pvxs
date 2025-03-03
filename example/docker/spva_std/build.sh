#!/bin/bash

# Build the Docker image and tag it, login, then push it
docker build --no-cache -t ${DOCKER_USERNAME}/spva_std:latest . && \
docker login && \
docker push ${DOCKER_USERNAME}/spva_std:latest
