#!/bin/bash

# Build the Docker image and tag it, login, then push it
docker build --pull -t ${DOCKER_USERNAME}/epics-base:latest . && \
docker login && \
docker push ${DOCKER_USERNAME}/epics-base:latest
