#!/bin/bash

# Build the Docker image and tag it
docker build --no-cache -t ${DOCKER_USERNAME}/spva_ldap:latest .

# Log in to DockerHub (only needed if not already logged in)
docker login

# Push the image to DockerHub
docker push ${DOCKER_USERNAME}/spva_ldap:latest
