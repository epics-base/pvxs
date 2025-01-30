#!/bin/bash

# Build the Docker image and tag it
docker build -t <your_dockerhub_username>/spva_krb:latest .

# Log in to DockerHub (only needed if not already logged in)
docker login

# Push the image to DockerHub
docker push <your_dockerhub_username>/spva_krb:latest
