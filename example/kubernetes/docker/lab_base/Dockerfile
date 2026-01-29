ARG DOCKER_USERNAME=georgeleveln
ARG BASE_IMAGE=pvxs
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
            adduser \
            sudo \
            supervisor

RUN echo "PVXS = \$(TOP)/../pvxs" >> ${PROJECT_HOME}/RELEASE.local

# Create the log directory and files with correct permissions
RUN mkdir -p /var/log/supervisor

# Copy the top-level Supervisor config
COPY supervisord.conf /etc/supervisor/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
