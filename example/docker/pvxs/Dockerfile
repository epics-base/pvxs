ARG DOCKER_USERNAME=georgeleveln

FROM ${DOCKER_USERNAME}/epics-base:latest

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
            openssl \
            libssl-dev \
            libevent-dev \
            libsqlite3-dev \
            libcurl4-openssl-dev \
            pkg-config

# Set up RELEASE.local
WORKDIR ${PROJECT_HOME}
RUN echo "EPICS_BASE = \$(TOP)/../epics-base" >> ${PROJECT_HOME}/RELEASE.local

# Set up CONFIG_SITE.local
RUN echo "PVXS_ENABLE_PVACMS = YES" >> CONFIG_SITE.local

# build PVXS
WORKDIR ${PROJECT_HOME}/pvxs
COPY . .
RUN make -j10 all

CMD ["/bin/bash"]
