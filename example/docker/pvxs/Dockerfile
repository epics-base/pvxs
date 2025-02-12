# FROM image built from /example/docker/epics-base
FROM georgeleveln/epics-base:latest

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

WORKDIR ${PROJECT_HOME}

# Set up RELEASE.local
RUN echo "EPICS_BASE = \$(TOP)/../epics-base" >> ${PROJECT_HOME}/RELEASE.local

# Clone and build PVXS
RUN git clone --recursive --branch tls https://github.com/george-mcintyre/pvxs.git && \
    cd pvxs && \
    make -j10 all

CMD ["/bin/bash"]
