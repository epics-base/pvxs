FROM ubuntu:latest

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
            build-essential \
            git \
            openssl \
            libssl-dev \
            libevent-dev \
            libsqlite3-dev \
            libcurl4-openssl-dev \
            pkg-config \
            adduser \
            sudo \
            supervisor && \
    mkdir -p ${PROJECT_HOME} && \
    mkdir -p /etc/skel/.config/pva/1.3

# Clone and build EPICS Base
WORKDIR ${PROJECT_HOME}
RUN git clone --branch 7.0-method_and_authority https://github.com/george-mcintyre/epics-base.git && \
    cd epics-base && \
    make -j10 all

# Set up RELEASE.local
RUN echo "EPICS_BASE = \$(TOP)/../epics-base" >> ${PROJECT_HOME}/RELEASE.local

# Clone and build PVXS
RUN git clone --recursive --branch tls https://github.com/george-mcintyre/pvxs.git && \
    cd pvxs && \
    make -j10 all

CMD ["/bin/bash"]
