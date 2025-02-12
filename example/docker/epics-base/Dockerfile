FROM ubuntu:latest

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
            build-essential \
            git && \
    mkdir -p ${PROJECT_HOME}

# Clone and build EPICS Base
WORKDIR ${PROJECT_HOME}
RUN git clone --branch 7.0-method_and_authority https://github.com/george-mcintyre/epics-base.git && \
    cd epics-base && \
    make -j10 all

CMD ["/bin/bash"]
