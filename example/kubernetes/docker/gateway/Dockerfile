ARG DOCKER_USERNAME=georgeleveln
ARG BASE_IMAGE=lab_base
ARG BASE_IMAGE_TAG=latest
ARG RELATIVE_DOCKER_DIR=pvxs/example/kubernetes/docker/gateway

FROM ${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

ARG RELATIVE_DOCKER_DIR

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
      ca-certificates \
      python3-dev \
      python3-numpy \
      python3-nose2 \
      python-is-python3 \
      python3-ply \
      cython3 \
      && \
    rm -rf /var/lib/apt/lists/*

# Build + install p4p (provides pvagw)
WORKDIR ${PROJECT_HOME}
COPY ./p4p ./p4p
WORKDIR ${PROJECT_HOME}/p4p

RUN make distclean || true && \
    make -j$(nproc) all

# Create gateway user and set up config
RUN useradd -m -s /bin/bash gateway && echo "gateway:secret" | chpasswd
COPY ${RELATIVE_DOCKER_DIR}/gateway_bashrc /home/gateway/.gateway_bashrc
COPY ${RELATIVE_DOCKER_DIR}/gateway.acf    /home/gateway/gateway.acf
RUN chown gateway:gateway /home/gateway/.gateway_bashrc && \
    chmod 644             /home/gateway/.gateway_bashrc

RUN echo "source ~/.gateway_bashrc" >> /home/gateway/.bashrc

WORKDIR /home/gateway
COPY ${RELATIVE_DOCKER_DIR}/gateway.conf   .
COPY ${RELATIVE_DOCKER_DIR}/gateway.pvlist .
COPY ${RELATIVE_DOCKER_DIR}/gateway.acf    .
RUN chown -R gateway:gateway /home/gateway && \
    chmod 644                /home/gateway/gateway.*

# Create the log files with correct permissions
RUN touch /var/log/supervisor/gateway.out.log \
          /var/log/supervisor/gateway.err.log && \
    chown gateway:gateway \
          /var/log/supervisor/gateway.out.log \
          /var/log/supervisor/gateway.err.log

# Copy the gateway Supervisor config
COPY ${RELATIVE_DOCKER_DIR}/gateway-supervisor.conf /etc/supervisor/conf.d/gateway.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
