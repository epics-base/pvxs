ARG DOCKER_USERNAME=georgeleveln
ARG BASE_IMAGE=spva_std
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install Python and required packages
RUN apt-get update && \
    apt-get install -y \
      python3 python3-pip \
      python3-flask python3-jwt python3-cryptography \
      curl && \
    rm -rf /var/lib/apt/lists/*

# Copy the JWT service application into the image
COPY app.py /opt/epics/app.py

COPY jwt-issuer-supervisor.conf /etc/supervisor/conf.d/jwt_issuer.conf

# Update pvacms service with jwt configuration
COPY pvacms_bashrc /home/pvacms/.spva_jwt_bashrc
RUN echo "source ~/.spva_jwt_bashrc" >> /home/pvacms/.bashrc

# Set up CONFIG_SITE.local
WORKDIR ${PROJECT_HOME}
RUN echo "EVENT2_HAS_OPENSSL = YES" >> CONFIG_SITE.local
RUN echo "PVXS_ENABLE_PVACMS = YES" >> CONFIG_SITE.local
RUN echo "PVXS_ENABLE_JWT_AUTH = YES" >> CONFIG_SITE.local

# Rebuild PVXS with JWT support
RUN cd pvxs && \
    make distclean && make -j$(nproc) all

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
