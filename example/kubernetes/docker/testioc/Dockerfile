ARG DOCKER_USERNAME=georgeleveln
ARG BASE_IMAGE=lab_base
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Create user with pre-set password ("secret")
RUN useradd -m -s /bin/bash testioc && echo "testioc:secret" | chpasswd

# Copy user-specific environment settings
COPY testioc_bashrc /home/testioc/.testioc_bashrc
COPY testioc.acf    /home/testioc/testioc.acf

RUN chown testioc:testioc /home/testioc/.testioc_bashrc && \
    chmod 644             /home/testioc/.testioc_bashrc && \
    chown testioc:testioc /home/testioc/testioc.acf     && \
    chmod 644             /home/testioc/testioc.acf

RUN echo "source ~/.testioc_bashrc" >> /home/testioc/.bashrc

# Create the log files with correct permissions
RUN touch /var/log/supervisor/testioc.out.log \
          /var/log/supervisor/testioc.err.log && \
    chown testioc:testioc \
          /var/log/supervisor/testioc.out.log \
          /var/log/supervisor/testioc.err.log

# Copy the testioc Supervisor config
COPY testioc-supervisor.conf /etc/supervisor/conf.d/testioc.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
