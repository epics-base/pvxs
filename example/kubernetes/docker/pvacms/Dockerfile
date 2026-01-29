ARG DOCKER_USERNAME=georgeleveln
ARG BASE_IMAGE=lab_base
ARG BASE_IMAGE_TAG=latest

FROM ${DOCKER_USERNAME}/${BASE_IMAGE}:${BASE_IMAGE_TAG}

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Create user with pre-set password ("secret")
RUN useradd -m -s /bin/bash pvacms && echo "pvacms:secret" | chpasswd
RUN useradd -m -s /bin/bash admin  && echo "admin:secret"  | chpasswd

# Copy user-specific environment settings
COPY pvacms_bashrc /home/pvacms/.cms_bashrc
COPY admin_bashrc  /home/admin/.cms_bashrc

RUN chown pvacms:pvacms /home/pvacms/.cms_bashrc && \
    chown admin:admin   /home/admin/.cms_bashrc  && \
    chmod 644           /home/pvacms/.cms_bashrc && \
    chmod 644           /home/admin/.cms_bashrc

RUN echo "source ~/.cms_bashrc" >> /home/pvacms/.bashrc
RUN echo "source ~/.cms_bashrc" >> /home/admin/.bashrc

# Create the log files with correct permissions
RUN touch /var/log/supervisor/pvacms.out.log \
          /var/log/supervisor/pvacms.err.log && \
    chown pvacms:pvacms \
          /var/log/supervisor/pvacms.out.log \
          /var/log/supervisor/pvacms.err.log

# Copy the PVACMS Supervisor config
COPY pvacms-supervisor.conf /etc/supervisor/conf.d/pvacms.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
