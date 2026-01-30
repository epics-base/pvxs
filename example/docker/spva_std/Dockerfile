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
            supervisor && \
    mkdir -p ${PROJECT_HOME}

# Create users with pre-set passwords ("secret")
RUN useradd -m -s /bin/bash admin && echo "admin:secret" | chpasswd
RUN useradd -m -s /bin/bash pvacms && echo "pvacms:secret" | chpasswd
RUN useradd -m -s /bin/bash softioc && echo "softioc:secret" | chpasswd
RUN useradd -m -s /bin/bash client && echo "client:secret" | chpasswd

# Copy user-specific environment settings
COPY admin_bashrc /home/admin/.spva_bashrc
COPY pvacms_bashrc /home/pvacms/.spva_bashrc
COPY softioc_bashrc /home/softioc/.spva_bashrc
COPY client_bashrc /home/client/.spva_bashrc

RUN chown admin:admin /home/admin/.spva_bashrc && chmod 644 /home/admin/.spva_bashrc
RUN chown pvacms:pvacms /home/pvacms/.spva_bashrc && chmod 644 /home/pvacms/.spva_bashrc
RUN chown softioc:softioc /home/softioc/.spva_bashrc && chmod 644 /home/softioc/.spva_bashrc
RUN chown client:client /home/client/.spva_bashrc && chmod 644 /home/client/.spva_bashrc

RUN echo "source ~/.spva_bashrc" >> /home/admin/.bashrc
RUN echo "source ~/.spva_bashrc" >> /home/pvacms/.bashrc
RUN echo "source ~/.spva_bashrc" >> /home/softioc/.bashrc
RUN echo "source ~/.spva_bashrc" >> /home/client/.bashrc

# Create the log directory and files with correct permissions
RUN mkdir -p /var/log/supervisor && \
    touch /var/log/supervisor/pvacms.out.log /var/log/supervisor/pvacms.err.log && \
    chown pvacms:pvacms /var/log/supervisor/pvacms.out.log /var/log/supervisor/pvacms.err.log

# Generate the administrator certificate with logging redirections
RUN su - pvacms -c "/bin/bash -c '/opt/epics/pvxs/bin/$(${PROJECT_HOME}/epics-base/startup/EpicsHostArch)/pvacms --admin-keychain-new admin >> /var/log/supervisor/pvacms.out.log 2>> /var/log/supervisor/pvacms.err.log'"

# Copy the administrator certificate to the admin user
RUN mkdir -p /home/admin/.config/pva/1.5 && \
    mv /home/pvacms/.config/pva/1.5/admin.p12 /home/admin/.config/pva/1.5/client.p12 && \
    chown admin:admin /home/admin/.config/pva/1.5/client.p12 && \
    chmod 400 /home/admin/.config/pva/1.5/client.p12

# Copy the top-level Supervisor config
COPY supervisord.conf /etc/supervisor/supervisord.conf

# Copy the PVACMS Supervisor config
COPY pvacms-supervisor.conf /etc/supervisor/conf.d/pvacms.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
