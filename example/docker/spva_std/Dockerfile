FROM georgeleveln/pvxs_spva:latest

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

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

# Generate the administrator certificate
RUN su - pvacms -c "/opt/epics/pvxs/bin/*/pvacms --admin-keychain-new admin"

# Copy the administrator certificate to the admin user
RUN mkdir -p /home/admin/.config/pva/1.3 && \
    cp -pr /home/pvacms/.config/pva/1.3/admin.p12 /home/admin/.config/pva/1.3/client.p12 && \
    chown admin:admin /home/admin/.config/pva/1.3/client.p12 && \
    chmod 400 /home/admin/.config/pva/1.3/client.p12

# Copy the top-level Supervisor config
COPY supervisord.conf /etc/supervisor/supervisord.conf

# Copy the PVACMS Supervisor config
COPY pvacms-supervisor.conf /etc/supervisor/conf.d/pvacms.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
