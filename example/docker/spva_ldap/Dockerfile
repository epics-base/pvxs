# FROM image built from /example/docker/spva_std
FROM georgeleveln/spva_std:latest

# Set environment variables
ENV PROJECT_HOME=/opt/epics
ENV DEBIAN_FRONTEND=noninteractive

# Preseed debconf for slapd so that it uses our desired domain and organization.
RUN echo "slapd slapd/no_configuration boolean false" | debconf-set-selections && \
    echo "slapd slapd/domain string epics.org" | debconf-set-selections && \
    echo "slapd shared/organization string EPICS" | debconf-set-selections && \
    echo "slapd slapd/password1 password secret" | debconf-set-selections && \
    echo "slapd slapd/password2 password secret" | debconf-set-selections && \
    echo "slapd slapd/backend string MDB" | debconf-set-selections && \
    echo "slapd slapd/purge_database boolean true" | debconf-set-selections && \
    echo "slapd slapd/move_old_database boolean true" | debconf-set-selections

# Install OpenLDAP (slapd and ldap-utils), SSSD, and supervisor
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        slapd \
        ldap-utils \
        sssd \
        libnss-sss \
        libpam-sss && \
    rm -rf /var/lib/apt/lists/*

# Remove the default LDAP configuration and reconfigure slapd non-interactively.
RUN rm -rf /etc/ldap/slapd.d && \
    dpkg-reconfigure -f noninteractive slapd

# Copy your LDAP data file
COPY ldap-data.ldif /tmp/ldap-data.ldif

# Remove existing LDAP database contents, then load the LDAP entries.
RUN rm -rf /var/lib/ldap/* && \
    slapadd -l /tmp/ldap-data.ldif && \
    chown -R openldap:openldap /var/lib/ldap

# Copy the supervisor configuration file for LDAP (for slapd)
COPY ldap-supervisor.conf /etc/supervisor/conf.d/ldap.conf

#########
## Setup all users auth to be based on LDAP

# Copy SSSD configuration file
COPY sssd.conf /etc/sssd/sssd.conf
RUN chmod 600 /etc/sssd/sssd.conf && chown root:root /etc/sssd/sssd.conf

# Update /etc/nsswitch.conf so that passwd, group, and shadow use SSSD.
RUN sed -i 's/^passwd:.*/passwd:         files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf

# (Optional) Expose the standard LDAP port if you plan to connect from outside.
# EXPOSE 389

# Copy SSSD supervisor configuration.
COPY sssd-supervisor.conf /etc/supervisor/conf.d/sssd.conf

# Run supervisord as the container entrypoint.
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
