ARG DOCKER_USERNAME=georgeleveln

FROM ${DOCKER_USERNAME}/spva_std:latest

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

# Install packages: OpenLDAP, ldap-utils, SSSD, and supervisor.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        slapd \
        ldap-utils \
        sssd \
        libldap2-dev \
        libnss-sss \
        libpam-sss && \
    rm -rf /var/lib/apt/lists/*

# Remove the default LDAP configuration and reconfigure slapd non-interactively.
RUN rm -rf /etc/ldap/slapd.d && \
    dpkg-reconfigure -f noninteractive slapd

# --- Schema, ACL, and Data Loading ---

# Copy and load the EPICS custom schema.
COPY epics-schema.ldif /tmp/epics-schema.ldif
COPY epics-acl.ldif    /tmp/epics-acl.ldif

# Start slapd in the background, wait for it to be ready, apply schema and ACL changes, then kill it.
RUN /usr/sbin/slapd -h "ldap:/// ldapi:///" -u openldap & \
    sleep 5 && \
    ldapadd -Y EXTERNAL -H ldapi:/// -f /tmp/epics-schema.ldif && \
    ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/epics-acl.ldif && \
    pkill slapd && \
    sleep 2 && \
    rm -f /tmp/epics-schema.ldif /tmp/epics-acl.ldif

# --- Load LDAP Data ---

# Copy LDAP data file.
COPY ldap-data.ldif /tmp/ldap-data.ldif

# Remove any existing LDAP database contents, load the LDAP entries using slapadd, fix ownership, and clean up.
RUN rm -rf /var/lib/ldap/* && \
    slapadd -l /tmp/ldap-data.ldif && \
    chown -R openldap:openldap /var/lib/ldap && \
    rm -f /tmp/ldap-data.ldif

# --- Supervisor and SSSD Configuration ---

# Copy the supervisor configuration for LDAP (slapd).
COPY ldap-supervisor.conf /etc/supervisor/conf.d/ldap.conf

# Copy and secure the SSSD configuration.
COPY sssd.conf /etc/sssd/sssd.conf
RUN chmod 600 /etc/sssd/sssd.conf && chown root:root /etc/sssd/sssd.conf

# Update /etc/nsswitch.conf to use SSSD for passwd, group, and shadow.
RUN sed -i 's/^passwd:.*/passwd:         files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:         files sss/' /etc/nsswitch.conf

# (Optional) Expose the standard LDAP port if you plan to connect from outside.
# EXPOSE 389

# Copy the supervisor configuration for SSSD.
COPY sssd-supervisor.conf /etc/supervisor/conf.d/sssd.conf

# Set up CONFIG_SITE.local
WORKDIR ${PROJECT_HOME}
RUN echo "EVENT2_HAS_OPENSSL = YES" >> CONFIG_SITE.local
RUN echo "PVXS_ENABLE_LDAP_AUTH = YES" >> CONFIG_SITE.local

# Rebuild PVXS with ldap support
RUN cd pvxs && \
    make distclean && make -j10 all

# Set the entrypoint to run supervisord.
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
