# FROM image built from /example/docker/spva_std
FROM georgeleveln/spva_std:latest

# Set environment variables
ENV PROJECT_HOME=/opt/epics

# Add kerberos dependencies
RUN apt-get update && \
    apt-get -y install \
            --no-install-recommends \
            krb5-admin-server \
            krb5-kdc \
            libkrb5-dev

# Set up CONFIG_SITE.local
WORKDIR ${PROJECT_HOME}
RUN echo "EVENT2_HAS_OPENSSL = YES" >> CONFIG_SITE.local
RUN echo "PVXS_ENABLE_KRB_AUTH = YES" >> CONFIG_SITE.local

# Rebuild PVXS with kerberos support
RUN cd pvxs && \
    make -j10 all

COPY kadm5.acl kdc.conf badpass.txt /etc/krb5kdc/

# Copy user kerberos configuration
COPY krb5.conf /etc/krb5.conf

# Copy the krb5 Supervisor configs
COPY krb5-admin-server-supervisor.conf /etc/supervisor/conf.d/kadmind.conf
COPY krb5-kdc-supervisor.conf /etc/supervisor/conf.d/krb5kdc.conf

RUN echo 'environment=KRB5_KTNAME="/home/pvacms/.config/krb5/pvacms.keytab"' >> /etc/supervisor/conf.d/pvacms.conf
RUN echo 'environment=KRB5_CLIENT_KTNAME="/home/pvacms/.config/krb5/pvacms.keytab"' >> /etc/supervisor/conf.d/pvacms.conf
RUN echo 'environment=EPICS_AUTH_KRB_REALM="EPICS.ORG"' >> /etc/supervisor/conf.d/pvacms.conf

# Ensure the pvacms userr's config directory is created
RUN mkdir -p /home/pvacms/.config/krb5/

# Ensure Kerberos services are available before modifying the database
RUN service krb5-kdc start && service krb5-admin-server start

# Create the principals
# - note clear passwords for testing purposes only
RUN kdb5_util create -s -P secret \
 && kadmin.local -q 'addprinc -pw secret -allow_svr admin' \
 && kadmin.local -q 'addprinc -randkey pvacms/cluster@EPICS.ORG' \
 && kadmin.local -q 'addprinc -pw secret -allow_svr softioc' \
 && kadmin.local -q 'addprinc -pw secret client'

# Create PVACMS keytab
RUN kadmin.local -q 'ktadd -k /home/pvacms/.config/krb5/pvacms.keytab pvacms/cluster@EPICS.ORG' \
 && chown pvacms:pvacms /home/pvacms/.config/krb5/pvacms.keytab \
 && chmod 600 /home/pvacms/.config/krb5/pvacms.keytab

# Update pvacms service with kerberos configuration
COPY pvacms_bashrc /home/pvacms/.spva_krb_bashrc
RUN echo "source ~/.spva_krb_bashrc" >> /home/pvacms/.bashrc

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
