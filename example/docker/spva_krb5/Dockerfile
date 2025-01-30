FROM georgeleveln/spva_std:latest

RUN apt-get update && \
    apt-get -y install \
            --no-install-recommends \
            krb5-admin-server \
            krb5-kdc supervisor

COPY kadm5.acl kdc.conf badpass.txt /etc/krb5kdc/

# Copy user kerberos configuration
COPY krb5.conf /etc/krb5.conf

# Copy the krb5 Supervisor configs
COPY krb5-admin-server-supervisor.conf /etc/supervisor/conf.d/kadmind.conf
COPY krb5-kdc-supervisor.conf /etc/supervisor/conf.d/krb5kdc.conf

# Ensure the pvacms userr's config directory is created
RUN mkdir -p /home/pvacms/.config/krb5/

# Ensure Kerberos services are available before modifying the database
RUN service krb5-kdc start && service krb5-admin-server start

# Create the principals
# - note clear passwords for testing purposes only
RUN kdb5_util create -s -P secret \
 && kadmin.local -q 'addprinc -pw secret -allow_svr admin' \
 && kadmin.local -q 'addprinc -nokey -allow_svr PVACMS' \
 && kadmin.local -q 'addprinc -pw secret -allow_svr softioc' \
 && kadmin.local -q 'addprinc -pw secret client'

# Create PVACMS keytab
RUN kadmin.local -q 'ktadd -k /home/pvacms/.config/krb5/pvacms.keytab PVACMS' \
 && chown pvacms:pvacms /home/pvacms/.config/krb5/pvacms.keytab \
 && chmod 600 /home/pvacms/.config/krb5/pvacms.keytab

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
