#!/bin/bash
set -e

# Start slapd using the ldapi:/// interface so we can use SASL EXTERNAL.
# (This runs slapd in the background.)
/usr/sbin/slapd -h "ldapi:///" -d 0 &
SLAPD_PID=$!

# Wait a few seconds to ensure slapd is ready.
sleep 5

# Change the admin password using ldapmodify over ldapi with SASL EXTERNAL.
# This command binds as the local root via ldapi.
ldapmodify -H ldapi:/// -Y EXTERNAL -f /tmp/change-admin.ldif

# Stop the temporary slapd instance.
kill $SLAPD_PID
sleep 2

# Now start supervisord which will run slapd (and any other services)
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
