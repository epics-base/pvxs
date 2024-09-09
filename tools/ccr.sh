#!/bin/bash

# ccr.sh name org usage
if [ $# != 3 ]
then
  echo "usage:"
  echo "    $0 name org usage_mask"
  echo "Where:"
  echo "    usage_mask: client=1, server=2 "
  exit 1
fi

name=$1
org=$2
usage=$3
if [ $usage == 1 ]
then
  target="client"
else
  target="server"
fi
PRIVATE_KEY_FILE="$HOME/.epics/keys/${target}_priv_key_tmp.pem"
PUBLIC_KEY_FILE="$HOME/.epics/keys/${target}_pub_key.pem"
P12_KEY_FILE="$HOME/.epics/keys/${target}.p12"
P12_PASSWORD="$(cat $HOME/.epics/passwords/${target}.pass)"

CERT_FILE="$HOME/.epics/keys/${target}_cert.pem"
ROOT_FILE="$HOME/.epics/keys/${target}_root.pem"
CHAIN_FILE="$HOME/.epics/keys/${target}_chain.pem"
P12_FILE="$HOME/.epics/certs/${target}.p12"

now=$(date +%s)
not_before=$((now + 0))
not_after=$((now + 86400))

#not_before=$((now + 60))
#not_after=$((now + 90))

# Check if the P12 key file exists to determine if keys need to be generated
if [ ! -f "$P12_KEY_FILE" ]; then
  echo Creating ... $P12_KEY_FILE $PUBLIC_KEY_FILE

  # Generate a new private key in PEM format (temporary)
  openssl genrsa -out "$PRIVATE_KEY_FILE" 2048

  # Generate the corresponding public key in PEM format
  openssl rsa -in "$PRIVATE_KEY_FILE" -pubout -outform PEM -out "$PUBLIC_KEY_FILE" 2>/dev/null

  # Create a P12 file containing only the private key
  openssl pkcs12 -export -inkey "$PRIVATE_KEY_FILE" -nocerts -out "$P12_KEY_FILE" -passout pass:$P12_PASSWORD

  # Remove the temporary PEM private key file
  rm "$PRIVATE_KEY_FILE"

  # Set secure file permissions for the P12 file and public key file
  chmod 400 "$P12_KEY_FILE" "$PUBLIC_KEY_FILE"
fi
pub_key=$(cat $PUBLIC_KEY_FILE)

echo pvxcall "CERT:CREATE" type="x509" name="$name" country="US" organization="$org" organization_unit=""  not_before=$not_before not_after=$not_after usage=$usage
result=$(pvxcall "CERT:CREATE" type="x509" name="$name" country="US" organization="$org" organization_unit=""  not_before=$not_before not_after=$not_after usage=$usage pub_key="${pub_key}")

# Capture the exit status of the pvxcall command
status=$?

# Check if the pvxcall command was successful
if [ $status -ne 0 ]; then
  exit $status
fi


# Extract the certificates block using awk and sed
certs_block=$(echo "$result" | awk -F 'string cert = "' '{print $2}' | sed 's/" struct.*//' | sed 's/\\n/\n/g' | sed '/^\s*$/d' | sed '/^\".*$/d')

# Split the certificates block into first and root certificates
cert=$(echo "$certs_block" | awk 'BEGIN {RS="-----END CERTIFICATE-----\n"} NR==1 {print $0 "-----END CERTIFICATE-----"}')
root_cert=$(echo "$certs_block" | awk 'BEGIN {RS="-----END CERTIFICATE-----\n"} {last=$0} END {print last "-----END CERTIFICATE-----"}')

# Extract the serial number using awk
serial=$(echo "$result" | awk -F 'uint64_t serial = ' '{print $2}' | awk '{print $1}' | sed '/^\s*$/d')

# Extract the issuer using awk
issuer=$(echo "$result" | awk -F 'string issuer = "' '{print $2}' | awk -F '"' '{print $1}' | sed '/^\s*$/d')


# Save the certificate to a temporary file
echo "$cert" > "$CERT_FILE"

# Save the root certificate to a temporary file
echo "$root_cert" > "$ROOT_FILE"

# Combine the first certificate and root certificate into a single chain file
cat "$CERT_FILE" "$ROOT_FILE" > "$CHAIN_FILE"

# Create the PKCS#12 (.p12) file
openssl pkcs12 -export \
  -in "$CERT_FILE" \
  -inkey <(openssl pkcs12 -in "$P12_KEY_FILE" -nocerts -nodes -passin pass:$P12_PASSWORD) \
  -certfile "$CHAIN_FILE" \
  -out "$P12_FILE" \
  -passout pass:$P12_PASSWORD

echo "Created: ${P12_FILE}.  ${target} certificate: ${issuer}:${serial}"
