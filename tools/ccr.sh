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
now=$(date +%s)
#not_before=$((now + 0))
#not_after=$((now + 86400))

not_before=$((now + 30))
not_after=$((now + 90))

if [ ! -f ~/.epics/public_key.pem ]
then
  openssl genrsa -out ~/.epics/private_key.pem 2048
  openssl rsa -in ~/.epics/private_key.pem -pubout -outform PEM -out ~/.epics/public_key.pem 2>/dev/null
  chmod 400 ~/.epics/private_key.pem ~/.epics/public_key.pem
fi
pub_key=$(cat ~/.epics/public_key.pem)

echo pvxcall "CERT:CREATE" type="x509" name="$name" country="US" organization="$org" organization_unit=""  not_before=$not_before not_after=$not_after usage=$usage
pvxcall "CERT:CREATE" type="x509" name="$name" country="US" organization="$org" organization_unit=""  not_before=$not_before not_after=$not_after usage=$usage pub_key="${pub_key}"
