#!/bin/bash

cd epics-base   && \
./build.sh      && \
cd ../pvxs      && \
./build.sh      && \
cd ../spva_std  && \
./build.sh      && \
cd ../spva_krb  && \
./build.sh      && \
cd ../spva_ldap && \
./build.sh
