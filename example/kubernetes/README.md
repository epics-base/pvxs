# Kubernetes Cluster with PVAccess Gateway ingress

## Overview
In this setup, we create a single-node Kubernetes cluster that simulates two isolated networks (subnets) on the same host:
- a “lab” subnet for internal services, and 
- a “non-lab” (external) subnet for clients

The goal is that external clients can only reach the SoftIOC’s PVs via the gateway, enforcing network isolation. This mirrors a typical EPICS deployment where a gateway machine with two NICs connects an isolated control network with an office network. The gateway will accept client connections on the external subnet and forward requests to the SoftIOC on the lab subnet, and vice versa, acting as a PVA protocol proxy.

# Users

## INSIDE LAB
- lab:
  - operator
  - guest
- pvacms
  - pvacms
  - admin
- testioc:
  - testioc
- tstioc:
  - tstioc
- gateway:
  - gateway

## OUTSIDE LAB
- lab:
  - operator
- extern:
  - remote


# PVs available:
## pvacms
- CERT:CREATE
- CERT:CREATE:65aeafe4
- CERT:ISSUER
- CERT:ISSUER:65aeafe4
- CERT:ROOT
- CERT:ROOT:65aeafe4
- CERT:STATUS:65aeafe4:*

## testioc
- test:aiExample
- test:arrayExample
- test:calcExample
- test:compressExample
- test:enumExample
- test:groupExampleAS
- test:groupExampleSave
- test:longExample
- test:spec   ....<<<....<<<....<<<...  Only setable by operator and gateway
- test:stringExample
- test:structExample
- test:structExampleSave
- test:tableExample
- test:vectorExampleD1
- test:vectorExampleD2

## tstioc
- tst:Array
- tst:Array2
- tst:ArrayData
- tst:ArrayData_
- tst:ArraySize0_RBV
- tst:ArraySize1_RBV
- tst:ColorMode
- tst:ColorMode_
- tst:extra
- tst:extra:alias


