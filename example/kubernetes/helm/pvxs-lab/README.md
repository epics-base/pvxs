# pvxs-lab Helm chart

Deploy pvacms, testioc, tstioc, and gateway together.

Key behaviour:
- Only gateway is reachable from the external network via hostNetwork.
- Other pods are ClusterIP only.
- /home/gateway/gateway.conf is overwritten by Helm ConfigMap (values.gateway.config).

## Install

```sh
helm upgrade --install pvxs-lab ./pvxs/example/kubernetes/helm/pvxs-lab \
  --namespace pvxs-lab --create-namespace
```

## Override gateway.conf
Edit values.yaml or 

```sh
helm upgrade --install pvxs-lab ./pvxs/example/kubernetes/helm/pvxs-lab \
  -n pvxs-lab \
  --set-file gateway.config=./my-gateway.conf

```

## Network policy
NetworkPolicy enforcement requires a policy CNI (Calico/Cilium/Antrea). If your cluster does not enforce NetworkPolicy, `set networkPolicy.enabled=false` and rely on the provided role-based EPICS environment configuration.

## External access

Because gateway runs with hostNetwork=true, it will bind on the node IP.
Run pvxget/pvxinfo from outside pointing at the node IP if you disable broadcast.

```shell
EPICS_PVA_AUTO_ADDR_LIST=NO
EPICS_PVA_ADDR_LIST=<node-ip>
pvxinfo -v ...
```

## Certificates

By default the gateway, testioc, and tstioc will run without certificates.

You can 


## Internal Lab Clients can create certs and access the IOCs directly

```shell
kubectl -n <ns> exec -it deploy/<release>-lab -- su - guest
# or
kubectl -n <ns> exec -it deploy/<release>-lab -- su - operator

```

## PVAccess TCP vs UDP

### TCP with EPICS_PVA_NAME_SERVERS
TCP-search-only - recommended.  This simulates lab clients that are on the Internet.  It is the robust/portable approach:

- Expose only TCP NodePort (eg 31075)

```shell
helm upgrade --install pvxs-lab pvxs-lab -n pvxs-lab \
  --set gateway.expose.mode=NodePort \
  --set gateway.expose.enableUdp=false
```

- Set EPICS_PVA_NAME_SERVERS=<addr>:31075
- Clear/disable UDP address lists

```shell
export EPICS_PVA_AUTO_ADDR_LIST=NO
export EPICS_PVA_ADDR_LIST=""
export EPICS_PVA_NAME_SERVERS="127.0.0.1:31075"   # or <node-ip>:31075

```

### UDP
UDP NodePort enabled.  For testing UDP connectivity if your kubernetes cluster supports UDP NodePorts.  kube-proxy/CNI must handle NAT/VM plumbing correctly.  It will not give you broadcast discovery but will allow you to test `EPICS_PVA_ADDR_LIST` without nameservers.

- Make pvagw listen on bcastport = your UDP NodePort (eg 31076)
- Expose UDP NodePort 31076

```shell
helm upgrade --install pvxs-lab pvxs-lab -n pvxs-lab \
  --set gateway.expose.mode=NodePort \
  --set gateway.expose.enableUdp=true
```


- Point clients at <node-ip> via EPICS_PVA_ADDR_LIST (unicast), with AUTO_ADDR_LIST=NO

Example host env:

```shell
export EPICS_PVA_AUTO_ADDR_LIST=NO
export EPICS_PVA_ADDR_LIST="127.0.0.1:31076"   # or <node-ip>:31076 if required
export EPICS_PVA_NAME_SERVERS=""               # ensure not using TCP search
```


