.. _quick_start_gw:

|guide| Quick Start Gateway
==================================================

This section contains a Quick Start |guide| for deploying a Secure PVAccess Gateway (using the Standard Authenticator).

    A Secure PVA Gateway is used to bridge an internal (trusted) network and an external network, providing controlled
    access to PVs. In this example, we deploy a Gateway in front of two PVAccess servers (IOCs) and
    demonstrate how internal users with different roles (e.g. *guest* vs. *operator*) have different permissions,
    and how an external client can securely connect through the Gateway.

    Our starting point for this Quick Start Guide is the end of the :ref:`quick_start_std`. If you haven't gone through
    that yet, do so now and then return here. You should have the PVAccess Certificate Management Service (``pvacms``)
    set up with an admin user, and you should be familiar with creating and approving certificates using the Standard
    Authenticator.

    (All the resources for this Gateway example are provided under the ``example/kubernetes`` directory of the
    PVXS repository.)

See :ref:`secure_pvaccess` for general documentation on Secure PVAccess.

Other Quick Start Guides:

- :ref:`quick_start`
- :ref:`quick_start_std`
- :ref:`quick_start_krb`
- :ref:`quick_start_ldap`
- :ref:`quick_start_jwt`

|learn| You will learn:
******************************

- :ref:`Building the Gateway Docker images from source <spva_qs_gw_build>`,
- :ref:`Deploying the Gateway and PVACMS on a Kubernetes cluster <spva_qs_gw_deploy>`,
- :ref:`Creating and approving certificate requests for Gateway and IOCs (Standard Authenticator) <spva_qs_gw_certs>`,
- :ref:`Using role-based access control for PV writes (guest vs. operator) <spva_qs_gw_access>` and
- :ref:`Connecting an external client via the secure Gateway <spva_qs_gw_external>`

|pre-packaged|\Prepackaged
********************************

If you want a prepackaged environment, try the following. You will need four terminal sessions.

|1| Setup Helper Functions
------------------------------
Create helper functions first

- **gw_cp**
- **gw_deploy**
- **gw_internet_config**
- **gw_undeploy**
- **go_in_to**
- **login_to_lab**

.. code-block:: shell

    source ${PROJECT_HOME}/pvxs/example/kubernetes/helpers.sh


|2| Deploy Helm Chart
------------------------------

.. _spva_qs_gw_deploy:

- |terminal|\¹
- deploy the gateway and other components to the kubernetes cluster

.. code-block:: shell

    gw_deploy

.. code-block:: console

    Release "pvxs-lab" does not exist. Installing it now.
    NAME: pvxs-lab
    LAST DEPLOYED: Wed Jan 21 17:12:44 2026
    NAMESPACE: pvxs-lab
    STATUS: deployed
    REVISION: 1
    TEST SUITE: None
    ~

The Helm chart starts up various pods in the pvxs-lab namespace.

- **pvxs-lab-pvacms**: the PVAccess Certificate Management Service
- **pvxs-lab-testioc** and **pvxs-lab-tstioc**: two example IOCs
- **pvxs-lab-gateway**: the PVAccess Gateway
- **pvxs-lab-lab**: lab control room for **operator** and **guest** to access the IOCs from the controls network.

The Gateway service is exposed, by default, as a NodePort (TCP port 31075 on localhost) for external access,
and UDP name queries from outside are disabled.

|3| Remote Access to the Laboratory via the Gateway
---------------------------------------------------------

- |terminal|\⁴
- configure environment to simulate remote access into the lab via the gateway

.. code-block:: shell

    gw_internet_config

- get PV introspection (e.g. test:spec) from the outside without using TLS

- test remote access to a laboratory PV from the internet using TCP via the gateway

.. code-block:: shell

    pvxinfo -v test:spec

.. code-block:: console

    2026-01-21T17:24:14.068585000 WARN pvxs.ossl.init TLS Debug Enabled: logging TLS secrets to /tmp/pva-secrets
    Effective config
    EPICS_PVA_AUTO_ADDR_LIST=NO
    EPICS_PVA_BROADCAST_PORT=5076
    EPICS_PVA_CERT_PV_PREFIX=CERT
    EPICS_PVA_CONN_TMO=30.000000
    EPICS_PVA_NAME_SERVERS=127.0.0.1:31075
    EPICS_PVA_SERVER_PORT=5075
    EPICS_PVA_TLS_OPTIONS=on_expiration=fallback-to-tcp
    EPICS_PVA_TLS_PORT=5076
    XDG_CONFIG_HOME=/Users/george/.config
    XDG_DATA_HOME=/Users/george/.local/share
    # anonymous/@127.0.0.1:31075
    test:spec from 127.0.0.1:31075
    struct "epics:nt/NTScalar:1.0" {
        double value
        struct "alarm_t" {
            int32_t severity
            int32_t status
            string message
        } alarm
        struct "time_t" {
            int64_t secondsPastEpoch
            int32_t nanoseconds
            int32_t userTag
        } timeStamp
        struct {
            double limitLow
            double limitHigh
            string description
            string units
            int32_t precision
            struct "enum_t" {
                int32_t index
                string[] choices
            } form
        } display
        struct {
            double limitLow
            double limitHigh
            double minStep
        } control
        struct {
            bool active
            double lowAlarmLimit
            double lowWarningLimit
            double highWarningLimit
            double highAlarmLimit
            int32_t lowAlarmSeverity
            int32_t lowWarningSeverity
            int32_t highWarningSeverity
            int32_t highAlarmSeverity
            double hysteresis
        } valueAlarm
    }

The connection falls back to plain pvAccess over TCP, as shown by the ``anonymous/@127.0.0.1:31075`` line above.

- test ability to remotely access data in a laboratory PV from the internet using TCP via the gateway

.. code-block:: shell

    pvxget -F tree tst:Array

.. code-block:: console

    2026-01-21T17:28:52.784279000 WARN pvxs.ossl.init TLS Debug Enabled: logging TLS secrets to /tmp/pva-secrets
    tst:Array
        struct "epics:nt/NTNDArray:1.0" {
            struct {
                struct {
                    int32_t queueSize = 0
                    bool atomic = true
                } _options
            } record
            struct "alarm_t" {
                int32_t severity = 0
                int32_t status = 0
                string message = ""
            } alarm
            struct "time_t" {
                int64_t secondsPastEpoch = 1769011967
                int32_t nanoseconds = 753666552
                int32_t userTag = 0
            } timeStamp
            struct[] attribute = {2}[
                struct {
                    string name = "ColorMode"
                    any value uint16_t = 0
                    struct "alarm_t" {
                        int32_t severity = 0
                        int32_t status = 0
                        string message = ""
                    } alarm
                    struct "time_t" {
                        int64_t secondsPastEpoch = 0
                        int32_t nanoseconds = 0
                        int32_t userTag = 0
                    } timeStamp
                }
                struct {
                    string name = ""
                    any value uint16_t = 0
                    struct "alarm_t" {
                        int32_t severity = 3
                        int32_t status = 2
                        string message = "UDF"
                    } alarm
                    struct "time_t" {
                        int64_t secondsPastEpoch = 631152000
                        int32_t nanoseconds = 0
                        int32_t userTag = 0
                    } timeStamp
                }
            ]
            struct {
                struct "alarm_t" {
                    int32_t severity = 0
                    int32_t status = 0
                    string message = ""
                } alarm
                struct "time_t" {
                    int64_t secondsPastEpoch = 1769011967
                    int32_t nanoseconds = 753666552
                    int32_t userTag = 0
                } timeStamp
            } x
            struct[] dimension = {2}[
                struct {
                    int32_t size = 100
                }
                struct {
                    int32_t size = 100
                }
            ]
            any value uint16_t[] = {10000}[0, 655, 1310, 1966, 2621, 3276, 3932, 4587, 5242, 5898, 6553, 7208, 7864, 8519, 9174, 9830, 10485, 11140, 11796, 12451, ...]
        }

- Show that role based access control is enforced for remote clients accessing laboratory PV data via the gateway

.. code-block:: shell

    pvxput test:spec 105

.. code-block:: console

    2026-01-21T17:31:54.792734000 WARN pvxs.ossl.init TLS Debug Enabled: logging TLS secrets to /tmp/pva-secrets
    Error N4pvxs6client11RemoteErrorE : Put permission denied by gateway

At this point, the external client can connect and read PVs through the Gateway without TLS.
Next, we will enable TLS authentication on all components.

.. _spva_qs_gw_certs:

|4| Administrator
------------------------------

- |terminal|\²
- log in as the pre-configured SPVA admin user (certificate already set up for admin access to PVACMS)

.. code-block:: shell

    login_to_lab admin


.. code-block:: console

    To run a command as administrator (user "root"), use "sudo <command>".
    See "man sudo_root" for details.

    admin@pvxs-lab-pvacms-6d67d755f-f7ncb:~$

*Keep this admin terminal open; you will use it later to approve certificate requests.*

|5| Create Certificates for Lab Identities
------------------------------------------------------------

Gateway service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\³
- log in to the Gateway container as the gateway service account

.. code-block:: shell

    login_to_lab gateway

.. code-block:: console

    Defaulted container "gateway" out of: gateway, gateway-conf-init (init)
    gateway@pvxs-lab-gateway-6d4645f497-nsf44:~$

- create a server certificate for the Gateway using the Standard Authenticator
- make sure to create a certificate that can be used as both a client and server certificate using the ``-u ioc`` flag

.. code-block:: shell

    authnstd -u ioc


.. code-block:: console

    Keychain file created   : /home/gateway/.config/pva/1.5/gateway.p12
    Certificate identifier  : bd537d5b:5611727325962034466

- Leave the Gateway shell

.. code-block:: shell

    exit


IOC Services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\³
- log in to the first test IOC container (testioc service account)

.. code-block:: shell

    login_to_lab testioc

- create a server certificate for the test IOC

.. code-block:: shell

    authnstd -u server

.. code-block:: console

    Keychain file created   : /home/testioc/.config/pva/1.5/server.p12
    Certificate identifier  : bd537d5b:15412497381357095102

- log out

.. code-block:: shell

    exit

- log in to the second test IOC container (tstioc service account)

.. code-block:: shell

    login_to_lab tstioc

- create a server certificate for the second test IOC

.. code-block:: shell

    authnstd -u server

.. code-block:: console

    Keychain file created   : /home/tstioc/.config/pva/1.5/server.p12
    Certificate identifier  : bd537d5b:7295515860002315009

- log out

.. code-block:: shell

    exit

Lab Control Room users
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\³
- log in to the control room as user ``guest``
- use ``secret`` as the password

.. code-block:: shell

    login_to_lab guest

.. code-block:: console

        Password:
        guest@pvxs-lab-lab-c5f7f55bc-fhqtz:~$

- create a client certificate for the ``guest`` user

.. code-block:: shell

    authnstd

.. code-block:: console

    Keychain file created   : /home/guest/.config/pva/1.5/client.p12
    Certificate identifier  : bd537d5b:8684117196707720985


- log out

.. code-block:: shell

    exit

- log in as user ``operator``
- use ``secret`` as the password

.. code-block:: shell

    login_to_lab operator

.. code-block:: console

        Password:
        operator@pvxs-lab-lab-c5f7f55bc-fhqtz:~$

- create a client certificate for the ``operator`` user

.. code-block:: shell

    authnstd

.. code-block:: console

    Keychain file created   : /home/operator/.config/pva/1.5/client.p12
    Certificate identifier  : bd537d5b:6238724260668906348


- log out

.. code-block:: shell

    exit

All Gateway services and users have now requested certificates.  These certificates are in the ``PENDING_APPROVAL``
state and will not be usable until approved by an administrator.

|6| Approve and Apply certificates
-------------------------------------

Approve Certificates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\² (admin shell from step 3)
- approve the Gateway's certificate request

.. code-block:: shell

    pvxcert --approve bd537d5b:5611727325962034466

.. code-block:: console

    Approve ==> CERT:STATUS:bd537d5b:5611727325962034466 ==> Completed Successfully

- approve the first test IOC’s certificate

.. code-block:: shell

    pvxcert --approve bd537d5b:15412497381357095102

.. code-block:: console

    Approve ==> CERT:STATUS:bd537d5b:15412497381357095102 ==> Completed Successfully

- approve the second test IOC’s certificate

.. code-block:: shell

    pvxcert --approve bd537d5b:7295515860002315009

.. code-block:: console

    Approve ==> CERT:STATUS:bd537d5b:7295515860002315009 ==> Completed Successfully

- approve the ``guest`` user’s certificate

.. code-block:: shell

    pvxcert --approve bd537d5b:8684117196707720985

.. code-block:: console

    Approve ==> CERT:STATUS:bd537d5b:8684117196707720985 ==> Completed Successfully

- approve the ``operator`` user’s certificate

.. code-block:: shell

    pvxcert --approve bd537d5b:6238724260668906348

.. code-block:: console

    Approve ==> CERT:STATUS:bd537d5b:6238724260668906348 ==> Completed Successfully


Restart services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

After approval, restart the Gateway and IOC services so they load their new certificates.

- |terminal|\³
- restart the IOC services in their containers

.. code-block:: shell

    exit
    go_in_to testioc
    supervisorctl restart testioc

.. code-block:: console

    testioc: stopped
    testioc: started

.. code-block:: shell

    exit
    go_in_to tstioc
    supervisorctl restart tstioc

.. code-block:: console

    tstioc: stopped
    tstioc: started

- open a shell in the Gateway container and restart its service

.. code-block:: shell

    go_in_to gateway

.. code-block:: shell

    supervisorctl restart gateway

.. code-block:: console

    gateway: stopped
    gateway: started

*All services are now running with TLS enabled and using their approved certificates.*

.. _spva_qs_gw_access:

|7| Internal client access
------------------------------

Now that TLS is enforced internally, test access from a lab user.

- |terminal|\³
- log in as guest (internal client)
- use ``secret`` as the password

.. code-block:: shell

    login_to_lab guest

.. code-block:: console

        Password:
        guest@pvxs-lab-lab-c5f7f55bc-fhqtz:~$

- read the PV value

.. code-block:: shell

    pvxget test:spec

.. code-block:: console

    test:spec
        value double = 0
        alarm.severity int32_t = 3
        alarm.status int32_t = 2
        alarm.message string = "UDF"
        timeStamp.secondsPastEpoch int64_t = 631152000
        timeStamp.nanoseconds int32_t = 0
        timeStamp.userTag int32_t = 0
        display.limitLow double = 0
        display.limitHigh double = 0
        display.description string = ""
        display.units string = ""
        display.precision int32_t = 0
        display.form.index int32_t = 0
        display.form.choices string[] = {7}["Default", "String", "Binary", "Decimal", "Hex", "Exponential", "Engineering"]
        control.limitLow double = 0
        control.limitHigh double = 0
        valueAlarm.lowAlarmLimit double = nan
        valueAlarm.lowWarningLimit double = nan
        valueAlarm.highWarningLimit double = nan
        valueAlarm.highAlarmLimit double = nan
    guest@pvxs-lab-lab-c5f7f55bc-fhqtz:~$

- attempt to change the PV’s value

.. code-block:: shell

    pvxput test:spec 101

.. code-block:: console

    Error N4pvxs6client11RemoteErrorE : Put not permitted
    guest@pvxs-lab-lab-c5f7f55bc-fhqtz:~$

The guest user cannot modify this PV (the operation is rejected by the IOC’s access control). Next, try with the operator account:

- log out

.. code-block:: shell

    exit

- log in as operator (internal client)
- use ``secret`` as the password

.. code-block:: shell

    login_to_lab operator

- read the PV value

.. code-block:: shell

    pvxget test:spec

.. code-block:: console

    test:spec
        value double = 0
        alarm.severity int32_t = 3
        alarm.status int32_t = 2
        alarm.message string = "UDF"
        timeStamp.secondsPastEpoch int64_t = 631152000
        timeStamp.nanoseconds int32_t = 0
        timeStamp.userTag int32_t = 0
        display.limitLow double = 0
        display.limitHigh double = 0
        display.description string = ""
        display.units string = ""
        display.precision int32_t = 0
        display.form.index int32_t = 0
        display.form.choices string[] = {7}["Default", "String", "Binary", "Decimal", "Hex", "Exponential", "Engineering"]
        control.limitLow double = 0
        control.limitHigh double = 0
        valueAlarm.lowAlarmLimit double = nan
        valueAlarm.lowWarningLimit double = nan
        valueAlarm.highWarningLimit double = nan
        valueAlarm.highAlarmLimit double = nan
    operator@pvxs-lab-lab-c5f7f55bc-fhqtz:~$

- write a new value to the PV and read it back

.. code-block:: shell

    pvxput test:spec 101
    pvxget test:spec

.. code-block:: console

    test:spec
        value double = 101
        alarm.severity int32_t = 0
        alarm.status int32_t = 0
        alarm.message string = ""
        timeStamp.secondsPastEpoch int64_t = 1769193538
        timeStamp.nanoseconds int32_t = 354317763
        timeStamp.userTag int32_t = 0
        display.limitLow double = 0
        display.limitHigh double = 0
        display.description string = ""
        display.units string = ""
        display.precision int32_t = 0
        display.form.index int32_t = 0
        display.form.choices string[] = {7}["Default", "String", "Binary", "Decimal", "Hex", "Exponential", "Engineering"]
        control.limitLow double = 0
        control.limitHigh double = 0
        valueAlarm.lowAlarmLimit double = nan
        valueAlarm.lowWarningLimit double = nan
        valueAlarm.highWarningLimit double = nan
        valueAlarm.highAlarmLimit double = nan
    operator@pvxs-lab-lab-c5f7f55bc-99wtq:~$


The ``operator`` user is able to update the PV successfully. (The IOC’s access security rules grant
write permission to ``operator`` but not to ``guest``.)

.. _spva_qs_gw_external:

|8| External client (TLS) access
----------------------------------------

Simulate an external client with a valid certificate:

- |terminal|\⁴
- (Using the same external environment as in step 2, which is already configured to use the Gateway’s address.)
- request a client certificate for an external user (e.g. ``remote``)

.. code-block:: shell

    authnstd -u client -n remote

.. code-block:: console

    Keychain file created   : /home/<youruser>/.config/pva/1.5/client.p12
    Certificate identifier  : bd537d5b:5631421150061257157


- |terminal|\²
- admin shell
– approve the external user’s certificate

.. code-block:: shell

    pvxcert --approve bd537d5b:5631421150061257157


.. code-block:: console

    Approve ==> CERT:STATUS:bd537d5b:5631421150061257157 ==> Completed Successfully


- |terminal|\⁴
- read the PV from outside using the new certificate

.. code-block:: shell

    pvxget test:spec

.. code-block:: console

    test:spec
        value double = 101
        alarm.severity int32_t = 0
        alarm.status int32_t = 0
        alarm.message string = ""
        timeStamp.secondsPastEpoch int64_t = 1769193538
        timeStamp.nanoseconds int32_t = 354317763
        timeStamp.userTag int32_t = 0
        display.limitLow double = 0
        display.limitHigh double = 0
        display.description string = ""
        display.units string = ""
        display.precision int32_t = 0
        display.form.index int32_t = 0
        display.form.choices string[] = {7}["Default", "String", "Binary", "Decimal", "Hex", "Exponential", "Engineering"]
        control.limitLow double = 0
        control.limitHigh double = 0
        valueAlarm.lowAlarmLimit double = nan
        valueAlarm.lowWarningLimit double = nan
        valueAlarm.highWarningLimit double = nan
        valueAlarm.highAlarmLimit double = nan

- try write a new value to the PV from outside when not authorised

.. code-block:: shell

    pvxput test:spec 202

.. code-block:: console

    2026-01-23T20:07:16.836912000 WARN pvxs.ossl.init TLS Debug Enabled: logging TLS secrets to /tmp/pva-secrets
    Error N4pvxs6client11RemoteErrorE : Put permission denied by gateway

Write access is blocked because only operators can write to that field from remote locations.


|9| Authorised Operator remote access
----------------------------------------

Finally, simulate an authorised remote operator with a valid certificate:

- |terminal|\⁴
- copy the operator's certificate (and private key) to the operator's protected local laptop
- first move our remote user's certificate out of the way

.. code-block:: shell

    mv ~/.config/pva/1.5/client.p12 ~/.config/pva/1.5/remote.p12
    gw_cp lab operator '/home/operator/.config/pva/1.5/client.p12' ~/.config/pva/1.5/client.p12

.. code-block:: console

    Password: secret

.. code-block:: shell

    chmod 600 ~/.config/pva/1.5/client.p12
    ls -l ~/.config/pva/1.5/client.p12

.. code-block:: console

    -rw-------  1 george  staff  4254 Jan 23 23:50 /home/<youruser>/.config/pva/1.5/client.p12

- check that you have write permission to the field when properly authenticated as ``operator``

.. code-block:: shell

    pvxcall GW:STS:asTest pv=test:spec peer=1.1.1.1

.. code-block:: console

    2026-01-23T23:50:39.308926000 WARN pvxs.ossl.init TLS Debug Enabled: logging TLS secrets to /tmp/pva-secrets
    struct "epics:p2p/Permission:1.0" {
        string pv = "test:spec"
        string account = "x509/operator"
        string peer = "1.1.1.1"
        string[] roles = {1}["operator"]
        string asg = "SPECIAL"
        int32_t asl = 0
        struct {
            bool put = true
            bool rpc = true
            bool uncached = false
            bool audit = true
        } permission
    }

The ``string account = "x509/operator"`` shows that spva in the gateway has correctly validated the
id as ``operator`` using the provided ``X.509`` certificate.
The ``string asg = "SPECIAL"`` shows that the gateway has found that access to the PV ``test:spec`` is controlled by
gateway Access Security Group ``SPECIAL``.  The ``bool permission.put = true`` shows that write access is allowed for this user.

- set the value of the PV and read it back

.. code-block:: shell

    pvxput test:spec 202
    pvxget test:spec

.. code-block:: console

    test:spec
        value double = 202
        alarm.severity int32_t = 0
        alarm.status int32_t = 0
        alarm.message string = ""
        timeStamp.secondsPastEpoch int64_t = 1769193538
        timeStamp.nanoseconds int32_t = 354317763
        timeStamp.userTag int32_t = 0
        display.limitLow double = 0
        display.limitHigh double = 0
        display.description string = ""
        display.units string = ""
        display.precision int32_t = 0
        display.form.index int32_t = 0
        display.form.choices string[] = {7}["Default", "String", "Binary", "Decimal", "Hex", "Exponential", "Engineering"]
        control.limitLow double = 0
        control.limitHigh double = 0
        valueAlarm.lowAlarmLimit double = nan
        valueAlarm.lowWarningLimit double = nan
        valueAlarm.highWarningLimit double = nan
        valueAlarm.highAlarmLimit double = nan

The operator can access and modify the protected Lab Control System PV remotely using the certificate and private key.


|step-by-step| Step-By-Step
********************************

This section just walks through the steps that the scripts above have automated.  It is useful to show the recommended way of configuring the components but not
as a way of running the gateway cluster.  Notably, we will not go through the process of starting the services or configuring the cluster with the images.

|step| Setup Helper Functions
------------------------------------------

|1| Create helper functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create helper functions

- **gw_build_images** - to build the images from source
- **gw_deploy** - to deploy the images into the kubernetes cluster
- **gw_undeploy** - to uninstall from the cluster
- **gw_internet_config** - set environment to simulate remote internet access to a lab via a gateway
- **go_in_to** - shell into a lab system as root
- **login_to_lab** - login to a lab system as the specified user
- **gw_log** - tail logs from specified container
- **gw_cp** - copy files out of a container into local machine

.. code-block:: shell

    source ${PROJECT_HOME}/pvxs/example/kubernetes/helpers.sh

**gw_build_images**
- usage: gw_build_images [image] [docker_build_options]
- command to build the docker images to load into the cluster

.. code-block:: zsh

    function gw_build_images {
     pushd $PVXS/example/kubernetes/docker
     builder="./build.sh"

     if [[ "$1" == "gateway" || "$1" == "lab" ||  "$1" == "lab_base" || "$1" == "pvacms" ||  "$1" == "testioc" || "$1" == "tstioc" ]] ; then
      cd $1
      builder="./build_docker.sh"
      shift
     fi
     $builder $*
     popd
    }


**gw_deploy**
- usage: gw_deploy [-r]
- command to deploy the docker images into the cluster using helm and the provided helm charts

.. code-block:: zsh

    function gw_deploy {
     pushd $PVXS/example/kubernetes/helm
     if [[ "$1" == "-r" ]] ; then
      helm uninstall pvxs-lab -n pvxs-lab
      sleep 5
     fi
     helm upgrade --install pvxs-lab pvxs-lab -n pvxs-lab \
      --set gateway.expose.mode=NodePort \
      --set gateway.expose.enableUdp=false ${*}
     popd
    }


**gw_undeploy**
- usage: gw_undeploy
- command to remove the helm deployment

.. code-block:: zsh

    function gw_undeploy {
      helm uninstall pvxs-lab -n pvxs-lab
    }

**gw_internet_config**
- usage: gw_internet_config
- command to set the environment to simulate a remote connection into the lab gateway from the internet

.. code-block:: zsh

    function gw_internet_config {
     unset EPICS_PVA_INTF_ADDR_LIST
     unset EPICS_PVA_TLS_KEYCHAIN
     export EPICS_PVA_AUTO_ADDR_LIST=NO
     export EPICS_PVA_ADDR_LIST=""
     export EPICS_PVA_NAME_SERVERS="127.0.0.1:31075"
     echo "INTERNET mode: PVA client->${EPICS_PVA_NAME_SERVERS} ; ~/.config/pva/1.5/client.p12"
    }

**go_in_to**
- usage: go_in_to <sys>
- command to open a root terminal into the specified lab system (gateway, pvacms, testioc, or tstioc).
Use this to restart the daemons

.. code-block:: zsh

    function go_in_to {
     if [[ "$1" == "lab" ||  "$1" == "pvacms" ||  "$1" == "testioc" || "$1" == "tstioc" || "$1" == "gateway" ]] ; then
      kubectl -n pvxs-lab exec -it deploy/pvxs-lab-$1 -- /bin/bash
     else
      echo "No such lab system: $1"
      false
     fi
    }

**login_to_lab**
- usage: login_to_lab <user>
- command to open a terminal and log in as the specified user into a lab system.  The lab system chosen will depend on
the user specified.

  - **gateway**: if **gateway** is specified
  - **lab** control room: if either **guest** or **operator** is specified
  - **pvacms**: if either **pvacms** or **admin** is specified
  - **testioc**: if **testioc** is specified
  - **tstioc**: if **tstioc** is specified

.. code-block:: zsh

    function login_to_lab {
     if [[ "$1" == "guest" || "$1" == "operator" ]] ; then
      kubectl -n pvxs-lab exec -it deploy/pvxs-lab-lab -- su - $1
     elif [[ "$1" == "admin" || "$1" == "pvacms" ]] ;  then
      kubectl -n pvxs-lab exec -it deploy/pvxs-lab-pvacms -- su - $1
     elif [[ "$1" == "testioc" ]] ; then
      kubectl -n pvxs-lab exec -it deploy/pvxs-lab-testioc -- su - $1
     elif [[ "$1" == "tstioc" ]] ; then
      kubectl -n pvxs-lab exec -it deploy/pvxs-lab-tstioc -- su - $1
     elif [[ "$1" == "gateway" ]] ; then
      kubectl -n pvxs-lab exec -it deploy/pvxs-lab-gateway -- su - $1
     else
      echo "No such lab user: $1"
      false
     fi
    }

**gw_log**
- usage: gw_log <sys>
- command to tail logs from the specified lab system (gateway, pvacms, testioc, tstioc)

.. code-block:: zsh

    function gw_log {
     if [[ "$1" == "lab" ||  "$1" == "pvacms" ||  "$1" == "testioc" || "$1" == "tstioc" || "$1" == "gateway" ]] ; then
      kubectl logs -n pvxs-lab deployment/pvxs-lab-$1  -f
     else
      echo "No such lab system: $1"
      false
     fi
    }



**gw_cp**
- usage: gw_cp <sys> <user> <src> [dest]
- command to copy from the cluster out to local machine

.. code-block:: zsh

    function gw_cp {
      emulate -L zsh
      setopt local_options

      if (( $# < 3 || $# > 4 )); then
        echo "usage: gw_cp <sys> <user> <src> [dest]"
        echo "You gave $#"
        return 1
      fi

      local sys=$1
      local user=$2
      local src=$3
      local dst=${4:-./${src:t}}

      case "${sys}:${user}" in
        (gateway:gateway|pvacms:pvacms|testioc:testioc|tstioc:tstioc|pvacms:admin|lab:guest|lab:operator)
          ;;
        (*)
          echo "usage: gw_cp <sys> <user> <src> [dest]"
          echo "sys: gateway|pvacms|testioc|tstioc|lab"
          echo "user: gateway|pvacms|testioc|tstioc|admin|guest|operator"
          return 1
          ;;
      esac

      local POD
      POD=$(kubectl -n pvxs-lab get pod -l "app=$sys" -o jsonpath='{.items[0].metadata.name}') || return 1

      kubectl -n pvxs-lab exec -i "$POD" -- bash -lc \
        'su - "$1" -c "cat -- \"$2\""' _ "$user" "$src" > "$dst"
    }

|step| Creating the Lab Base Image
------------------------------------------

|1| Use a Prepackaged spva_std image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- open a terminal and load pre-built image

.. code-block:: shell

    docker run -it --name lab_base ${DOCKER_USERNAME}/pvxs:latest


|2| Install Pre-requisites
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- ability to add users and sudo
- supervisor

.. code-block:: shell

    apt-get update && \
    apt-get install -y \
            adduser \
            sudo \
            supervisor

.. code-block:: console

    Hit:1 http://ports.ubuntu.com/ubuntu-ports noble InRelease
    Hit:2 http://ports.ubuntu.com/ubuntu-ports noble-updates InRelease
    Hit:3 http://ports.ubuntu.com/ubuntu-ports noble-backports InRelease
    Hit:4 http://ports.ubuntu.com/ubuntu-ports noble-security InRelease
    Reading package lists... Done
    Reading package lists... Done
    Building dependency tree... Done
    Reading state information... Done
    ...
    Setting up libpython3-stdlib:arm64 (3.12.3-0ubuntu2.1) ...
    Setting up python3 (3.12.3-0ubuntu2.1) ...
    Setting up python3-pkg-resources (68.1.2-2ubuntu1.2) ...
    Setting up supervisor (4.2.5-1ubuntu0.1) ...
    invoke-rc.d: could not determine current runlevel
    invoke-rc.d: policy-rc.d denied execution of start.
    Processing triggers for libc-bin (2.39-0ubuntu8.6) ...


|3| Update the RELEASE.local to reference pvxs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    echo "PVXS = \$(TOP)/../pvxs" >> ${PROJECT_HOME}/RELEASE.local

|4| Create supervisor directories and add basic configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    # Create the log directory and files with correct permissions
    mkdir -p /var/log/supervisor

    # Create the top-level Supervisor config
    cat > /etc/supervisor/supervisord.conf <<EOF
    [supervisord]
    nodaemon=true
    logfile=/proc/1/fd/1
    logfile_maxbytes=0
    pidfile=/var/run/supervisord.pid
    user=root

    [unix_http_server]
    file=/var/run/supervisor.sock
    chmod=0700
    chown=root:root

    [rpcinterface:supervisor]
    supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

    [supervisorctl]
    serverurl=unix:///var/run/supervisor.sock

    [include]
    files = /etc/supervisor/conf.d/*.conf
    EOF

|5| Lab Base Build Note
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*Normally you will run* ``gw_build_images`` *to create the* ``lab_base:latest`` *image from*
``example/kubernetes/docker/lab_base/Dockerfile``

- Note: You can use the helper function ``gw_build_images`` to build this image.  Make sure $PVXS is set to your
  Project ROOT pvxs directory then run the following:

.. code-block:: shell

    gw_build_images lab_base

- You can optionally add ``--no-cache`` to force a full rebuild


|step| Configure PVACMS Image
------------------------------------------

|1| Use a Prepackaged lab_base image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- open a terminal and load pre-built image

.. code-block:: shell

    docker run -it --name pvacms ${DOCKER_USERNAME}/lab_base:latest

|2| Create pvacms user and admin user
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create ``pvacms`` user with password 'secret'
- create ``admin`` user with password 'secret'

.. code-block:: shell

    # Create user with pre-set password ("secret")
    useradd -m -s /bin/bash pvacms && echo "pvacms:secret" | chpasswd
    useradd -m -s /bin/bash admin  && echo "admin:secret"  | chpasswd

|3| Create user specific login environments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- pvacms

.. code-block:: shell

    cat > /home/pvacms/.cms_bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics

    #### [optional] Set path and name of the certificate database file (default: ./certs.db)
    # Environment: EPICS_PVACMS_DB
    # Default    : ${XDG_DATA_HOME}/pva/1.5/certs.db
    # export EPICS_PVACMS_DB=${XDG_DATA_HOME}/pva/1.5/certs.db

    #### SETUP Certificate Authority KEYCHAIN FILE
    # Place your certificate authority's certificate and key in this file if you have one
    # otherwise the certificate authority certificate will be created by PVACMS
    # Environment: EPICS_CERT_AUTH_TLS_KEYCHAIN
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/cert_auth.p12
    # export EPICS_CERT_AUTH_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.5/cert_auth.p12

    # Specify the name of your certificate authority
    # Environment: EPICS_CERT_AUTH_NAME, EPICS_CERT_AUTH_ORGANIZATION, EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT
    # Default    : CN=EPICS Root Certificate Authority, O=certs.epics.org, OU=EPICS Certificate Authority,
    # export EPICS_CERT_AUTH_NAME="EPICS Root Certificate Authority"
    # export EPICS_CERT_AUTH_ORGANIZATION="certs.epics.org"
    # export EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT="EPICS Certificate Authority"

    #### SETUP PVACMS KEYCHAIN FILE
    # Environment: EPICS_PVACMS_TLS_KEYCHAIN
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/pvacms.p12
    # export EPICS_PVACMS_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.5/pvacms.p12

    # Configure ADMIN user client certificate (will be created for you)
    # This file will be copied to the admin user
    # Environment: EPICS_ADMIN_TLS_KEYCHAIN
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/admin.p12
    # export EPICS_ADMIN_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.5/admin.p12

    # Configure PVACMS ADMIN user access control file
    # Environment: EPICS_PVACMS_ACF
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/pvacms.acf
    # export EPICS_PVACMS_ACF=${XDG_CONFIG_HOME}/pva/1.5/pvacms.acf

    # set path
    export EPICS_HOST_ARCH=\$(\${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="\${PROJECT_HOME}/pvxs/bin/\${EPICS_HOST_ARCH}:$PATH"

    cd ~
    EOF

- admin

.. code-block:: shell

    cat > /home/admin/.cms_bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics

    #### SETUP ADMIN KEYCHAIN FILE (will be copied from PVACMS)
    # Environment: EPICS_PVA_TLS_KEYCHAIN
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/client.p12
    # export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.5/client.p12

    #### SETUP ADMIN Organisation
    # Environment: EPICS_PVA_AUTH_ORGANIZATION
    # Default    : <hostname>
    export EPICS_PVA_AUTH_ORGANIZATION=epics.org

    #### SETUP Address list
    # Make sure that the only PVs that are seen are upstream (pvacms, testioc, and tstioc)
    export EPICS_PVA_ADDR_LIST="127.0.0.1"
    export EPICS_PVA_AUTO_ADDR_LIST="NO"

    # set path
    export EPICS_HOST_ARCH=\$(${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="\${PROJECT_HOME}/pvxs/bin/\${EPICS_HOST_ARCH}:$PATH"

    cd ~
    EOF

- set permissions

.. code-block:: shell

    chown pvacms:pvacms /home/pvacms/.cms_bashrc && \
    chown admin:admin   /home/admin/.cms_bashrc  && \
    chmod 644           /home/pvacms/.cms_bashrc && \
    chmod 644           /home/admin/.cms_bashrc

- add to login script

.. code-block:: shell

    echo "source ~/.cms_bashrc" >> /home/pvacms/.bashrc
    echo "source ~/.cms_bashrc" >> /home/admin/.bashrc

|4| Configure Supervisor
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Create the log files with correct permissions

.. code-block:: shell

    touch /var/log/supervisor/pvacms.out.log \
          /var/log/supervisor/pvacms.err.log && \
    chown pvacms:pvacms \
          /var/log/supervisor/pvacms.out.log \
          /var/log/supervisor/pvacms.err.log

- Create the PVACMS Supervisor config

.. code-block:: shell

    cat > /etc/supervisor/conf.d/pvacms.conf <<EOF
    [program:pvacms]
    command=/bin/sh -c 'exec /opt/epics/pvxs/bin/\$(/opt/epics/epics-base/startup/EpicsHostArch)/pvacms -v'
    user=pvacms
    autostart=true
    autorestart=true

    ; Send logs to container stdout/stderr
    stdout_logfile=/proc/1/fd/1
    stdout_logfile_maxbytes=0
    stderr_logfile=/proc/1/fd/2
    stderr_logfile_maxbytes=0
    stopsignal=TERM
    stopasgroup=true
    killasgroup=true
    EOF


|5| Start PVACMS Service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This step is optional.  Normally you will only do this in an image that is running in a cluster where the network
configuration can be controlled.

.. code-block:: shell

    /usr/bin/supervisord -c /etc/supervisor/supervisord.conf


|6| PVACMS Build Note
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*Normally you will run* ``gw_build_images`` *to create the* ``pvacms:latest`` *image from
``example/kubernetes/docker/pvacms/Dockerfile``

- Note: You can use the helper function ``gw_build_images`` to build this image.  Make sure $PVXS is set to your
  Project ROOT pvxs directory then run the following:

.. code-block:: shell

    gw_build_images pvacms

- You can optionally add ``--no-cache`` to force a full rebuild

|step| Configure testioc Image
------------------------------------------

|1| Use a Prepackaged lab_base image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- open a terminal and load pre-built image

.. code-block:: shell

    docker run -it --name testioc ${DOCKER_USERNAME}/lab_base:latest


|2| Create testioc user
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create ``testioc`` user with password 'secret'

.. code-block:: shell

    # Create user with pre-set password ("secret")
    useradd -m -s /bin/bash testioc && echo "testioc:secret" | chpasswd

|3| Create user specific login environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- testioc

.. code-block:: shell

    cat > /home/testioc/.testioc_bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics

    #### SETUP SOFTIOC KEYCHAIN FILE
    # Environment: EPICS_PVAS_TLS_KEYCHAIN
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/server.p12
    # export EPICS_PVAS_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.5/server.p12

    #### SETUP SOFTIOC Organisation
    # Environment: EPICS_PVAS_AUTH_ORGANIZATION
    # Default    : <hostname>
    export EPICS_PVAS_AUTH_ORGANIZATION=epics.org

    #### SETUP Address list
    # Make sure that the only PVs that are seen are upstream (pvacms, and tstioc)
    export EPICS_PVA_ADDR_LIST="pvxs-lab-pvacms pvxs-lab-tstioc"
    export EPICS_PVA_AUTO_ADDR_LIST="NO"

    # set path
    export EPICS_HOST_ARCH=\$(\${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="\${PROJECT_HOME}/pvxs/bin/\${EPICS_HOST_ARCH}:$PATH"

    cd ~
    EOF

- set permissions

.. code-block:: shell

    chown testioc:testioc /home/testioc/.testioc_bashrc && \
    chmod 644             /home/testioc/.testioc_bashrc

- add to login script

.. code-block:: shell

    echo "source ~/.testioc_bashrc" >> /home/testioc/.bashrc

|4| Create ACF file to control PV Access
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    cat > /home/testioc/testioc.acf <<EOF
    AUTHORITY(EPICS_CA, "EPICS Root Certificate Authority")

    UAG(USERS) {
        "gateway",
        "operator",
        "guest"
    }

    UAG(SPECIAL_USERS) {
        "gateway",
        "operator"
    }

    ASG(SPECIAL) {
        RULE(1,WRITE,TRAPWRITE) {
            UAG(SPECIAL_USERS)
            AUTHORITY(EPICS_CA)
            PROTOCOL(TLS)
            METHOD(X509)
        }
    }

    ASG(DEFAULT) {
        RULE(0,NONE)
        RULE(1,WRITE,TRAPWRITE) {
            UAG(USERS)
            AUTHORITY(EPICS_CA)
            PROTOCOL(TLS)
            METHOD(X509)
        }
    }
    EOF

- set permissions

.. code-block:: shell

    chown testioc:testioc /home/testioc/testioc.acf     && \
    chmod 644             /home/testioc/testioc.acf

|5| Configure Supervisor
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Create the log files with correct permissions

.. code-block:: shell

    touch /var/log/supervisor/testioc.out.log \
          /var/log/supervisor/testioc.err.log && \
    chown testioc:testioc \
          /var/log/supervisor/testioc.out.log \
          /var/log/supervisor/testioc.err.log


- Create the testioc Supervisor config

.. code-block:: shell

    cat > /etc/supervisor/conf.d/testioc.conf <<EOF
    [program:testioc]
    command=/bin/sh -c 'exec /opt/epics/pvxs/bin/\$(/opt/epics/epics-base/startup/EpicsHostArch)/softIocPVX -v -m user=test -d /opt/epics/pvxs/test/testioc.db -d /opt/epics/pvxs/test/testiocg.db -a /home/testioc/testioc.acf'
    user=testioc
    autostart=true
    autorestart=true

    ; Send logs to container stdout/stderr
    stdout_logfile=/proc/1/fd/1
    stdout_logfile_maxbytes=0
    stderr_logfile=/proc/1/fd/2
    stderr_logfile_maxbytes=0
    stopsignal=TERM
    stopasgroup=true
    killasgroup=true
    EOF

|6| Start testioc Service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This step is optional.  Normally you will only do this in an image that is running in a cluster where the network
configuration can be controlled.

.. code-block:: shell

    /usr/bin/supervisord -c /etc/supervisor/supervisord.conf


|7| testioc Build Note
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*Normally you will run* ``gw_build_images`` *to create the* ``testioc:latest`` *image from*
``example/kubernetes/docker/testioc/Dockerfile``

- Note: You can use the helper function ``gw_build_images`` to build this image.  Make sure $PVXS is set to your
  Project ROOT pvxs directory then run the following:

.. code-block:: shell

    gw_build_images testioc

- You can optionally add ``--no-cache`` to force a full rebuild

|step| Configure tstioc Image
------------------------------------------

|1| Use a Prepackaged lab_base image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- open a terminal and load pre-built image

.. code-block:: shell

    docker run -it --name tstioc ${DOCKER_USERNAME}/lab_base:latest


|2| Create tstioc user
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create ``tstioc`` user with password 'secret'

.. code-block:: shell

    # Create user with pre-set password ("secret")
    useradd -m -s /bin/bash tstioc && echo "tstioc:secret" | chpasswd

|3| Create user specific login environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- tstioc

.. code-block:: shell

    cat > /home/tstioc/.tstioc_bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics

    #### SETUP SOFTIOC KEYCHAIN FILE
    # Environment: EPICS_PVAS_TLS_KEYCHAIN
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/server.p12
    # export EPICS_PVAS_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.5/server.p12

    #### SETUP SOFTIOC Organisation
    # Environment: EPICS_PVAS_AUTH_ORGANIZATION
    # Default    : <hostname>
    export EPICS_PVAS_AUTH_ORGANIZATION=epics.org

    #### SETUP Address list
    # Make sure that the only PVs that are seen are upstream (pvacms, and testioc)
    export EPICS_PVA_ADDR_LIST="pvxs-lab-pvacms pvxs-lab-testioc"
    export EPICS_PVA_AUTO_ADDR_LIST="NO"

    # set path
    export EPICS_HOST_ARCH=\$(\${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="\${PROJECT_HOME}/pvxs/bin/\${EPICS_HOST_ARCH}:$PATH"

    cd ~
    EOF

- set permissions

.. code-block:: shell

    chown tstioc:tstioc /home/tstioc/.tstioc_bashrc && \
    chmod 644           /home/tstioc/.tstioc_bashrc

- add to login script

.. code-block:: shell

    echo "source ~/.tstioc_bashrc" >> /home/tstioc/.bashrc

|4| Create ACF file to control PV Access
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    cat > /home/tstioc/tstioc.acf <<EOF
    AUTHORITY(EPICS_CA, "EPICS Root Certificate Authority")

    UAG(USERS) {
        "gateway",
        "operator"
    }

    UAG(SPECIAL_USERS) {
        "gateway",
        "operator"
    }

    ASG(SPECIAL) {
        RULE(1,WRITE,TRAPWRITE) {
            UAG(SPECIAL_USERS)
            AUTHORITY(EPICS_CA)
            PROTOCOL(TLS)
            METHOD(X509)
        }
    }

    ASG(DEFAULT) {
        RULE(0,READ)
        RULE(1,WRITE,TRAPWRITE) {
            UAG(USERS)
            AUTHORITY(EPICS_CA)
            PROTOCOL(TLS)
            METHOD(X509)
        }
    }
    EOF

- set permissions

.. code-block:: shell

    chown tstioc:tstioc /home/tstioc/tstioc.acf     && \
    chmod 644             /home/tstioc/tstioc.acf

|5| Configure Supervisor
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Create the log files with correct permissions

.. code-block:: shell

    touch /var/log/supervisor/tstioc.out.log \
          /var/log/supervisor/tstioc.err.log && \
    chown tstioc:tstioc \
          /var/log/supervisor/tstioc.out.log \
          /var/log/supervisor/tstioc.err.log


- Create the tstioc Supervisor config

.. code-block:: shell

    cat > /etc/supervisor/conf.d/tstioc.conf <<EOF
    [program:tstioc]
    command=/bin/sh -c 'exec /opt/epics/pvxs/bin/\$(/opt/epics/epics-base/startup/EpicsHostArch)/softIocPVX -v -m user=test -d /opt/epics/pvxs/test/tstioc.db -d /opt/epics/pvxs/test/tstiocg.db -a /home/tstioc/tstioc.acf'
    user=tstioc
    autostart=true
    autorestart=true

    ; Send logs to container stdout/stderr
    stdout_logfile=/proc/1/fd/1
    stdout_logfile_maxbytes=0
    stderr_logfile=/proc/1/fd/2
    stderr_logfile_maxbytes=0
    stopsignal=TERM
    stopasgroup=true
    killasgroup=true
    EOF

|6| Start tstioc Service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This step is optional.  Normally you will only do this in an image that is running in a cluster where the network
configuration can be controlled.

.. code-block:: shell

    /usr/bin/supervisord -c /etc/supervisor/supervisord.conf


|7| tstioc Build Note
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*Normally you will run* ``gw_build_images`` *to create the* ``tstioc:latest`` *image from*
``example/kubernetes/docker/tstioc/Dockerfile``

- Note: You can use the helper function ``gw_build_images`` to build this image.  Make sure $PVXS is set to your
  Project ROOT pvxs directory then run the following:

.. code-block:: shell

    gw_build_images tstioc

- You can optionally add ``--no-cache`` to force a full rebuild

|step| Configure Lab Control Room Image
------------------------------------------

|1| Use a Prepackaged lab_base image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- open a terminal and load pre-built image

.. code-block:: shell

    docker run -it --name lab ${DOCKER_USERNAME}/lab_base:latest

|2| Create guest user and operator user
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create ``guest`` user with password 'secret'
- create ``operator`` user with password 'secret'

.. code-block:: shell

    # Create users with pre-set password ("secret")
    useradd -m -s /bin/bash guest                && echo "guest:secret"    | chpasswd
    useradd -m -s /bin/bash operator -g operator && echo "operator:secret" | chpasswd

|3| Create user specific login environments
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- guest

.. code-block:: shell

    cat > /home/lab/.guest_bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics

    #### SETUP guest KEYCHAIN FILE
    # Environment: EPICS_PVA_TLS_KEYCHAIN
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/client.p12
    # export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.5/client.p12

    #### SETUP guest Organisation
    # Environment: EPICS_PVA_AUTH_ORGANIZATION
    # Default    : <hostname>
    export EPICS_PVA_AUTH_ORGANIZATION=epics.org

    #### SETUP Address list
    # Make sure that the only PVs that are seen are upstream (pvacms, testioc, and tstioc)
    export EPICS_PVA_ADDR_LIST="pvxs-lab-pvacms pvxs-lab-testioc pvxs-lab-tstioc"
    export EPICS_PVA_AUTO_ADDR_LIST="NO"

    # set path
    export EPICS_HOST_ARCH=\$(\${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="\${PROJECT_HOME}/pvxs/bin/\${EPICS_HOST_ARCH}:$PATH"

    cd ~
    EOF

- operator

.. code-block:: shell

    cat > /home/admin/.operator_bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics

    #### SETUP operator KEYCHAIN FILE
    # Environment: EPICS_PVA_TLS_KEYCHAIN
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/client.p12
    # export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.5/client.p12

    #### SETUP operator Organisation
    # Environment: EPICS_PVA_AUTH_ORGANIZATION
    # Default    : <hostname>
    export EPICS_PVA_AUTH_ORGANIZATION=epics.org

    #### SETUP Address list
    # Make sure that the only PVs that are seen are upstream (pvacms, testioc, and tstioc)
    export EPICS_PVA_ADDR_LIST="pvxs-lab-pvacms pvxs-lab-testioc pvxs-lab-tstioc"
    export EPICS_PVA_AUTO_ADDR_LIST="NO"

    # set path
    export EPICS_HOST_ARCH=\$(\${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="${PROJECT_HOME}/pvxs/bin/\${EPICS_HOST_ARCH}:$PATH"

    cd ~
    EOF

- set permissions

.. code-block:: shell

    chown guest:guest       /home/guest/.guest_bashrc       && \
    chown operator:operator /home/operator/.operator_bashrc && \
    chmod 644               /home/guest/.guest_bashrc       && \
    chmod 644               /home/operator/.operator_bashrc

- add to login script

.. code-block:: shell

    echo "source ~/.guest_bashrc"    >> /home/guest/.bashrc
    echo "source ~/.operator_bashrc" >> /home/operator/.bashrc


|5| Lab Control Room Build Note
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*Normally you will run* ``gw_build_images`` *to create the* ``lab:latest`` *image from*
``example/kubernetes/docker/lab/Dockerfile``

- Note: You can use the helper function ``gw_build_images`` to build this image.  Make sure $PVXS is set to your
  Project ROOT pvxs directory then run the following:

.. code-block:: shell

    gw_build_images lab

- You can optionally add ``--no-cache`` to force a full rebuild

.. _spva_qs_gw_build:

|step| Configure Gateway Image
------------------------------------------

|1| Use a Prepackaged lab_base image & Install Pre-requisites
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- open a terminal and load pre-built image

.. code-block:: shell

    docker run -it --name gateway ${DOCKER_USERNAME}/lab_base:latest


- Install Pre-requisites
  - python
  - numpy
  - nose
  - ply
  - cython

.. code-block:: shell

    apt-get update && \
    apt-get install -y \
      ca-certificates \
      python3-dev \
      python3-numpy \
      python3-nose2 \
      python-is-python3 \
      python3-ply \
      cython3 \
      && \
    rm -rf /var/lib/apt/lists/*


|2| Build + install p4p (provides pvagw)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Build

.. code-block:: shell

    cd ${PROJECT_HOME}
    git clone --branch tls https://github.com/slac-epics/p4p-tls.git
    cd pvp-tls

    make distclean || true && \
    make -j$(nproc) all

    cd ${PROJECT_HOME}

|3| Create gateway user and login environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create ``gateway`` user with password 'secret'

.. code-block:: shell

    # Create user with pre-set password ("secret")
    useradd -m -s /bin/bash gateway && echo "gateway:secret" | chpasswd


- gateway login environment

.. code-block:: shell

    cat > /home/gateway/.gateway_bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics

    #### SETUP GATEWAY KEYCHAIN FILE
    # Environment: EPICS_PVA_TLS_KEYCHAIN
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/client.p12
    export EPICS_PVA_TLS_KEYCHAIN=\${XDG_CONFIG_HOME}/pva/1.5/gateway.p12
    # Environment: EPICS_PVAS_TLS_KEYCHAIN
    # Default    : ${XDG_CONFIG_HOME}/pva/1.5/server.p12
    # We will take the keychain from the conf file
    SVR_KEYCHAIN=\$(grep gatewayS gateway.conf > /dev/null && echo "gatewayS" || echo "gateway")
    export EPICS_PVAS_TLS_KEYCHAIN=\${XDG_CONFIG_HOME}/pva/1.5/\${SVR_KEYCHAIN}.p12

    #### SETUP Gateway Organisation
    # Environment: EPICS_PVA_AUTH_ORGANIZATION
    # Default    : <hostname>
    export EPICS_PVA_AUTH_ORGANIZATION=epics.org

    # set path
    export EPICS_HOST_ARCH=\$(\${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="\${PROJECT_HOME}/pvxs/bin/\${EPICS_HOST_ARCH}:$PATH"
    export PATH="\${PROJECT_HOME}/p4p/bin/\${EPICS_HOST_ARCH}:$PATH"

    cd ~
    EOF

|4| Create a gateway config file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- gateway.conf
- Note that this is suitable for a cluster deployment:
  - client ``addrlist`` points to the upstream services
- Assumes that gateway.p12 will contain a certificate with client and server EKU
- Assumes that gateway external port is ``31075`` for TCP and ``31076`` for TLS

.. code-block:: shell

    cat > /home/gateway/gateway.conf <<EOF
    {
      "version": 2,
      "readOnly": false,
      "clients": [
        {
          "name": "upstream",
          "autoaddrlist": false,
          "addrlist": "pvxs-lab-pvacms pvxs-lab-testioc pvxs-lab-tstioc",
          "tls_keychain": "/home/gateway/.config/pva/1.5/gateway.p12"
        }
      ],
      "servers": [
        {
          "name": "downstream",
          "clients": ["upstream"],
          "statusprefix": "GW:STS:",
          "autoaddrlist": false,
          "addrlist": "pvxs-lab-gateway pvxs-lab-pvacms",
          "tls_keychain": "/home/gateway/.config/pva/1.5/gateway.p12",
          "serverport": "31075",
          "EPICS_PVAS_TLS_PORT": "31076",
          "access": "gateway.acf",
          "pvlist": "gateway.pvlist"
        },
        {
          "name": "downstream_status",
          "clients": [],
          "interface": ["127.0.0.1"],
          "statusprefix": "GW:STS:"
        }
      ]
    }
    EOF

|5| Create a gateway pvlist file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- gateway.pvlist

.. code-block:: shell

    cat > /home/gateway/gateway.pvlist <<EOF
    test:.* ALLOW
    tst:.* ALLOW
    test:spec ALLOW SPECIAL
    CERT:CREATE(?::.*)? ALLOW CERT_CREATE
    CERT:STATUS(?::.*)? ALLOW CERT_STATUS
    EOF

|6| Create a gateway combined ACF file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- gateway.pvlist

.. code-block:: shell

    cat > /home/gateway/gateway.acf <<EOF
    UAG(USERS) {
        "x509/guest",
        "x509/operator",
        "x509/remote"
    }

    UAG(SPECIAL_USERS) {
        "x509/operator"
    }

    ASG(SPECIAL) {
        RULE(1,READ) {
            UAG(USERS)
        }
        RULE(1,WRITE,TRAPWRITE) {
            UAG(SPECIAL_USERS)
        }
    }

    ASG(CERT_CREATE) {
        RULE(1,WRITE)
    }

    ASG(CERT_STATUS) {
        RULE(1,READ)
    }

    ASG(DEFAULT) {
        RULE(1,READ) {
            UAG(USERS)
        }
    }
    EOF

|7| Set permissions and add to login profile
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    chown -R gateway:gateway /home/gateway && \
    chmod 644                /home/gateway/gateway.*

- add to login script

.. code-block:: shell

    echo "source ~/.gateway_bashrc" >> /home/gateway/.bashrc

|8| Configure Supervisor
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Create the log files with correct permissions

.. code-block:: shell

    touch /var/log/supervisor/gateway.out.log \
          /var/log/supervisor/gateway.err.log && \
    chown gateway:gateway \
          /var/log/supervisor/gateway.out.log \
          /var/log/supervisor/gateway.err.log

- Create the GATEWAY Supervisor config

.. code-block:: shell

    cat > /etc/supervisor/conf.d/gateway.conf <<EOF
    [program:gateway]
    command=/opt/epics/p4p/bin/linux-aarch64/pvagw /home/gateway/gateway.conf
    user=gateway
    autostart=true
    autorestart=true

    ; Send logs to container stdout/stderr
    stdout_logfile=/proc/1/fd/1
    stdout_logfile_maxbytes=0
    stderr_logfile=/proc/1/fd/2
    stderr_logfile_maxbytes=0
    stopsignal=TERM
    stopasgroup=true
    killasgroup=true
    EOF


|9| Start gateway Service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This step is optional.  Normally you will only do this in an image that is running in a cluster where the network
configuration can be controlled.

.. code-block:: shell

    /usr/bin/supervisord -c /etc/supervisor/supervisord.conf


Gateway Build Note
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*Normally you will run* ``gw_build_images`` *to create the* ``gateway:latest`` *image from*
``example/kubernetes/docker/gateway/Dockerfile``

- Note: You can use the helper function ``gw_build_images`` to build this image.  Make sure $PVXS is set to your
  Project ROOT pvxs directory then run the following:

.. code-block:: shell

    gw_build_images gateway

- You can optionally add ``--no-cache`` to force a full rebuild


|step| Build everything
------------------------------

- |terminal|\¹
- build all Docker images for the Gateway example (this may take several minutes)

.. code-block:: shell

    gw_build_images --no-cache

.. code-block:: console

    ~/Projects/com/slac/pvxs/example/kubernetes/docker ~
    --- Building lab_base Docker image ---
    [+] Building 11.5s (10/10) FINISHED                                                                      docker:desktop-linux
     => [internal] load build definition from Dockerfile                                                                     0.0s
     => => transferring dockerfile: 735B                                                                                     0.0s
     => [internal] load metadata for docker.io/georgeleveln/pvxs:local                                                       0.0s
     => [internal] load .dockerignore                                                                                        0.0s
     => => transferring context: 2B                                                                                          0.0s
     => CACHED [1/5] FROM docker.io/georgeleveln/pvxs:local@sha256:a103a4d94588531b5218f9134ea08e5d755ecdfd3adb95b8d83f941a  0.0s
     => => resolve docker.io/georgeleveln/pvxs:local@sha256:a103a4d94588531b5218f9134ea08e5d755ecdfd3adb95b8d83f941a8398083  0.0s
     => [internal] load build context                                                                                        0.0s
     => => transferring context: 38B                                                                                         0.0s
     => [2/5] RUN apt-get update &&     apt-get install -y             adduser             sudo             supervisor       9.1s
     => [3/5] RUN echo "PVXS = $(TOP)/../pvxs" >> /opt/epics/RELEASE.local                                                   0.2s
     => [4/5] RUN mkdir -p /var/log/supervisor                                                                               0.2s
     => [5/5] COPY supervisord.conf /etc/supervisor/supervisord.conf                                                         0.0s
     => exporting to image                                                                                                   1.8s
     => => exporting layers                                                                                                  1.5s
     => => exporting manifest sha256:23a331fa48be64ccdff0872d6a789f9faa1219a828f1e1af1bc31ea7c4954db1                        0.0s
     => => exporting config sha256:4f258b032790f4123a1b46952e53a43594afa580af12d533242f7652f29579a7                          0.0s
     => => exporting attestation manifest sha256:e353776192f1b0351bb3cd4fc20b1e7aa04efd91d6f651076707727494d021d7            0.0s
     => => exporting manifest list sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b8964905112c6a97b8e6392d                   0.0s
     => => naming to docker.io/georgeleveln/lab_base:local                                                                   0.0s
     => => unpacking to docker.io/georgeleveln/lab_base:local                                                                0.3s

    View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/dss0bxt962xi960zditqtkamx
    --- Successfully built lab_base:local ---
    --- Building lab Docker image ---
    [+] Building 1.4s (13/13) FINISHED                                                                       docker:desktop-linux
     => [internal] load build definition from Dockerfile                                                                     0.0s
     => => transferring dockerfile: 1.04kB                                                                                   0.0s
     => [internal] load metadata for docker.io/georgeleveln/lab_base:local                                                   0.0s
     => [internal] load .dockerignore                                                                                        0.0s
     => => transferring context: 2B                                                                                          0.0s
     => [1/8] FROM docker.io/georgeleveln/lab_base:local@sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b8964905112c6a97b8e  0.1s
     => => resolve docker.io/georgeleveln/lab_base:local@sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b8964905112c6a97b8e  0.0s
     => [internal] load build context                                                                                        0.0s
     => => transferring context: 69B                                                                                         0.0s
     => [2/8] RUN useradd -m -s /bin/bash operator -g operator && echo "operator:secret" | chpasswd                          0.2s
     => [3/8] RUN useradd -m -s /bin/bash guest                && echo "guest:secret"    | chpasswd                          0.2s
     => [4/8] COPY operator_bashrc /home/operator/.operator_bashrc                                                           0.0s
     => [5/8] COPY guest_bashrc /home/guest/.guest_bashrc                                                                    0.0s
     => [6/8] RUN chown operator:operator /home/operator/.operator_bashrc &&     chown guest:guest       /home/guest/.guest  0.1s
     => [7/8] RUN echo "source ~/.operator_bashrc" >> /home/operator/.bashrc                                                 0.2s
     => [8/8] RUN echo "source ~/.guest_bashrc"    >> /home/guest/.bashrc                                                    0.1s
     => exporting to image                                                                                                   0.2s
     => => exporting layers                                                                                                  0.1s
     => => exporting manifest sha256:6c4457ef5a9f4d626f8632cb394fdeaee7aad2ec63f60a57ab29df9f63b1b203                        0.0s
     => => exporting config sha256:2bd25d5cbfd0a461d81ad6d6c45f8e57163ea88a0c803adf057006967f42494c                          0.0s
     => => exporting attestation manifest sha256:634911735d2c797eec05d1a2aee640653e1508b0aa3bfefe8961c9aae0443bc0            0.0s
     => => exporting manifest list sha256:9186501b8d4585569d079c34123a13e5066acd9872b1744935363663fed84b19                   0.0s
     => => naming to docker.io/georgeleveln/lab:local                                                                        0.0s
     => => unpacking to docker.io/georgeleveln/lab:local                                                                     0.0s

    View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/ujvteu8tgg9yol6riod8jlcwu
    --- Successfully built lab:local ---
    --- Building testioc Docker image ---
    [+] Building 1.1s (13/13) FINISHED                                                                       docker:desktop-linux
     => [internal] load build definition from Dockerfile                                                                     0.0s
     => => transferring dockerfile: 1.27kB                                                                                   0.0s
     => [internal] load metadata for docker.io/georgeleveln/lab_base:local                                                   0.0s
     => [internal] load .dockerignore                                                                                        0.0s
     => => transferring context: 2B                                                                                          0.0s
     => CACHED [1/8] FROM docker.io/georgeleveln/lab_base:local@sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b8964905112c  0.0s
     => => resolve docker.io/georgeleveln/lab_base:local@sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b8964905112c6a97b8e  0.0s
     => [internal] load build context                                                                                        0.0s
     => => transferring context: 110B                                                                                        0.0s
     => [2/8] RUN useradd -m -s /bin/bash testioc && echo "testioc:secret" | chpasswd                                        0.2s
     => [3/8] COPY testioc_bashrc /home/testioc/.testioc_bashrc                                                              0.0s
     => [4/8] COPY testioc.acf    /home/testioc/testioc.acf                                                                  0.0s
     => [5/8] RUN chown testioc:testioc /home/testioc/.testioc_bashrc &&     chmod 644             /home/testioc/.testioc_b  0.1s
     => [6/8] RUN echo "source ~/.testioc_bashrc" >> /home/testioc/.bashrc                                                   0.1s
     => [7/8] RUN touch /var/log/supervisor/testioc.out.log           /var/log/supervisor/testioc.err.log &&     chown test  0.1s
     => [8/8] COPY testioc-supervisor.conf /etc/supervisor/conf.d/testioc.conf                                               0.0s
     => exporting to image                                                                                                   0.2s
     => => exporting layers                                                                                                  0.1s
     => => exporting manifest sha256:21c800c85c7d979993015d1abe574fc6a6324a38f69e5c382d340d1c17e51f84                        0.0s
     => => exporting config sha256:2bf704065e7b020abb96f33ced5398ef6d81dcfb233443791020cee8f5dd13a3                          0.0s
     => => exporting attestation manifest sha256:719ba040858bfc293f842600714ef2f0c5ace31e57a1fa5e45c3685a32b6b5d1            0.0s
     => => exporting manifest list sha256:127af21fd863a5e6f10ba942ee1f52c116b74f230e2bede139c756fe6bace38a                   0.0s
     => => naming to docker.io/georgeleveln/testioc:local                                                                    0.0s
     => => unpacking to docker.io/georgeleveln/testioc:local                                                                 0.1s

    View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/iie4xays61gbwyjr43pmo1sfm
    --- Successfully built testioc:local ---
    --- Building tstioc Docker image ---
    [+] Building 1.1s (13/13) FINISHED                                                                       docker:desktop-linux
     => [internal] load build definition from Dockerfile                                                                     0.0s
     => => transferring dockerfile: 1.24kB                                                                                   0.0s
     => [internal] load metadata for docker.io/georgeleveln/lab_base:local                                                   0.0s
     => [internal] load .dockerignore                                                                                        0.0s
     => => transferring context: 2B                                                                                          0.0s
     => CACHED [1/8] FROM docker.io/georgeleveln/lab_base:local@sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b8964905112c  0.0s
     => => resolve docker.io/georgeleveln/lab_base:local@sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b8964905112c6a97b8e  0.0s
     => [internal] load build context                                                                                        0.0s
     => => transferring context: 107B                                                                                        0.0s
     => [2/8] RUN useradd -m -s /bin/bash tstioc && echo "tstioc:secret" | chpasswd                                          0.2s
     => [3/8] COPY tstioc_bashrc /home/tstioc/.tstioc_bashrc                                                                 0.0s
     => [4/8] COPY tstioc.acf    /home/tstioc/tstioc.acf                                                                     0.0s
     => [5/8] RUN chown tstioc:tstioc /home/tstioc/.tstioc_bashrc &&     chmod 644           /home/tstioc/.tstioc_bashrc &&  0.1s
     => [6/8] RUN echo "source ~/.tstioc_bashrc" >> /home/tstioc/.bashrc                                                     0.2s
     => [7/8] RUN touch /var/log/supervisor/tstioc.out.log           /var/log/supervisor/tstioc.err.log &&     chown tstioc  0.1s
     => [8/8] COPY tstioc-supervisor.conf /etc/supervisor/conf.d/tstioc.conf                                                 0.0s
     => exporting to image                                                                                                   0.3s
     => => exporting layers                                                                                                  0.1s
     => => exporting manifest sha256:ad293a515fec2c9986b1c6090c5c4538cd56a0cb39403d7a933aad12583435f5                        0.0s
     => => exporting config sha256:275dd15f99f105b350f47c5cfd51e5674cdb7f17575f60ad037e20fd735fbfb9                          0.0s
     => => exporting attestation manifest sha256:b57e5d795187fe032f2cae4504ab6351a46dc942677e28852231e1f08ec60346            0.0s
     => => exporting manifest list sha256:8c6fbfdd03c7e2ebf51be96264db631365a7cb5a80c1a4ab509d35b88b959045                   0.0s
     => => naming to docker.io/georgeleveln/tstioc:local                                                                     0.0s
     => => unpacking to docker.io/georgeleveln/tstioc:local                                                                  0.1s

    View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/ip2ng0txcpkq3vtezwtwenga2
    --- Successfully built tstioc:local ---
    --- Building pvacms Docker image ---
    [+] Building 1.4s (15/15) FINISHED                                                                       docker:desktop-linux
     => [internal] load build definition from Dockerfile                                                                     0.0s
     => => transferring dockerfile: 1.35kB                                                                                   0.0s
     => [internal] load metadata for docker.io/georgeleveln/lab_base:local                                                   0.0s
     => [internal] load .dockerignore                                                                                        0.0s
     => => transferring context: 2B                                                                                          0.0s
     => CACHED [ 1/10] FROM docker.io/georgeleveln/lab_base:local@sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b896490511  0.0s
     => => resolve docker.io/georgeleveln/lab_base:local@sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b8964905112c6a97b8e  0.0s
     => [internal] load build context                                                                                        0.0s
     => => transferring context: 109B                                                                                        0.0s
     => [ 2/10] RUN useradd -m -s /bin/bash pvacms && echo "pvacms:secret" | chpasswd                                        0.2s
     => [ 3/10] RUN useradd -m -s /bin/bash admin  && echo "admin:secret"  | chpasswd                                        0.2s
     => [ 4/10] COPY pvacms_bashrc /home/pvacms/.cms_bashrc                                                                  0.0s
     => [ 5/10] COPY admin_bashrc  /home/admin/.cms_bashrc                                                                   0.0s
     => [ 6/10] RUN chown pvacms:pvacms /home/pvacms/.cms_bashrc &&     chown admin:admin   /home/admin/.cms_bashrc  &&      0.1s
     => [ 7/10] RUN echo "source ~/.cms_bashrc" >> /home/pvacms/.bashrc                                                      0.1s
     => [ 8/10] RUN echo "source ~/.cms_bashrc" >> /home/admin/.bashrc                                                       0.2s
     => [ 9/10] RUN touch /var/log/supervisor/pvacms.out.log           /var/log/supervisor/pvacms.err.log &&     chown pvac  0.1s
     => [10/10] COPY pvacms-supervisor.conf /etc/supervisor/conf.d/pvacms.conf                                               0.0s
     => exporting to image                                                                                                   0.3s
     => => exporting layers                                                                                                  0.1s
     => => exporting manifest sha256:1a473a532b9c21e8f2ef743e8a174c012363c2554a273adb2afe77ff6769d980                        0.0s
     => => exporting config sha256:138c1f95d94ee6926f31d528c23dc1aa3ef77a50e8852613a6fbcc7768dc32d1                          0.0s
     => => exporting attestation manifest sha256:672d403610fcc662c2d5d11a4b5e712496d5648a0eb4140210dafe352ff480b0            0.0s
     => => exporting manifest list sha256:4547ce8cbb85472088cc60160960873c738e1c823ed80193948b153f6643eaf2                   0.0s
     => => naming to docker.io/georgeleveln/pvacms:local                                                                     0.0s
     => => unpacking to docker.io/georgeleveln/pvacms:local                                                                  0.1s

    View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/yfpfcy0wj39x1nwyjlyuydubm
    --- Successfully built pvacms:local ---
    --- Building gateway Docker image ---
    [+] Building 25.9s (23/23) FINISHED                                                                      docker:desktop-linux
     => [internal] load build definition from Dockerfile                                                                     0.0s
     => => transferring dockerfile: 1.93kB                                                                                   0.0s
     => [internal] load metadata for docker.io/georgeleveln/lab_base:local                                                   0.0s
     => [internal] load .dockerignore                                                                                        0.0s
     => => transferring context: 2B                                                                                          0.0s
     => CACHED [ 1/18] FROM docker.io/georgeleveln/lab_base:local@sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b896490511  0.0s
     => => resolve docker.io/georgeleveln/lab_base:local@sha256:3bcdd56b34f2c6f32e42dfbe0d2f87df40461741b8964905112c6a97b8e  0.0s
     => [internal] load build context                                                                                        0.0s
     => => transferring context: 34.99kB                                                                                     0.0s
     => [ 2/18] RUN apt-get update &&     apt-get install -y       ca-certificates       python3-dev       python3-numpy     8.1s
     => [ 3/18] WORKDIR /opt/epics                                                                                           0.0s
     => [ 4/18] COPY ./p4p ./p4p                                                                                             0.1s
     => [ 5/18] WORKDIR /opt/epics/p4p                                                                                       0.0s
     => [ 6/18] RUN make distclean || true &&     make -j$(nproc) all                                                       11.3s
     => [ 7/18] RUN useradd -m -s /bin/bash gateway && echo "gateway:secret" | chpasswd                                      0.2s
     => [ 8/18] COPY pvxs/example/kubernetes/docker/gateway/gateway_bashrc /home/gateway/.gateway_bashrc                     0.0s
     => [ 9/18] COPY pvxs/example/kubernetes/docker/gateway/gateway.acf    /home/gateway/gateway.acf                         0.0s
     => [10/18] RUN chown gateway:gateway /home/gateway/.gateway_bashrc &&     chmod 644             /home/gateway/.gateway  0.1s
     => [11/18] RUN echo "source ~/.gateway_bashrc" >> /home/gateway/.bashrc                                                 0.1s
     => [12/18] WORKDIR /home/gateway                                                                                        0.0s
     => [13/18] COPY pvxs/example/kubernetes/docker/gateway/gateway.conf   .                                                 0.0s
     => [14/18] COPY pvxs/example/kubernetes/docker/gateway/gateway.pvlist .                                                 0.0s
     => [15/18] COPY pvxs/example/kubernetes/docker/gateway/gateway.acf    .                                                 0.0s
     => [16/18] RUN chown -R gateway:gateway /home/gateway &&     chmod 644                /home/gateway/gateway.*           0.1s
     => [17/18] RUN touch /var/log/supervisor/gateway.out.log           /var/log/supervisor/gateway.err.log &&     chown ga  0.1s
     => [18/18] COPY pvxs/example/kubernetes/docker/gateway/gateway-supervisor.conf /etc/supervisor/conf.d/gateway.conf      0.0s
     => exporting to image                                                                                                   5.2s
     => => exporting layers                                                                                                  3.8s
     => => exporting manifest sha256:ee0a74908a82ce58f5feb7792f6e9e899fc5bf44b4e3b3c98f0ae8f1350aef93                        0.0s
     => => exporting config sha256:f6dd4db669742e7f9adca3f6c6ed7c712c5c8efc7ed1d95d1a40c9cf9d4ff040                          0.0s
     => => exporting attestation manifest sha256:bba60ac079d8bac463ccdc3c625b13ef4442c489c0268294987cc551aa4e8011            0.0s
     => => exporting manifest list sha256:7e82861729f0a33ebb309c6ddf7fe74e98961339ce7ccc9a175421cec9881aa7                   0.0s
     => => naming to docker.io/georgeleveln/gateway:local                                                                    0.0s
     => => unpacking to docker.io/georgeleveln/gateway:local                                                                 1.3s

    View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/2a0ftrpayym0wjx2btwiioxf1
    --- Successfully built gateway:local ---
    ~

|step| Helm Deployment Options
-----------------------------------------------------

You can add extra options to helm using the ``gw_deploy`` wrapper.
e.g.

.. code-block:: shell

    gw_deploy --set <key>=<option> ...

(where ``<key>`` and ``<option>`` are the keys and options in the table below.

+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| key                                               | option              | description                                                    |
+===================================================+=====================+================================================================+
| ``dockerUsername``                                | ``<username>``      | the dockerhub username to use                                  |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.config``                                | ``<file_contents>`` | to specify an alternative ``~/gateway.conf`` file              |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.debug.enabled``                         | ``true|false``      | true to enable debug logs for gateway.                         |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.debug.logLevel``                        | ``<str>=<loglvl>``  | if ``gateway.debug.enabled`` sets the logger str and level.    |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.expose.mode``                           | ``NodePort``        | uses NodePort to expose the gateway port                       |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.expose.nodePortTcp``                    | ``<port>``          | the port to expose on the node if ``NodePort`` is selected     |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.expose.nodePortTls``                    | ``<port>``          | the port to expose on the node if ``NodePort`` is selected     |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.expose.tcpPort``                        | ``<port>``          | the port to expose / connect to on the pod                     |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.expose.tlsPort``                        | ``<port>``          | the port to expose / connect to on the pod                     |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.expose.udpPort``                        | ``<port>``          | the port to expose / connect to on the pod                     |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.persistence.enabled``                   | ``true|false``      | true if you want gateway configuration to survive pod          |
|                                                   |                     | restarts. Uses a persistent volume                             |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.persistence.size``                      | ``<size>``          | the size to use for gateway storage class volume if specified  |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.persistence.storageClassName``          | ``<class>``         | the name to use for gateway storage class volume if specified  |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``gateway.separate_server_keychain``              | ``true|false``      | true to use different names for server and client keychains    |
|                                                   |                     | in gateway.  ``gateway.p12`` and ``gatewayS.p12``              |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``lab.keepalive.args``                            | ``<args>``          | the lab keepalive args if ``lab.keepalive.enabled`` is true    |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``lab.keepalive.command``                         | ``<command>``       | the lab keepalive command if ``lab.keepalive.enabled`` is true |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``lab.keepalive.enabled``                         | ``true|false``      | true to install a keep alive for the lab pod                   |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``lab.persistence.enabled``                       | ``true|false``      | true if you want lab configuration to survive pod restarts.    |
|                                                   |                     | Uses a persistent volume                                       |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``lab.persistence.size``                          | ``<size>``          | the size to use for lab storage class volume if specified      |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``lab.persistence.storageClassName``              | ``<class>``         | the name to use for lab storage class volume if specified      |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``nameOverride``                                  | ``<name>``          | to override the chart name ``pvxs-lab``                        |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``networkPolicy.enabled``                         | ``true|false``      | true if you want lab to configure a kubernetes network policy  |
|                                                   |                     | that controls inter-pod accessibility.  Many kubernetes        |
|                                                   |                     | implementation don't enforce these (e.g. Docker Desktop)       |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``ports.ports.exposePvaTls``                      | ``true|false``      | true to expose the TLS port on the pods                        |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``ports.pvaTcp``                                  | ``<port>``          | port to expose on each PVAccess pods for TCP connections       |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``ports.pvaTls``                                  | ``<port>``          | port to expose on each PVAccess pods for TLS connections       |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``ports.pvaUdp``                                  | ``<port>``          | port to expose on each PVAccess pods for UDP broadcasts        |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``pvacms.debug.enabled``                          | ``true|false``      | true to enable debug logs for pvacms.                          |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``pvacms.debug.logLevel``                         | ``<str>=<loglvl>``  | if ``pvacms.debug.enabled`` sets the logger str and level.     |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``pvacms.persistence.enabled``                    | ``true|false``      | true if you want pvacms configuration to survive pod restarts. |
|                                                   |                     | Uses a persistent volume                                       |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``pvacms.persistence.size``                       | ``<size>``          | the size to use for pvacms storage class volume if specified   |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``pvacms.persistence.storageClassName``           | ``<class>``         | the name to use for pvacms storage class volume if specified   |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``testioc.debug.enabled``                         | ``true|false``      | true to enable debug logs for testioc.                         |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``testioc.debug.logLevel``                        | ``<str>=<loglvl>``  | if ``testioc.debug.enabled`` sets the logger str and level.    |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``testioc.persistence.enabled``                   | ``true|false``      | true if you want testioc configuration to survive pod          |
|                                                   |                     | restarts. Uses a persistent volume                             |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``testioc.persistence.storageClassName``          | ``<class>``         | the name to use for testioc storage class volume if specified  |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``testioc.persistence.size``                      | ``<size>``          | the size to use for testioc storage class volume if specified  |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``tstioc.debug.enabled``                          | ``true|false``      | true to enable debug logs for tstioc.                          |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``tstioc.debug.logLevel``                         | ``<str>=<loglvl>``  | if ``tstioc.debug.enabled`` sets the logger str and level.     |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``tstioc.persistence.enabled``                    | ``true|false``      | true if you want tstioc configuration to survive pod           |
|                                                   |                     | restarts. Uses a persistent volume                             |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``tstioc.persistence.size``                       | ``<size>``          | the size to use for tstioc storage class volume if specified   |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
| ``tstioc.persistence.storageClassName``           | ``<class>``         | the name to use for tstioc storage class volume if specified   |
+---------------------------------------------------+---------------------+----------------------------------------------------------------+
