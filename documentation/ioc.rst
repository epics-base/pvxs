IOC Integration
###############

.. code-block:: c++

    #include <pvxs/iochooks.h>
    namespace pvxs { namespace namespace ioc { ... } }

The separate ``pvxsIoc`` library exists to run a PVXS server as part of an IOC.
See also :ref:`includepvxs`.

IOC Integration respects the **$PVXS_LOG** as well as **$EPICS_PVA\*** environment variables.
Changes to this environment variable are possible prior to
calling ``\*_registerRecordDeviceDriver(pdbbase)``.

IOC shell
^^^^^^^^^

The "pvxsIoc" library adds several IOC shell functions which apply to all PVs
served by the Integrated PVA server.

.. cpp:function:: void pvxsr(int level)

    PVXS Server Report.  Shows information about server configuration (level==0)
    or about connected clients (level>0).  Indirectly calls `pvxs::server::Source::show`.

.. cpp:function:: void pvxsl(int level)

    PVXS Server List.  Lists attached Sources and PV names.
    Indirectly calls `pvxs::server::Source::onList`.

.. cpp:function:: void pvxsi()

    Print information about module versions, target, and toolchain.
    May be requested when reporting a bug.

Adding custom PVs to Server
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. doxygenfunction:: pvxs::ioc::server


QSRV 2
######

Beginning with PVXS UNRELEASED the functionality of `QSRV <https://epics-base.github.io/pva2pva>`_
is replicated in the ``pvxsIoc`` library.
Currently this is considered **alpha** level, with missing functionality.
So users must **opt in** by setting **$PVXS_QSRV_ENABLE=YES** before ``iocInit()``. ::

    epicsEnvSet("PVXS_QSRV_ENABLE", "YES")
    iocInit()

Functionality
-------------

The features of QSRV are divided into three broad categories.

- Single PV access
- Group PV access
- PVA Links


IOC Shell
^^^^^^^^^

IOC Shell commands specific to database integration.

.. cpp:function:: void pvxgl(int level, const char* pattern)

    Group PV information.  At detail level 0, lists Group names.
    Pattern restricts listing to only matching names.

.. cpp:function:: void dbLoadGroup(const char *file, const char* macros)

    Load Group definitions from a separate JSON file.
    (as opposed to ``info(Q:group, {...})`` in a .db file)
    See :ref:`groupjson`.

Single PV
^^^^^^^^^

When QSRV is enabled, access to individual/single PVs in the global process database
is automatic and equivalent to the access provided by the Channel Access server
in the IOC (aka. RSRV).

So ``caget pv:name`` and ``pvxget pv:name`` should be functionally equivalent.

Additionally, adding a ``$`` suffix when addressing a ``DBF_STRING`` or ``DBF_*LINK`` field
will make it visible as a PVA string.
It will not be necessary for clients to interpret a ``char[]`` as a "long string". ::

    # eg.
    pvget some:record.NAME$
    pvget some:record.INP$

An ``info(Q:form, "...")`` may be used to set the ``display.form`` PVA meta-data hint
which is used by some OPI clients. ::

    record(longin, "my:bits") {
        field(VAL, "0x1234")
        info(Q:form, "Hex") # hint to clients to render as hexadecimal
    }

Currently supported format hints are:

- Default
- String
- Binary
- Decimal
- Hex
- Exponential
- Engineering

Group PV
^^^^^^^^

By default no Group PVs are defined.

A Group PV is a mapping values taken from one or more Single PVs to be composed into an overall structure.

A Group is defined using a JSON syntax.
Groups are defined with respect to a *Group Name*, which is also the PV name used when accessing the group.
Unlike records, the "field" of a group have a different meaning than the fields of a record.
Group field names are *not* part of the PV name.

A group definition may be split among several records, or included in separate JSON file(s).
For example of a group including two records is: ::

    record(ai, "rec:X") {
        info(Q:group, {
            "grp:name": {
                "X": {+channel:"VAL"}
            }
        })
    }
    record(ai, "rec:Y") {
        info(Q:group, {
            "grp:name": {
                "Y": {+channel:"VAL"} // .VAL in enclosing record()
            }
        })
    }

Or equivalently with separate .db file and .json files. ::

    # some .db
    record(ai, "rec:X") {}
    record(ai, "rec:Y") {}
    # in some .json
    {
        "grp:name": {
            "X": {+channel:"rec:X.VAL"}, // full PV name
            "Y": {+channel:"rec:Y.VAL"}
        }
    }

This group, named ``grp:name``, has two group fields ``X`` and ``Y``. ::

    $ pvget grp:name
    grp:name
    structure 
        epics:nt/NTScalar:1.0 X
            double value 0
            alarm_t alarm INVALID DRIVER UDF
            time_t timeStamp <undefined> 0
    ...
        epics:nt/NTScalar:1.0 Y
            double value 0
            alarm_t alarm INVALID DRIVER UDF
            time_t timeStamp <undefined> 0
    ...

.. _groupjson:

JSON Reference
^^^^^^^^^^^^^^

A Group `JSON schema <qsrv2-schema-0.json>`_ definition file is available.

.. code-block:: json

    record(...) {
        info(Q:group, {
            "<group_name>":{
                +id:"some/NT:1.0",  // top level ID
                +atomic:true,       // whether monitors default to multi-locking atomicity
                "<field.name>":{
                    +type:"scalar", // controls how map VAL mapped onto <field.name>
                    +channel:"VAL",
                    +id:"some/NT:1.0",
                    +trigger:"*",   // "*" or comma seperated list of <field.name>s
                    +putorder:0,    // set for fields where put is allowed, processing done in increasing order
                },
                "": {+type:"meta", +channel:"VAL"} // special case adds meta-data fields at top level
            }
        })
    }

Field mapping ``+type``:

- ``scalar`` (default) places an NTScalar or NTScalarArray as a sub-structure.  (see :ref:`ntscalar`)
- ``plain`` ignores all meta-data and places only the "value" as a field.
            The field placed will have the type of the ``value`` field of the equivalent NTScalar/NTScalarArray as a field.
- ``any`` places a variant union into which the "value" is stored.
- ``meta`` places only the "alarm" and "timeStamp" fields of ``scalar``.
- ``structure`` places only the associated ``+id``.  Has no ``+channel``.
- ``proc`` places no fields.  The associated ``+channel`` is processed on PUT.


``+channel``:

When included in an ``info(Q:group, ...``, the ``+channel`` must only name a field of the enclosing record.
(eg. ``+channel:"VAL"``)
When in a separate JSON file, ``+channel`` must be a full PV name, beginning with a record or alias name.
(eg. ``+channel:"record:name.VAL"``)

Group ``+trigger``:

The field triggers define how changes to the constituent field are translated into a subscription update to the group.
``+trigger`` may be an empty string (``""``), a wildcard ``"*"``, or a comma separated list of group field names.

- ``""`` (the default) means that changes to the field do not cause a subscription update.
- ``"*"`` causes a subscription update containing the most recent values/meta-data of all group fields.
- A comma separated list of field names causes an update with the most recent values of only the listed group fields.

Access Security
^^^^^^^^^^^^^^^

QSRV will enforce an optional access control policy file (``.acf``) loaded by ``asSetFilename()``.
This policy is applied to Single PVs just as RSRV does for Channel Access.
With Group PVs, restrictions are not defined for the group, but rather for the individual member records.
The same policy applies whether record is accessed individually, or through a group.

Policy application differs from CA (RSRV) in several ways:

Client hostname is always the numeric IP address.
``HAG()`` entries must either contained numeric IP addresses,
or that ``asCheckClientIP=1`` flag must be set to translate hostnames into IPs on ACF file load (effects CA server as well).
This prevents clients from trivially forging "hostname".
In additional to client usernames ``UAG()`` definitions may contained items beginning with ``role/`` which are matched against the list of local systems groups of which the client username is a member.
Username to group lookup is done *locally* by QSRV, and depends on IOC host authentication configuration.
Note that this is still based on the client provided username string. ::

    UAG(special) {
        someone, "role/op"
    }

The "special" ``UAG()`` will match CA or PVA clients with the username "someone".
It will also match a PVA client if the "special" account exists locally,
and is a member of the "op" group (supported on POSIX targets and Windows).

PVAccess Links
^^^^^^^^^^^^^^

TODO...
