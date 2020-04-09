.. _reportbug:

Reporting a Bug
===============

Before reporting a bug, please check to see if this issue has already been `reported <https://github.com/mdavidsaver/pvxs/issues>`_.

When composing a new report, please run the included automatic tests "make runtests" and mention the results.
It is enough to mention "All tests successful." if this is so.  (see `runtests`)

`Bug reports <https://github.com/mdavidsaver/pvxs/issues>`_ should always include:

* EPICS Base version or VCS commit
* PVXS module version or VCS commit
* libevent version or VCS commit (running "pvxget -V" shows these)
* EPICS host and target archs.  (eg. "linux-x86_64")
* Host OS name and version (eg. run "cat /etc/issue")
* Compiler name and version (eg. run "gcc --version")
* The values of any $EPICS_PVA* environment variables which are set.
* Any local/site modifications to PVXS or libevent
* Concise instructions for reproducing the issue.

Additional information which may be relevant:

* Number of network interfaces if more than one.
* Whether clients and/or servers are on the same host or diffrent hosts.
* Whether clients and/or servers are in the same subnet or different subnets
* Whether network traffic crosses between virtual machine(s) and physical host(s).
* Firewall rules on UDP traffic to/from port 5075 or TCP connections to port 5074
* Any local/site modifications to EPICS Base

.. _contrib:

Contributing
============

The recommended path for including changes is through [Pull Request](https://github.com/mdavidsaver/pvxs/pulls).

When changing c++ code please do:

* Indent with 4 spaces.  No hard tabs.  UNIX style EoL.
* Try to maintain the style of surrounding code.
* Include meaningful code comments where reasonable.

but do not:

* Add any c++ global constructors or destructors in the pvxs library.  (Ok in tools, examples, or tests)

When committing changes please do:

* Include a commit message
* Break up changes into multiple commits where reasonable
* Include whitespace only changes as seperate commits

Notes
=====

Misc. notes on design and Implementation.

* All Server and client Context instances listening on the same UDP port# within a process
  will share a single UDP socket.

* The UDP local multicast fanout aspect of the PVA protocol is not implemented.

* Client UDP search retry follows a linear backoff starting from 1 second
  and stepping to 30 seconds.  cf. bucketInterval and nBuckets in client.cpp.

* To level UDP search traffic, search retry may delay a PV for an extra
  bucket if the difference in the number of PVs in the desired and subsequent
  buckets is too large.

* Client Context::hurryUp() expires the search bucket timer immediately,
  saving up to bucketInterval seconds.

* Each Value refers points to a pair of FieldDesc and FieldStorage in arrays
  of the same.  Value::operator[] steps around in these arrays.

* There is a hidden StructTop which holds the FieldStorage array and holds
  a shared_ptr to the FieldDesc array to join ownership of the two.

* TCP connection buffering will read up to tcp_readahead (cf. conn.h) bytes
  while waiting for a complete header.  After a header is received,
  the larger of tcp_readahead or the message body length is buffered.

