Examples
========

Mailbox Server
--------------

Serves a single PV name.
Any updates written (PUT) to this PV will be stored verbatim
and sent to any subscribers.

.. literalinclude:: ../example/mailbox.cpp
    :language: c++
    :name: mailbox.cpp
