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

