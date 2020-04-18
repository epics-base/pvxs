Systemtap scripts
=================

This directory contains systemtap scripts for inspecting processes using PVXS.

Unless run from this directory, scripts will **require modification** of the `process(PATH)` entries
with the installed location of libpvxs.so.* files.

Debian 10 users may need to add `-DSTP_NO_BUILDID_CHECK` if a "Build-id mismatch"
is seen with a fresh build.

Setup
-----

Remember to install kernel debug symbols (which are huge).

```sh
# Debian
apt-get install systemtap systemtap-doc systemtap-sdt-dev linux-image-$(uname -r)-dbg
```

Rebuild PVXS after installing systemtap-sdt-dev to include probe points.


List available library probe points
-----------------------------------

```sh
$ stap -L 'process("lib/linux-x86_64/libpvxs.so.*").mark("*")'
process("/abs/path/to/pvxs/lib/linux-x86_64-debug/libpvxs.so.0.0").mark("connclose") $arg1:long $arg2:long
...
```

This will list available library probe point (aka. marker)
names and argument names and types.
