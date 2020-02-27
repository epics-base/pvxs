TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

USR_CPPFLAGS += -DPVXS_API_BUILDING

ifneq (,$(filter gcc clang,$(CMPLR_CLASS)))

# we explicitly mark dllimport/export anyway.
# So hide our internal symbols to speed up linking/loading on all targets.
USR_CFLAGS += -fvisibility=hidden
USR_CXXFLAGS += -fvisibility=hidden -fvisibility-inlines-hidden

# Compress debug information on ELF targets for ~25%-50% reduction in .so and .a file size
# (C++ debug info is Huuuge!)
#USR_CFLAGS_Linux += -gz=zlib
#USR_CXXFLAGS_Linux += -gz=zlib
#USR_LDFLAGS_Linux += -Wl,--compress-debug-sections=zlib

# LTO takes a nice chunk out of the .so text size, but blows up the .a size
#USR_CXXFLAGS += -flto
#USR_LDFLAGS += -flto

# fault on any undefined symbols (eg. from missing LIB_SYS_LIBS)
# breaks on older ncurses (circa RHEL6) not using the INPUT() trick to pull in libtinfo.so
USR_LDFLAGS_Linux += -Wl,--no-undefined -Wl,--no-allow-shlib-undefined

endif

EXPANDVARS += PVXS_MAJOR_VERSION
EXPANDVARS += PVXS_MINOR_VERSION
EXPANDVARS += PVXS_MAINTENANCE_VERSION

EXPANDFLAGS += $(foreach var,$(EXPANDVARS),-D$(var)="$(strip $($(var)))")

SHRLIB_VERSION = $(PVXS_MAJOR_VERSION).$(PVXS_MINOR_VERSION)

INC += pvxs/version.h
INC += pvxs/versionNum.h
INC += pvxs/log.h
INC += pvxs/unittest.h
INC += pvxs/util.h
INC += pvxs/bitmask.h
INC += pvxs/sharedArray.h
INC += pvxs/data.h
INC += pvxs/nt.h
INC += pvxs/server.h
INC += pvxs/sharedpv.h
INC += pvxs/source.h
INC += pvxs/client.h

LIBRARY = pvxs

LIB_SRCS += log.cpp
LIB_SRCS += unittest.cpp
LIB_SRCS += util.cpp
LIB_SRCS += bitmask.cpp
LIB_SRCS += type.cpp
LIB_SRCS += data.cpp
LIB_SRCS += pvrequest.cpp
LIB_SRCS += dataencode.cpp
LIB_SRCS += nt.cpp
LIB_SRCS += evhelper.cpp
LIB_SRCS += udp_collector.cpp

LIB_SRCS += config.cpp
LIB_SRCS += conn.cpp

LIB_SRCS += server.cpp
LIB_SRCS += serverconn.cpp
LIB_SRCS += serverchan.cpp
LIB_SRCS += serverintrospect.cpp
LIB_SRCS += serverget.cpp
LIB_SRCS += servermon.cpp
LIB_SRCS += serversource.cpp
LIB_SRCS += sharedpv.cpp

LIB_SRCS += client.cpp
LIB_SRCS += clientreq.cpp
LIB_SRCS += clientconn.cpp
LIB_SRCS += clientintrospect.cpp
LIB_SRCS += clientget.cpp

LIB_LIBS += Com

LIB_SYS_LIBS += event_core

LIB_SYS_LIBS_DEFAULT += event_pthreads
LIB_SYS_LIBS_WIN32 += netapi32 ws2_32
LIB_SYS_LIBS_vxWorks =


#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

# Can't use EXPAND as generated headers must appear
# in O.Common, but EXPAND emits rules for O.$(T_A)
../O.Common/pvxs/versionNum.h: ../pvxs/versionNum.h@
	$(MKDIR) $(COMMON_DIR)/pvxs
	$(EXPAND_TOOL) $(EXPANDFLAGS) $($@_EXPANDFLAGS) $< $@

ifeq ($(T_A),)
cppcheck:
	echo "Run in O.$(EPICS_HOST_ARCH) sub-dir"
	false
else
ifeq ($(OS_CLASS)$(GNU),LinuxYES)

# gcc specific way to discover actual list of directories searched,
# including implied target specific directories (like /usr/include).
# only includes directories which exist.
# $ echo | gcc -E -xc++ -Wp,-v -
# ...
# #include "..." search starts here:
# #include <...> search starts here:
#  /usr/include/c++/8
# ...
#  /usr/include
# End of search list.
# ...

REALINC=$(shell echo | $(CC) $(INCLUDES) -E -xc++ -Wp,-v - 2>&1 | grep '^ '| xargs echo)

cppcheck:
	cppcheck \
 --std=posix --std=c11 --std=c++11 --enable=all \
 -D__GNUC__ -D__STDC__ \
 -D__cplusplus=201103L \
 $(REALINC:%=-I%) \
 .. ../pvxs

else
cppcheck:
	echo "cppcheck only configured for Linux+GCC targets."
endif
endif

.PHONY: cppcheck
