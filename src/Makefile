TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

USR_CPPFLAGS += -DPVXS_API_BUILDING

# fault on any undefined symbols (eg. from missing LIB_SYS_LIBS)
USR_LDFLAGS_Linux += -Wl,--no-undefined -Wl,--no-allow-shlib-undefined
USR_LDFLAGS_DEFAULT +=

SHRLIB_VERSION = $(PVXS_MAJOR_VERSION).$(PVXS_MINOR_VERSION)

INC += pvxs/version.h
INC += pvxs/versionNum.h
INC += pvxs/log.h

LIBRARY = pvxs

LIB_SRCS += log.cpp
LIB_SRCS += evhelper.cpp
LIB_SRCS += udp_collector.cpp

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
