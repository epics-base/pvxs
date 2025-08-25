TOP=..

include $(TOP)/configure/CONFIG
# cfg/ sometimes isn't correctly included due to a Base bug
# so we do here (maybe again) as workaround
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

# access to private headers
USR_CPPFLAGS += -I$(TOP)/src

ifeq ($(EVENT2_HAS_OPENSSL),YES)
SRC_DIRS += $(TOP)/certs
SRC_DIRS += $(TOP)/src
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL
USR_CPPFLAGS += -I$(TOP)/certs -I$(TOP)/bundle/CLI11/include
SRCS += certstatus.cpp

PROD += pvxcert
pvxcert_SRCS += cert.cpp
pvxcert_SRCS += p12filefactory.cpp
pvxcert_SRCS += certfilefactory.cpp
pvxcert_SRCS += certfactory.cpp
pvxcert_SRCS += certstatusmanager.cpp
pvxcert_SRCS += opensslgbl.cpp

endif # EVENT2_HAS_OPENSSL

PROD_LIBS += pvxs Com

PROD += pvxvct
pvxvct_SRCS += pvxvct.cpp

PROD += pvxinfo
pvxinfo_SRCS += info.cpp

PROD += pvxget
pvxget_SRCS += get.cpp

PROD += pvxmonitor
pvxmonitor_SRCS += monitor.cpp

PROD += pvxput
pvxput_SRCS += put.cpp

PROD += pvxcall
pvxcall_SRCS += call.cpp

PROD += pvxlist
pvxlist_SRCS += list.cpp

PROD += pvxmshim
pvxmshim_SRCS += mshim.cpp

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE

