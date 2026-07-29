TOP=..

include $(TOP)/configure/CONFIG
# cfg/ sometimes isn't correctly included due to a Base bug
# so we do here (maybe again) as workaround
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

ifdef BASE_3_15

# access to private headers
USR_CPPFLAGS += -I$(TOP)/src

ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL
endif # EVENT2_HAS_OPENSSL
USR_CPPFLAGS += -DPVXS_ENABLE_EXPERT_API

PROD_LIBS += pvxs Com

PROD_SRCS += cliutil.cpp

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

# tests of CLI tools

TESTPROD_HOST += testcliutil
testcliutil_SRCS += testcliutil.cpp
TESTS += testcliutil

TESTPROD_HOST += testxput
testxput_SRCS += testxput.cpp
TESTS += testxput

TESTSCRIPTS_HOST += $(TESTS:%=%.t)

endif # BASE_3_15

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
