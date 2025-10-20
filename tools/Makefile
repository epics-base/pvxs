TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

# access to private headers
USR_CPPFLAGS += -I$(TOP)/src

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

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

