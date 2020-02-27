TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

# access to private headers
USR_CPPFLAGS += -I$(TOP)/src

PROD_LIBS += pvxs Com

TESTPROD += testsock
testsock_SRCS += testsock.cpp
TESTS += testsock

TESTPROD += testev
testev_SRCS += testev.cpp
TESTS += testev

TESTPROD += testudp
testudp_SRCS += testudp.cpp
TESTS += testudp

TESTPROD += testshared
testshared_SRCS += testshared.cpp
TESTS += testshared

TESTPROD += testbitmask
testbitmask_SRCS += testbitmask.cpp
TESTS += testbitmask

TESTPROD += testxcode
testxcode_SRCS += testxcode.cpp
TESTS += testxcode

TESTPROD += testtype
testtype_SRCS += testtype.cpp
TESTS += testtype

TESTPROD += testdata
testdata_SRCS += testdata.cpp
TESTS += testdata

TESTPROD += testconfig
testconfig_SRCS += testconfig.cpp
TESTS += testconfig

TESTPROD += testpvreq
testpvreq_SRCS += testpvreq.cpp
TESTS += testpvreq

TESTPROD += testinfo
testinfo_SRCS += testinfo.cpp
TESTS += testinfo

TESTPROD += testget
testget_SRCS += testget.cpp
TESTS += testget

TESTPROD += testmon
testmon_SRCS += testmon.cpp
TESTS += testmon

TESTPROD += testput
testput_SRCS += testput.cpp
TESTS += testput

TESTPROD += testrpc
testrpc_SRCS += testrpc.cpp
TESTS += testrpc

TESTPROD += mcat
mcat_SRCS += mcat.cpp
# not a unittest

PROD_SYS_LIBS += event_core

PROD_SYS_LIBS_DEFAULT += event_pthreads
PROD_SYS_LIBS_WIN32 += netapi32 ws2_32
PROD_SYS_LIBS_vxWorks =

TESTSCRIPTS_HOST += $(TESTS:%=%.t)
ifneq ($(filter $(T_A),$(CROSS_COMPILER_RUNTEST_ARCHS)),)
TESTPROD = $(TESTPROD_HOST)
TESTSCRIPTS += $(TESTS:%=%.t)
endif

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

