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

TESTPROD += dummyserv
dummyserv_SRCS += dummyserv.cpp
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

