TOP=..

include $(TOP)/configure/CONFIG
# cfg/ sometimes isn't correctly included due to a Base bug
# so we do here (maybe again) as workaround
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

# access to private headers and source
USR_CPPFLAGS += -I$(TOP)/src
USR_CPPFLAGS += -I$(TOP)/ioc

ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -I$(TOP)/certs
SRC_DIRS += $(TOP)/certs
SRC_DIRS += $(TOP)/src
endif

PROD_LIBS = pvxs Com

TESTPROD_HOST += testsock
testsock_SRCS += testsock.cpp
TESTS += testsock

TESTPROD_HOST += testutil
testutil_SRCS += testutil.cpp
TESTS += testutil

TESTPROD_HOST += testev
testev_SRCS += testev.cpp
TESTS += testev

TESTPROD_HOST += testlog
testlog_SRCS += testlog.cpp
TESTS += testlog

TESTPROD_HOST += testudp
testudp_SRCS += testudp.cpp
TESTS += testudp

TESTPROD_HOST += testshared
testshared_SRCS += testshared.cpp
TESTS += testshared

TESTPROD_HOST += testbitmask
testbitmask_SRCS += testbitmask.cpp
TESTS += testbitmask

TESTPROD_HOST += testxcode
testxcode_SRCS += testxcode.cpp
TESTS += testxcode

TESTPROD_HOST += testtype
testtype_SRCS += testtype.cpp
TESTS += testtype

TESTPROD_HOST += testdata
testdata_SRCS += testdata.cpp
TESTS += testdata

TESTPROD_HOST += testnt
testnt_SRCS += testnt.cpp
TESTS += testnt

TESTPROD_HOST += testconfig
testconfig_SRCS += testconfig.cpp
TESTS += testconfig

TESTPROD_HOST += testwild
testwild_SRCS += testwild.cpp
TESTS += testwild

TESTPROD_HOST += testpvreq
testpvreq_SRCS += testpvreq.cpp
TESTS += testpvreq

TESTPROD_HOST += testinfo
testinfo_SRCS += testinfo.cpp
TESTS += testinfo

TESTPROD_HOST += testget
testget_SRCS += testget.cpp
TESTS += testget

TESTPROD_HOST += testmon
testmon_SRCS += testmon.cpp
TESTS += testmon

TESTPROD_HOST += testmonpipe
testmonpipe_SRCS += testmonpipe.cpp
TESTS += testmonpipe

TESTPROD_HOST += testput
testput_SRCS += testput.cpp
TESTS += testput

TESTPROD_HOST += testrpc
testrpc_SRCS += testrpc.cpp
TESTS += testrpc

TESTPROD_HOST += testdiscover
testdiscover_SRCS += testdiscover.cpp
# very slow and dependent on host network config.
#TESTS += testdiscover

TESTPROD_HOST += testnamesrv
testnamesrv_SRCS += testnamesrv.cpp
TESTS += testnamesrv

TESTPROD_HOST += test1000
test1000_SRCS += test1000.cpp
TESTS += test1000

TESTPROD_HOST += testendian
testendian_SRCS += testendian.cpp
TESTS += testendian

TESTPROD_HOST += testudpfwd
testudpfwd_SRCS += testudpfwd.cpp
TESTS += testudpfwd

ifdef BASE_3_15
ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL
TESTPROD_HOST += gen_test_certs
gen_test_certs_SRCS += gen_test_certs.cpp
gen_test_certs_SRCS += certfactory.cpp

TESTPROD_HOST += testtls
testtls_SRCS += testtls.cpp
testtls_SRCS += certstatusfactory.cpp
testtls_SRCS += certstatusmanager.cpp
testtls_SRCS += certstatus.cpp
TESTS += testtls
TESTFILES += cert_auth.p12 cert_authcert.p12 client1.p12 client2.p12 intermediateCA.p12 ioc1.p12 server1.p12 server2.p12 superserver1.p12

TESTPROD_HOST += testtlswithcms
testtlswithcms_SRCS += testtlswithcms.cpp
testtlswithcms_SRCS += certstatusfactory.cpp
testtlswithcms_SRCS += certstatusmanager.cpp
testtlswithcms_SRCS += certstatus.cpp
TESTS += testtlswithcms
TESTFILES += cert_auth.p12 cert_authcert.p12 client1.p12 client2.p12 intermediateCA.p12 ioc1.p12 server1.p12 server2.p12 superserver1.p12

TESTPROD_HOST += testtlswithcmsandstapling
testtlswithcmsandstapling_SRCS += testtlswithcmsandstapling.cpp
testtlswithcmsandstapling_SRCS += certstatusfactory.cpp
testtlswithcmsandstapling_SRCS += certstatusmanager.cpp
testtlswithcmsandstapling_SRCS += certstatus.cpp
TESTS += testtlswithcmsandstapling
TESTFILES += cert_auth.p12 cert_authcert.p12 client1.p12 client2.p12 intermediateCA.p12 ioc1.p12 server1.p12 server2.p12 superserver1.p12

TESTPROD_HOST += testtlstime
testtlstime_SRCS += testtlstime.cpp
TESTS += testtlstime

TESTPROD_HOST += testtlsstatus
testtlsstatus_SRCS += testtlsstatus.cpp
testtlsstatus_SRCS += certstatusfactory.cpp
testtlsstatus_SRCS += certstatusmanager.cpp
testtlsstatus_SRCS += certstatus.cpp
TESTS += testtlsstatus

endif # EVENT2_HAS_OPENSSL
endif

ifdef BASE_7_0

TESTPROD_HOST += benchdata
benchdata_SRCS += benchdata.cpp

TESTPROD_HOST += testpvalink
testpvalink_SRCS += testpvalink.cpp
testpvalink_SRCS += testioc_registerRecordDeviceDriver.cpp
testpvalink_LIBS += pvxsIoc pvxs $(EPICS_BASE_IOC_LIBS)
TESTS += testpvalink
TESTFILES += ../testpvalink.db

endif

ifdef BASE_3_15

DBDDEPENDS_FILES += testioc.dbd$(DEP)
testioc_DBD = base.dbd pvxsIoc.dbd
TESTFILES += $(COMMON_DIR)/testioc.dbd

TESTPROD_HOST += testqsingle
testqsingle_SRCS += testqsingle
testqsingle_SRCS += testioc_registerRecordDeviceDriver.cpp
testqsingle_LIBS = pvxsIoc pvxs $(EPICS_BASE_IOC_LIBS)
TESTFILES += ../testqsingle.db
TESTFILES += ../testqsingle64.db
TESTFILES += ../testqsinglelsi.db
TESTFILES += ../testioc.acf
TESTS += testqsingle

endif

ifdef BASE_7_0

TESTPROD_HOST += testqgroup
testqgroup_SRCS += testqgroup
testqgroup_SRCS += testioc_registerRecordDeviceDriver.cpp
testqgroup_LIBS = pvxsIoc pvxs $(EPICS_BASE_IOC_LIBS)
TESTFILES += ../table.db
TESTFILES += ../image.db
TESTFILES += ../image.json
TESTFILES += ../iq.db
TESTFILES += ../ntenum.db
TESTFILES += ../const.db
TESTS += testqgroup

PROD_SRCS_RTEMS += rtemsTestData.c

endif

TESTPROD_HOST += mcat
mcat_SRCS += mcat.cpp
# not a unittest

TESTPROD_HOST += spam
spam_SRCS += spam.cpp
# not a unittest

TESTPROD_HOST += eatspam
eatspam_SRCS += eatspam.cpp
# not a unittest

TESTSCRIPTS_HOST += $(TESTS:%=%.t)
ifdef BASE_3_15
ifneq ($(filter $(T_A),$(CROSS_COMPILER_RUNTEST_ARCHS)),)
TESTPROD = $(TESTPROD_HOST)
TESTSCRIPTS = $(TESTSCRIPTS_HOST)
endif
endif

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE

ifdef BASE_3_15
rtemsTestData.c : $(TESTFILES) $(TOOLS)/epicsMakeMemFs.pl
	$(PERL) $(TOOLS)/epicsMakeMemFs.pl $@ epicsRtemsFSImage $(TESTFILES)

ifeq ($(EVENT2_HAS_OPENSSL),YES)
testtls$(EXE): | cert_auth.p12

# generate test certs only with EPICS_HOST_ARCH
ifdef T_A
cert_auth.p12 :
	$(RM) *.p12
	../O.$(EPICS_HOST_ARCH)/gen_test_certs$(HOSTEXE) -O .
ifeq ($(T_A),$(EPICS_HOST_ARCH))
cert_auth.p12 : gen_test_certs$(HOSTEXE)
endif # T_A==EPICS_HOST_ARCH
endif # T_A
endif # EVENT2_HAS_OPENSSL

endif
