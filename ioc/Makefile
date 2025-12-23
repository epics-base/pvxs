#
# Copyright - See the COPYRIGHT that is included with this distribution.
# pvxs is distributed subject to a Software License Agreement found
# in file LICENSE that is included with this distribution.
#
# Author George S. McIntyre <george@level-n.com>, 2023
#

TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

# access to private headers
USR_CPPFLAGS += -I$(TOP)/src
USR_CPPFLAGS += -DPVXS_IOC_API_BUILDING

DBD += pvxsIoc.dbd

INC += pvxs/iochooks.h

LIBRARY += pvxsIoc

SHRLIB_VERSION = $(PVXS_MAJOR_VERSION).$(PVXS_MINOR_VERSION)

pvxsIoc_SRCS += iochooks.cpp

ifdef BASE_3_15

pvxsIoc_SRCS += credentials.cpp
pvxsIoc_SRCS += channel.cpp
pvxsIoc_SRCS += demo.cpp
pvxsIoc_SRCS += dberrormessage.cpp
pvxsIoc_SRCS += imagedemo.c
pvxsIoc_SRCS += iocsource.cpp
pvxsIoc_SRCS += localfieldlog.cpp
pvxsIoc_SRCS += securityclient.cpp
pvxsIoc_SRCS += singlesource.cpp
pvxsIoc_SRCS += singlesourcehooks.cpp
pvxsIoc_SRCS += singlesrcsubscriptionctx.cpp
pvxsIoc_SRCS += typeutils.cpp

ifdef BASE_7_0

pvxsIoc_SRCS += field.cpp
pvxsIoc_SRCS += fielddefinition.cpp
pvxsIoc_SRCS += fieldname.cpp
pvxsIoc_SRCS += fieldsubscriptionctx.cpp
pvxsIoc_SRCS += group.cpp
pvxsIoc_SRCS += groupconfigprocessor.cpp
pvxsIoc_SRCS += groupprocessorcontext.cpp
pvxsIoc_SRCS += groupsource.cpp
pvxsIoc_SRCS += groupsourcehooks.cpp
pvxsIoc_SRCS += pvalink.cpp
pvxsIoc_SRCS += pvalink_channel.cpp
pvxsIoc_SRCS += pvalink_jlif.cpp
pvxsIoc_SRCS += pvalink_link.cpp
pvxsIoc_SRCS += pvalink_lset.cpp

else

pvxsIoc_SRCS += dummygroup.cpp

endif # BASE_7_0

pvxsIoc_LIBS += $(EPICS_BASE_IOC_LIBS)

else # BASE_3_15

pvxsIoc_SRCS += dummysingle.cpp
pvxsIoc_SRCS += dummygroup.cpp

pvxsIoc_LIBS += Com

endif # BASE_3_15

LIB_LIBS += pvxs
LIB_LIBS += $(EPICS_BASE_IOC_LIBS)

# Tell Make where to find the DBD source files (works from any build context)
vpath pvxs7x.dbd $(CURDIR) $(TOP)/ioc
vpath pvxs3x.dbd $(CURDIR) $(TOP)/ioc

# Ensure pvxsIoc.dbd source file exists before DBD expansion in RULES
# This must be defined before RULES is included so it's available when expansion runs
# Create the file at Makefile parse time to ensure it exists before any processing
$(shell \
	if [ -f $(TOP)/ioc/pvxs7x.dbd ] && [ ! -f $(TOP)/ioc/pvxsIoc.dbd ]; then \
		cp $(TOP)/ioc/pvxs7x.dbd $(TOP)/ioc/pvxsIoc.dbd; \
	elif [ -f $(TOP)/ioc/pvxs3x.dbd ] && [ ! -f $(TOP)/ioc/pvxsIoc.dbd ]; then \
		cp $(TOP)/ioc/pvxs3x.dbd $(TOP)/ioc/pvxsIoc.dbd; \
	fi \
)

# Also provide the rule for explicit builds and to keep file up to date
ifdef BASE_7_0
pvxsIoc.dbd: pvxs7x.dbd
	$(CP) $< $@
else
pvxsIoc.dbd: pvxs3x.dbd
	$(CP) $< $@
endif

# Ensure the source file exists before DBD expansion
# Make library build depend on DBD file existing (ensures it's created early)
pvxsIoc$(LIB): pvxsIoc.dbd

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

# Make DBD expansion depend on source file existing
# This ensures pvxsIoc.dbd is created before dbdExpand.pl runs
# The file must exist before EPICS tries to expand it
../O.Common/pvxsIoc.dbd$(DEP): pvxsIoc.dbd
$(COMMON_DIR)/pvxsIoc.dbd$(DEP): pvxsIoc.dbd

# Clean up generated DBD file (pvxsIoc.dbd is generated from pvxs7x.dbd or pvxs3x.dbd)
# Hook into EPICS clean process by making archsCommonClean depend on our cleanup
archsCommonClean: clean-pvxsIoc-dbd

clean-pvxsIoc-dbd:
	$(RM) pvxsIoc.dbd
