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

# Clean up generated DBD file (pvxsIoc.dbd is generated from pvxs7x.dbd or pvxs3x.dbd)
CLEANS += pvxsIoc.dbd

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

# Rules to generate pvxsIoc.dbd from pvxs7x.dbd or pvxs3x.dbd before DBD expansion
# Following the exact pattern suggested for softIoc.dbd (as per PR review):
# - .dbd$(DEP) rule creates dependency file (in O.<arch>)
# - $(COMMON_DIR)/pvxsIoc.dbd rule creates source file that EPICS will expand
ifdef BASE_7_0
pvxsIoc.dbd$(DEP): ../pvxs7x.dbd
$(COMMON_DIR)/pvxsIoc.dbd: ../pvxs7x.dbd
	$(CP) $< $@
# Also create in source directory for builds from ioc directory
pvxsIoc.dbd: pvxs7x.dbd
	$(CP) $< $@
else
pvxsIoc.dbd$(DEP): ../pvxs3x.dbd
$(COMMON_DIR)/pvxsIoc.dbd: ../pvxs3x.dbd
	$(CP) $< $@
# Also create in source directory for builds from ioc directory
pvxsIoc.dbd: pvxs3x.dbd
	$(CP) $< $@
endif
