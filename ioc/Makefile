TOP=..

include $(TOP)/configure/CONFIG
# cfg/ sometimes isn't correctly included due to a Base bug
# so we do here (maybe again) as workaround
include $(TOP)/configure/CONFIG_PVXS_MODULE
include $(TOP)/configure/CONFIG_PVXS_VERSION
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

LIB_LIBS += pvxs
LIB_LIBS += $(EPICS_BASE_IOC_LIBS)

#===========================

include $(TOP)/configure/RULES
include $(TOP)/configure/RULES_PVXS_MODULE
#----------------------------------------
#  ADD RULES AFTER THIS LINE

