TOP=..

include $(TOP)/configure/CONFIG
# cfg/ sometimes isn't correctly included due to a Base bug
# so we do here (maybe again) as workaround
include $(TOP)/configure/CONFIG_PVXS_MODULE
include $(TOP)/configure/CONFIG_PVXS_VERSION
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

PROD_IOC += softIocPVX

softIocPVX_SRCS += softMain.cpp
softIocPVX_SRCS += softIocPVX_registerRecordDeviceDriver.cpp

softIocPVX_LIBS += pvxsIoc
softIocPVX_LIBS += pvxs
softIocPVX_LIBS += $(EPICS_BASE_IOC_LIBS)

DBD += softIocPVX.dbd

softIocPVX_DBD += softIoc.dbd
softIocPVX_DBD += pvxsIoc.dbd

DB += softIocPVXExit.db

# used with Base < 7.0.5
FINAL_LOCATION ?= $(shell $(PERL) $(TOOLS)/fullPathName.pl $(INSTALL_LOCATION))

#===========================

include $(TOP)/configure/RULES
include $(TOP)/configure/RULES_PVXS_MODULE
#----------------------------------------
#  ADD RULES AFTER THIS LINE

softMain$(DEP): epicsInstallDir.h

epicsInstallDir.h: $(TOP)/configure/CONFIG_SITE*
	$(ECHO) "FINAL_LOCATION=$(FINAL_LOCATION)"
	$(PERL) ../makeInstallDir.pl "$(FINAL_LOCATION)" > $@
