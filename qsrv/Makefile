TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

USR_CPPFLAGS += -I$(TOP)/src

PROD_IOC += softIocPVX

softIocPVX_SRCS += softMain.cpp
softIocPVX_SRCS += softIocPVX_registerRecordDeviceDriver.cpp

softIocPVX_LIBS += pvxsIoc
softIocPVX_LIBS += pvxs
softIocPVX_LIBS += $(EPICS_BASE_IOC_LIBS)

DBD += softIocPVX.dbd

softIocPVX_DBD += softIoc.dbd
softIocPVX_DBD += pvxsIoc.dbd

# Ensure correct build order when generating the expanded DBD.
# pvxsIoc.dbd is produced by ioc/ and installed into $(INSTALL_LOCATION)/dbd.
$(COMMON_DIR)/softIocPVX.dbd: $(INSTALL_LOCATION)/dbd/pvxsIoc.dbd

DB += softIocPVXExit.db

# used with Base < 7.0.5
FINAL_LOCATION ?= $(shell $(PERL) $(TOOLS)/fullPathName.pl $(INSTALL_LOCATION))

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

softMain$(DEP): epicsInstallDir.h

epicsInstallDir.h: $(TOP)/configure/CONFIG_SITE*
	$(ECHO) "FINAL_LOCATION=$(FINAL_LOCATION)"
	$(PERL) ../makeInstallDir.pl "$(FINAL_LOCATION)" > $@
