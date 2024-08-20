TOP=..

include $(TOP)/configure/CONFIG
# cfg/ sometimes isn't correctly included due to a Base bug
# so we do here (maybe again) as workaround
-include $(wildcard $(TOP)/cfg/CONFIG*)
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

ifeq ($(EVENT2_HAS_OPENSSL),YES)
USR_CPPFLAGS += -DPVXS_ENABLE_OPENSSL
AUTHN = $(TOP)/certs/authn

PROD_LIBS = pvxs Com

# access to API and private headers
USR_CPPFLAGS += -I$(TOP)/src/pvxs
USR_CPPFLAGS += -I$(TOP)/src

INC += security.h

PROD += pvacms
pvacms_SRCS += pvacms.cpp
pvacms_SRCS += configcms.cpp
pvacms_SRCS += certfactory.cpp
pvacms_SRCS += p12filefactory.cpp
pvacms_SRCS += certstatus.cpp
pvacms_LIBS += $(EPICS_BASE_IOC_LIBS)
pvacms_LDFLAGS += -lsqlite3 -lssl -lcrypto

#PROD += ocsppva
#pvaocsp_SRCS += ocsppva.cpp
#pvaocsp_SRCS += configocsp.cpp

#include $(AUTHN)/Makefile

endif # EVENT2_HAS_OPENSSL

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
