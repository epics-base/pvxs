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

# access to private headers
USR_CPPFLAGS += -I$(TOP)/src

# Access to API for targets that link with pvxs lib
USR_CPPFLAGS += -I$(TOP)/src/pvxs

INC += certconfig.h
INC += security.h

#LIB_LIBS += Com

#PROD += pvacms
#pvacms_SRCS += pvacms.cpp
#pvacms_SRCS += configcms.cpp
#pvacms_SRCS += certfactory.cpp
#pvacms_SRCS += keychainfactory.cpp
#pvacms_LDFLAGS += -lsqlite3 -lssl -lcrypto -lpvxs

#PROD += ocsppva
#pvaocsp_SRCS += ocsppva.cpp
#pvaocsp_SRCS += configocsp.cpp

include $(AUTHN)/Makefile

endif # EVENT2_HAS_OPENSSL

#===========================

include $(TOP)/configure/RULES
-include $(wildcard $(TOP)/cfg/RULES*)
#----------------------------------------
#  ADD RULES AFTER THIS LINE
