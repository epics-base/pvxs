# This is a Makefile fragment, see src/Makefile.

SRC_DIRS += $(TOP)/src/security

INC += auth.h
INC += authregistry.h
INC += authdefault.h
INC += certfactory.h
INC += certmgmtservice.h
INC += keychainfactory.h
INC += openssl.h
INC += security.h

LIB_SRCS += auth.cpp
LIB_SRCS += authregistry.cpp
LIB_SRCS += certmgmtservice.cpp
LIB_SRCS += certfactory.cpp
LIB_SRCS += openssl.cpp
LIB_SRCS += keychainfactory.cpp

include $(SECURITY)/authdefault/Makefile

#----------------------------------------
#  ADD AUTH PLUGINS AFTER THIS LINE

ifeq ($(PVXS_ENABLE_JWT_AUTH),YES)
include $(SECURITY)/authjwt/Makefile
endif

ifeq ($(PVXS_ENABLE_KRB_AUTH),YES)
include $(SECURITY)/authkrb/Makefile
endif

ifeq ($(PVXS_ENABLE_LDAP_AUTH),YES)
include $(SECURITY)/authldap/Makefile
endif
