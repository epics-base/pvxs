# This is a Makefile fragment, see cert/Makefile.

SRC_DIRS += $(AUTHN)

SRCS += auth.cpp
SRCS += configauthn.cpp
SRCS += ccrmanager.cpp

include $(AUTHN)/std/Makefile

SRCS += certstatusmanager.cpp

#--------------------------------------------
#  ADD AUTHENTICATOR PLUGINS AFTER THIS LINE

ifeq ($(PVXS_ENABLE_KRB_AUTH),YES)
include $(AUTHN)/krb/Makefile
endif

ifeq ($(PVXS_ENABLE_LDAP_AUTH),YES)
include $(AUTHN)/ldap/Makefile
endif
