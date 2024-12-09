# This is a Makefile fragment, see cert/Makefile.

SRC_DIRS += $(AUTHN)

#--------------------------------------------
#  ADD AUTHENTICATION PLUGINS AFTER THIS LINE

SRCS += auth.cpp
SRCS += ccrmanager.cpp

include $(AUTHN)/std/Makefile

ifeq ($(PVXS_ENABLE_JWT_AUTH),YES)
include $(AUTHN)/jwt/Makefile
endif

ifeq ($(PVXS_ENABLE_KRB_AUTH),YES)
include $(AUTHN)/krb/Makefile
endif

ifeq ($(PVXS_ENABLE_LDAP_AUTH),YES)
include $(AUTHN)/ldap/Makefile
endif
