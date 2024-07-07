# This is a Makefile fragment, see cert/Makefile.

SRC_DIRS += $(AUTHN)

#--------------------------------------------
#  ADD AUTHENTICATION PLUGINS AFTER THIS LINE

#include $(AUTHN)/std/Makefile
#authnstd_INC += authn.h
#authnstd_SRCS += authmain.cpp

ifeq ($(PVXS_ENABLE_JWT_AUTH),YES)
include $(AUTHN)/jwt/Makefile
authnjwt_INC += authn.h
authnjwt_SRCS += authmain.cpp
endif

ifeq ($(PVXS_ENABLE_KRB_AUTH),YES)
include $(AUTHN)/krb/Makefile
authnkrb_INC += authn.h
authnkrb_SRCS += authmain.cpp
endif

ifeq ($(PVXS_ENABLE_LDAP_AUTH),YES)
include $(AUTHN)/ldap/Makefile
authnldap_INC += authn.h
authnldap_SRCS += authmain.cpp
endif
