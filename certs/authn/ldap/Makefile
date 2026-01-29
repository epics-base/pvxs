# This is a Makefile fragment, see cert/authn/Makefile.

SRC_DIRS += $(AUTHN)/ldap

PROD += authnldap
authnldap_SRCS += authnldap.cpp
authnldap_SRCS += authnldapmain.cpp
authnldap_SRCS += configldap.cpp
authnldap_SRCS += certstatusfactory.cpp
authnldap_SRCS += certstatus.cpp

pvacms_SRCS += authnldap.cpp
pvacms_SRCS += configldap.cpp

authnldap_SYS_LIBS += ldap lber
pvacms_SYS_LIBS += ldap lber
