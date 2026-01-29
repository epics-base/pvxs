# This is a Makefile fragment, see cert/authn/Makefile.

SRC_DIRS += $(AUTHN)/krb

PROD += authnkrb
authnkrb_SRCS += authnkrb.cpp
authnkrb_SRCS += authnkrbmain.cpp
authnkrb_SRCS += configkrb.cpp
authnkrb_SRCS += certstatusfactory.cpp
authnkrb_SRCS += certstatus.cpp

pvacms_SRCS += authnkrb.cpp
pvacms_SRCS += configkrb.cpp

# Detect the operating system
UNAME_S := $(shell uname -s)

# Set platform-specific krb libs
ifeq ($(UNAME_S), Darwin)
    # macOS
	authnkrb_LDFLAGS += -framework GSS
	pvacms_LDFLAGS += -framework GSS
else
    # MIT Kerberos
	authnkrb_SYS_LIBS += gssapi_krb5 krb5 k5crypto com_err
	pvacms_SYS_LIBS += gssapi_krb5 krb5 k5crypto com_err
endif
