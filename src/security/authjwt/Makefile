# This is a Makefile fragment, see src/security/Makefile.

SRC_DIRS += $(TOP)/src/security/authjwt

INC += authjwt.h

LIB_SRCS += authjwt.cpp

JWT_PREFIX = $(TOP)/bundle/jwt-cpp
INCLUDES += $(if $(JWT_PREFIX),-I$(JWT_PREFIX)/include)

JWT_SYS_LIBS = jsoncpp
INCLUDES += $(shell pkg-config --cflags $(JWT_SYS_LIBS))
LDFLAGS += $(shell pkg-config --libs $(JWT_SYS_LIBS))
LIB_SYS_LIBS += curl
