TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

# access to private headers
USR_CPPFLAGS += -I$(TOP)/src

PROD_LIBS += pvxs Com

PROD += pvxvct
pvxvct_SRCS += pvxvct.cpp

PROD += pvxinfo
pvxinfo_SRCS += info.cpp

PROD += pvxget
pvxget_SRCS += get.cpp

PROD += pvxput
pvxput_SRCS += put.cpp

PROD_SYS_LIBS += event_core

PROD_SYS_LIBS_DEFAULT += event_pthreads
PROD_SYS_LIBS_WIN32 += netapi32 ws2_32
PROD_SYS_LIBS_vxWorks =

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

