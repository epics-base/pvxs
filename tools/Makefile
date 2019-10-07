TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

# access to private headers
USR_CPPFLAGS += -I$(TOP)/src

USR_CXXFLAGS += -std=c++11

PROD_LIBS += pvxs Com

PROD += pvxvct
pvxvct_SRCS += pvxvct.cpp

PROD_SYS_LIBS += event_core

PROD_SYS_LIBS_DEFAULT += event_pthreads
PROD_SYS_LIBS_WIN32 += netapi32 ws2_32
PROD_SYS_LIBS_vxWorks =

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

