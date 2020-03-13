TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

PROD_LIBS += pvxs Com

TESTPROD += mailbox
mailbox_SRCS += mailbox.cpp

TESTPROD += spam
spam_SRCS += spam.cpp

TESTPROD += ticker
ticker_SRCS += ticker.cpp

TESTPROD += client
client_SRCS += client.cpp

PROD_SYS_LIBS += event_core

PROD_SYS_LIBS_DEFAULT += event_pthreads
PROD_SYS_LIBS_WIN32 += netapi32 ws2_32
PROD_SYS_LIBS_vxWorks =

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

