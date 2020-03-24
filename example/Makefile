TOP=..

include $(TOP)/configure/CONFIG
# cfg/ sometimes isn't correctly included due to a Base bug
# so we do here (maybe again) as workaround
include $(TOP)/configure/CONFIG_PVXS_MODULE
include $(TOP)/configure/CONFIG_PVXS_VERSION
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

PROD_LIBS += pvxs Com

TESTPROD_HOST += mailbox
mailbox_SRCS += mailbox.cpp

TESTPROD_HOST += spam
spam_SRCS += spam.cpp

TESTPROD_HOST += ticker
ticker_SRCS += ticker.cpp

TESTPROD_HOST += client
client_SRCS += client.cpp

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

