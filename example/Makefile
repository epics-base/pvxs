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

TESTPROD_HOST += rpc_server
rpc_server_SRCS += rpc_server.cpp

TESTPROD_HOST += rpc_client
rpc_client_SRCS += rpc_client.cpp

#===========================

include $(TOP)/configure/RULES
include $(TOP)/configure/RULES_PVXS_MODULE
#----------------------------------------
#  ADD RULES AFTER THIS LINE

