TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

PROD_LIBS += pvxs Com

TESTPROD_HOST += simplesrv
simplesrv_SRCS += simplesrv.cpp

TESTPROD_HOST += mailbox
mailbox_SRCS += mailbox.cpp

TESTPROD_HOST += ticker
ticker_SRCS += ticker.cpp

TESTPROD_HOST += simpleget
simpleget_SRCS += simpleget.cpp

TESTPROD_HOST += client
client_SRCS += client.cpp

TESTPROD_HOST += rpc_server
rpc_server_SRCS += rpc_server.cpp

TESTPROD_HOST += rpc_client
rpc_client_SRCS += rpc_client.cpp

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

