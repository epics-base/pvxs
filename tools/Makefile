TOP=..

include $(TOP)/configure/CONFIG
#----------------------------------------
#  ADD MACRO DEFINITIONS AFTER THIS LINE
#=============================

ifdef BASE_3_15

# access to private headers
USR_CPPFLAGS += -I$(TOP)/src

PROD_LIBS += pvxs Com

PROD += pvxvct
pvxvct_SRCS += pvxvct.cpp

PROD += pvxinfo
pvxinfo_SRCS += info.cpp

PROD += pvxget
pvxget_SRCS += get.cpp

PROD += pvxmonitor
pvxmonitor_SRCS += monitor.cpp

PROD += pvxput
pvxput_SRCS += put.cpp

PROD += pvxcall
pvxcall_SRCS += call.cpp

PROD += pvxlist
pvxlist_SRCS += list.cpp

PROD += pvxmshim
pvxmshim_SRCS += mshim.cpp

endif # BASE_3_15

#===========================

include $(TOP)/configure/RULES
#----------------------------------------
#  ADD RULES AFTER THIS LINE

