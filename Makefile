# Makefile at top of application tree
TOP = .
include $(TOP)/configure/CONFIG

# Directories to build, any order
DIRS += configure

DIRS += src
src_DEPEND_DIRS = configure

DIRS += tools
tools_DEPEND_DIRS = src

DIRS += ioc
ioc_DEPEND_DIRS = src

DIRS += test
test_DEPEND_DIRS = src ioc

DIRS += example
example_DEPEND_DIRS = src

include $(TOP)/configure/RULES_TOP
