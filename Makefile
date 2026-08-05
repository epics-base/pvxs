# Makefile at top of application tree
TOP = .
include $(TOP)/configure/CONFIG

# Directories to build, any order
DIRS += configure

DIRS += setup
setup_DEPEND_DIRS = configure

DIRS += src
src_DEPEND_DIRS = setup

DIRS += tools
tools_DEPEND_DIRS = src

# site/ must build before ioc/: gen_siteregister.py runs here and
# produces site/siteregister.cpp, which ioc/ picks up via its
# SRC_DIRS wildcard.  Tests live in site/test/, which depends on ioc/.
DIRS += site
site_DEPEND_DIRS = src

DIRS += ioc
ioc_DEPEND_DIRS = src site

ifdef BASE_3_15
DIRS += qsrv
qsrv_DEPEND_DIRS = src ioc
endif

DIRS += test
test_DEPEND_DIRS = src ioc

DIRS += site/test
site/test_DEPEND_DIRS = ioc

DIRS += example
example_DEPEND_DIRS = src

include $(TOP)/configure/RULES_TOP
