TOP=..

include $(TOP)/configure/CONFIG

TARGETS = $(CONFIG_TARGETS)
CONFIGS += $(subst ../,,$(wildcard $(CONFIG_INSTALLS)))

CFG += CONFIG_PVXS_VERSION
CFG += CONFIG_PVXS_MODULE
CFG += RULES_PVXS_MODULE

include $(TOP)/configure/RULES

ifdef T_A
install: $(TOP)/configure/CONFIG_TOOLCHAIN.Common.$(T_A)

$(TOP)/configure/CONFIG_TOOLCHAIN.Common.$(T_A): toolchain.c
	$(PREPROCESS.cpp)

CLEANS += ../CONFIG_TOOLCHAIN.Common.$(T_A)

install: $(TOP)/configure/CONFIG_SDT.Common.$(T_A)

$(TOP)/configure/CONFIG_SDT.Common.$(T_A): maybe_sdt.h ../Makefile
	$(CPP) $(CPPFLAGS) $(INCLUDES) $< > maybe_sdt.c && echo "USR_CPPFLAGS+=-DUSE_SDT" > $@ || echo "# No SDT" > $@

CLEANS += ../CONFIG_SDT.Common.$(T_A):


endif
