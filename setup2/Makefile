TOP=..

# step 2 in setup/Makefile
# step 3. install cfg/*
# remaining TOP directories will include generated files
_PVXS_BOOTSTRAP = YES

include $(TOP)/configure/CONFIG

CFG += CONFIG_PVXS_MODULE
CFG += RULES_PVXS_MODULE

include $(TOP)/configure/RULES

# enforce installation order to reverse of order requirements within
# these Makefile fragments.
# TOOLCHAIN -> CONFIG_PVXS_MODULE -> RULES_PVXS_MODULE
$(INSTALL_CFG)/RULES_PVXS_MODULE: $(INSTALL_CFG)/CONFIG_PVXS_MODULE
