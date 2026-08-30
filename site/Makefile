TOP=..
include $(TOP)/configure/CONFIG

include $(TOP)/configure/RULES_DIRS

# All registrar sources: every .cpp in site/ except the generated file itself.
SITE_REGISTRAR_SRCS := $(filter-out \
    $(TOP)/site/siteregister.cpp, \
    $(sort $(wildcard $(TOP)/site/*.cpp)))

# ioc/ picks up siteregister.cpp via its SRC_DIRS wildcard; it must
# exist before the ioc build starts (enforced by ioc_DEPEND_DIRS = site
# in the top-level Makefile).
all install: $(TOP)/site/siteregister.cpp

$(TOP)/site/siteregister.cpp: $(SITE_REGISTRAR_SRCS) $(TOP)/site/gen_siteregister.py
	python3 $(TOP)/site/gen_siteregister.py \
	    $(SITE_REGISTRAR_SRCS) > $@.tmp && mv $@.tmp $@

.PHONY: clean_generated
clean realclean: clean_generated
clean_generated:
	$(RM) $(TOP)/site/siteregister.cpp
