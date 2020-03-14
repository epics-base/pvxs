TOP=..

include $(TOP)/configure/CONFIG

CMAKE ?= cmake

CMAKEFLAGS = $(CMD_CMAKEFLAGS)

CMAKEFLAGS += -DCMAKE_INSTALL_PREFIX:PATH=$(abspath $(INSTALL_LOCATION)/bundle/usr-$*)

# not needed, and may not be available on embedded targets, so never try
CMAKEFLAGS += -DEVENT__DISABLE_OPENSSL=ON

# no run, so why bother?
CMAKEFLAGS += -DEVENT__DISABLE_REGRESS=ON
CMAKEFLAGS += -DEVENT__DISABLE_SAMPLES=ON
CMAKEFLAGS += -DEVENT__DISABLE_TESTS=ON

CMAKEFLAGS += -DCMAKE_MODULE_PATH:DIR=$(abspath $(TOP)/bundle/cmake)

# check either $(HOST_OPT) or $(CROSS_OPT) depending on $(BUILD_CLASS)
IS_OPT = $($(BUILD_CLASS)_OPT)
# cmake build types: DEBUG RELEASE RELWITHDEBINFO MINSIZEREL
CMAKEFLAGS_DEBUG_YES += -DCMAKE_BUILD_TYPE=RELEASE
CMAKEFLAGS_DEBUG_NO += -DCMAKE_BUILD_TYPE=DEBUG
CMAKEFLAGS += $(CMAKEFLAGS_DEBUG_$(IS_OPT))

ifneq (,$(filter linux-%,$(EPICS_HOST_ARCH)))
_TOOLCHAIN_windows-x64-mingw ?= x86_64-w64-mingw32
endif

# toolchain file when cross compiling
CMAKE_TOOLCHAIN ?= $(_TOOLCHAIN_$(T_A))
CMAKEFLAGS_CROSS_YES = -DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN)
CMAKEFLAGS += $(CMAKEFLAGS_CROSS_$(CROSS))

# Use NMake for native windows since we must already have a MSVC version in %PATH%
CMAKEFLAGS_msvc += -G "NMake Makefiles"
CMAKEFLAGS += $(CMAKEFLAGS_$(CMPLR_CLASS))

# flags for cmake --build
# eg. "-j 2"  (that space is important)
CBUILDFLAGS +=

all: help

help:
	$(ECHO) "Building of bundled libevent is not automatic!"
	$(ECHO) " Requires $(CMAKE)"
	$(ECHO) " Possible targets: $(CROSS_COMPILER_TARGET_ARCHS)"
	$(ECHO) ""
	$(ECHO) "Usage:"
	$(ECHO) " # alias for libevent.$(EPICS_HOST_ARCH)"
	$(ECHO) " make -C bundle libevent"
	$(ECHO) " # build for one target"
	$(ECHO) " make -C bundle libevent.<epics-arch>"
	$(ECHO) " # remove all target"
	$(ECHO) " make -C bundle clean  # remove all for targets"
	$(ECHO) " # remove one target"
	$(ECHO) " make -C bundle clean.<epics-arch> # remove for one target"

libevent: libevent.$(EPICS_HOST_ARCH)

clean:
	$(RMDIR) $(CURDIR)/O.* $(CURDIR)/usr-*

clean.%:
	$(RMDIR) $(CURDIR)/O.$* $(CURDIR)/usr-$*

ifndef T_A

# re-entry this Makefile with target configuration
libevent.%:
	$(MKDIR) $(CURDIR)/O.$*
	$(MAKE) -C $(CURDIR)/O.$* -f $(CURDIR)/Makefile TOP=$(TOP)/.. T_A=$* libevent.$*

else # T_A

libevent.%:
	$(CMAKE) $(CMAKEFLAGS) ../libevent
	$(CMAKE) --build . $(CBUILDFLAGS) --target install

endif # T_A

.PHONY: libevent libevent.%
