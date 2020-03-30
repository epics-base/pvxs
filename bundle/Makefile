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
CMAKEFLAGS += -DEVENT__DISABLE_BENCHMARK=ON

CMAKEFLAGS += -DCMAKE_MODULE_PATH:DIR=$(abspath $(TOP)/bundle/cmake)

# check either $(HOST_OPT) or $(CROSS_OPT) depending on $(BUILD_CLASS)
IS_OPT = $($(BUILD_CLASS)_OPT)
# cmake build types: DEBUG RELEASE RELWITHDEBINFO MINSIZEREL
CMAKEFLAGS_DEBUG_YES += -DCMAKE_BUILD_TYPE=RELEASE
CMAKEFLAGS_DEBUG_NO += -DCMAKE_BUILD_TYPE=DEBUG
CMAKEFLAGS += $(CMAKEFLAGS_DEBUG_$(IS_OPT))

CMAKEFLAGS_WIN32_STATIC_NO += -DEVENT__LIBRARY_TYPE=SHARED
CMAKEFLAGS_WIN32_STATIC_YES += -DEVENT__LIBRARY_TYPE=STATIC
CMAKEFLAGS += $(CMAKEFLAGS_$(OS_CLASS)_STATIC_$(STATIC_BUILD))

ifneq (,$(filter linux-%,$(EPICS_HOST_ARCH)))
# cross mingw hosted on linux
CMAKE_TOOLCHAIN_windows-x64-mingw ?= x86_64-w64-mingw32
endif

ifneq (,$(filter win%,$(EPICS_HOST_ARCH)))
# hosted mingw on windows
CMAKEFLAGS_gcc += -G "MinGW Makefiles" -DCMAKE_C_COMPILER="$(CC)"

# Use NMake for native windows since we must already have a MSVC version in %PATH%
CMAKEFLAGS_msvc += -G "NMake Makefiles" -DCMAKE_C_COMPILER="$(CC)"
endif

# toolchain file when cross compiling
CMAKE_TOOLCHAIN ?= $(CMAKE_TOOLCHAIN_$(T_A))
CMAKEFLAGS += $(if $(CMAKE_TOOLCHAIN),-DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN))

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

ifneq (,$(wildcard $(CURDIR)/../libevent/CMakeLists.txt))
# libevent >= 2.1 prefer CMake

libevent.%:
	$(CMAKE) $(CMAKEFLAGS) ../libevent
	$(CMAKE) -E env --unset=MAKEFLAGS --unset=CC $(CMAKE) --build . $(CBUILDFLAGS) --target install

else
# libevent 2.0 only autotools
# only host CC supported

libevent.%: ../libevent/configuration
	[ -f Makefile ] || ../libevent/configure --prefix=$(abspath $(INSTALL_LOCATION)/bundle/usr-$*) --disable-openssl
	$(MAKE) install

../libevent/configuration: ../libevent/configure.ac
	(cd ../libevent && autoreconf -ivf)

endif

endif # T_A

.PHONY: libevent libevent.%

# These rules support printing a Makefile variable values.
# Many variables are only set inside an O.<arch> build directory.
#   make PRINT.T_A

PRINT_Var = $(@:PRINT.%=%)
PRINT.%:
	@echo $(PRINT_Var) = '$($(PRINT_Var))'

.PHONY: PRINT PRINT.%
