# to understand Platform/ read
# https://github.com/Kitware/CMake/blob/f86d8009c6a4482c81221114a2b04b375564cc94/Source/cmGlobalGenerator.cxx#L461-L504

set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS FALSE)

set(CMAKE_EXECUTABLE_SUFFIX ".elf")

set(CMAKE_FIND_ROOT_PATH
  "${RTEMS_TARGET_PREFIX}/${RTEMS_BSP}"
  "${RTEMS_TARGET_PREFIX}"
)

set(CMAKE_SYSTEM_PREFIX_PATH ${CMAKE_FIND_ROOT_PATH})

set(CMAKE_SYSTEM_INCLUDE_PATH
  "${RTEMS_TARGET_PREFIX}/${RTEMS_BSP}/lib/include"
  "${RTEMS_TARGET_PREFIX}/include"
)
set(CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES ${CMAKE_SYSTEM_INCLUDE_PATH})
set(CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES ${CMAKE_SYSTEM_INCLUDE_PATH})

set(CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES
  "${RTEMS_TARGET_PREFIX}/${RTEMS_BSP}/lib"
)
set(CMAKE_SYSTEM_LIBRARY_PATH ${CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES})

set(CMAKE_C_FLAGS_INIT
 "-B${RTEMS_TARGET_PREFIX}/${RTEMS_BSP}/lib/ -specs bsp_specs -qrtems ${RTEMS_BSP_C_FLAGS}"
)
set(CMAKE_C_FLAGS_INIT ${CMAKE_C_FLAGS_INIT})

set(CMAKE_EXE_LINKER_FLAGS_INIT "-u Init ${RTEMS_BSP_LINKER_FLAGS}")
foreach(ldpart ${RTEMS_LDPARTS})
  string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " ${RTEMS_TARGET_PREFIX}/${RTEMS_BSP}/lib/${ldpart}")
endforeach()
string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " -static")

# Needed to pass to try_compile, but not to actual executables
string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " -lrtemsdefaultconfig")

# Would be nice to use instead, but break eg. CheckFunctionExists.cmake
#set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)


# libbsd.a has some undefined symbols.  eg. iflib_pseudo_detach()
string(APPEND CMAKE_EXE_LINKER_FLAGS_INIT " -Wl,--gc-sections")

# Hack so that CheckFunctionExists.cmake will find network bits normally found in a libc
set(CMAKE_REQUIRED_LIBRARIES "-lbsd")
