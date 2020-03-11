/* Compiler inspection
 *
 * expanded as configure/CONFIG_SITE.Common.*
 */
#define VERSION_INT(V,R,M,P) ( ((V)<<24) | ((R)<<16) | ((M)<<8) | (P))

CONFIG_LOADED=YES

#if __GNUC__
/* also true for clang */
GNUISH=YES
USR_CXXFLAGS += -std=c++11
#endif

#if __GNUC__ && !__clang__
#define GCC_VERSION VERSION_INT(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__, 0)

/* LTO takes a nice chunk out of the .so text size, but blows up the .a size */
#if GCC_VERSION>=VERSION_INT(4,9,0,0)
OPT_CFLAGS_YES += -flto
OPT_CXXFLAGS_YES += -flto
USR_LDFLAGS += -flto
#endif

/* Compress debug information on ELF targets for ~25%-50% reduction in .so and .a file size
 * (C++ debug info is Huuuge!)
 */
#if __ELF__ && GCC_VERSION>=VERSION_INT(5,0,0,0)
USR_CFLAGS += -gz=zlib
USR_CXXFLAGS += -gz=zlib
/* Actually a binutils feature, which we can't detect.
 * Assume binutils upgrade follow gcc
 */
USR_LDFLAGS += -Wl,--compress-debug-sections=zlib
#endif

#endif /* __GNUC__ */
