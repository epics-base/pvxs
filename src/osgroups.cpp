/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/* originally taken from getgroups.cpp in pvAccessCPP
 */

#include <vector>

#if defined(_WIN32)
#  define USE_LANMAN
#elif !defined(__rtems__) && !defined(vxWorks)
#  define USE_UNIX_GROUPS
#endif

/* conditionally include any system headers */
#if defined(USE_UNIX_GROUPS)

#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

// getgrouplist() has a slightly different prototype on OSX.
#  ifdef __APPLE__
//   OSX has gid_t, which isn't "int", but doesn't use it here.
// int getgrouplist(const char *name, int basegid, int *groups, int *ngroups);
typedef int osi_gid_t;
#  else
// int getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups);
typedef gid_t osi_gid_t;
#  endif

#elif defined(USE_LANMAN)

#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <lm.h>

#endif

#include <epicsAssert.h>

#include "utilpvt.h"

namespace pvxs {
namespace impl {

#if defined(USE_UNIX_GROUPS)

void osdGetRoles(const std::string& account, std::set<std::string>& roles)
{
    passwd *user = getpwnam(account.c_str());
    if(!user) {
        roles.insert(account);
        return; // don't know who this is
    }

    typedef std::set<gid_t> gids_t;
    gids_t gids;

    gids.insert(user->pw_gid); // include primary group

    /* List supplementary groups.
     *
     * Rant...
     * getgrouplist() differs subtly when the *count is too short.
     * Some libc (Mac) don't update the count
     * Some libc (glibc) don't write a truncated list.
     *
     * We might also use getgrent(), but this isn't reentrant, and
     * would anyway require visiting all groups.
     * The GNU alternative getgrent_r() would require us to allocate
     * enough space to hold the list of all members of the largest
     * group.  This may be hundreds.
     *
     * So we iterate with getgrouplist() as the lesser evil...
     */
    {
        // start with a guess
        std::vector<osi_gid_t> gtemp(16, (osi_gid_t)-1);

        while(true) {
            int gcount = int(gtemp.size());
            int ret = getgrouplist(user->pw_name, user->pw_gid, &gtemp[0], &gcount);

            if(ret>=0 && gcount>=0 && gcount <= int(gtemp.size())) {
                // success
                gtemp.resize(gcount);
                break;

            } else if(ret>=0) {
                // success, but invalid count?  give up
                gtemp.clear();
                break;

            } else if(gcount == int(gtemp.size())) {
                // too small, but gcount not updated.  (Mac)
                // arbitrary increase to size and retry
                gtemp.resize(gtemp.size()*2u, (osi_gid_t)-1);

            } else if(gcount > int(gtemp.size())) {
                // too small, gcount holds actual size.  retry
                gtemp.resize(gcount, (osi_gid_t)-1);

            } else {
                // too small, but gcount got smaller?  give up
                gtemp.clear();
                break;
            }
        }

        for(size_t i=0, N=gtemp.size(); i<N; i++)
            gids.insert(gtemp[i]);
    }

    // map GIDs to names
    for(auto gid : gids) {
        if(group* gr = getgrgid(gid))
            roles.insert(gr->gr_name);
    }
}

#elif defined(USE_LANMAN)

void osdGetRoles(const std::string& account, std::set<std::string>& roles)
{
    NET_API_STATUS sts;
    LPLOCALGROUP_USERS_INFO_0 pinfo = NULL;
    DWORD ninfo = 0, nmaxinfo = 0;
    std::vector<wchar_t> wbuf;

    {
        size_t N = mbstowcs(NULL, account.c_str(), 0);
        if(N==size_t(-1))
            return; // username has invalid MB char
        wbuf.resize(N+1);
        N = mbstowcs(&wbuf[0], account.c_str(), account.size());
        assert(N+1==wbuf.size());
        wbuf[N] = 0; // paranoia
    }

    // this call may involve network I/O
    sts = NetUserGetLocalGroups(NULL, &wbuf[0], 0,
                                LG_INCLUDE_INDIRECT,
                                (LPBYTE*)&pinfo,
                                MAX_PREFERRED_LENGTH,
                                &ninfo, &nmaxinfo);

    if(sts!=NERR_Success) {
       ninfo = 0;
    }

    try {
        std::vector<char> buf;

        for(DWORD i=0; i<ninfo; i++) {
            size_t N = wcstombs(NULL, pinfo[i].lgrui0_name, 0);
            if(N==size_t(-1))
                continue; // has invalid MB char

            buf.resize(N+1);
            N = wcstombs(&buf[0], pinfo[i].lgrui0_name, buf.size());
            buf[N] = 0; // paranoia

            roles.insert(&buf[0]);
        }

        if(pinfo)
            NetApiBufferFree(pinfo);
    }catch(...){
        NetApiBufferFree(pinfo);
        throw;
    }

    if(roles.empty())
        roles.insert(account);
}

#else

void osdGetRoles(const std::string& account, std::set<std::string>& roles)
{
    /* Group list not available (RTEMS, vxWorks)
     * Report the remote account as the only role.
     */
    roles.insert(account);
}
#endif

}} // namespace pvxs::impl
