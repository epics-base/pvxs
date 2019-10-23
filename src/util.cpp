/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iomanip>

#include <ctype.h>

#include <pvxs/util.h>

namespace pvxs {

#define stringify(X) #X

const char *version_str()
{
    return "PVXS " stringify(PVXS_MAJOR_VERSION);
}

unsigned long version_int()
{
    return PVXS_VERSION;
}

namespace detail {

std::ostream& operator<<(std::ostream& strm, const Escaper& esc)
{
    const char *s = esc.val;
    if(!s) {
        strm<<"<NULL>";
    } else {
        for(; *s; s++) {
            char c = *s, next;
            switch(c) {
            case '\a': next = 'a'; break;
            case '\b': next = 'b'; break;
            case '\f': next = 'f'; break;
            case '\n': next = 'n'; break;
            case '\r': next = 'r'; break;
            case '\t': next = 't'; break;
            case '\v': next = 'v'; break;
            case '\\': next = '\\'; break;
            case '\'': next = '\''; break;
            default:
                if(isprint(c)) {
                    strm.put(c);
                } else {
                    strm<<"\\x"<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(c);
                }
                continue;
            }
            strm.put('\\').put(next);
        }
    }
    return strm;
}


}

}
