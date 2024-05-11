/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cmath>
#include <vector>
#include <ostream>
#include <algorithm>

#include <pvxs/data.h>
#include <pvxs/nt.h>
#include <pvxs/unittest.h>

#include "pvaproto.h"
#include <utilpvt.h>

#include <evhelper.h>

#include <epicsTime.h>
#include <epicsUnitTest.h>
#include <testMain.h>

namespace {
using namespace pvxs;

struct Sampler
{
    size_t nsamp =0;
    double min=0.0, max=0.0, first=0.0;
    double sum=0.0, sum2=0.0;

    void reset() {
        *this = {}; // zero members
    }

    void sample(double val) {
        if(nsamp==0u) {
            min = max = first = val;

        } else {
            if(max < val)
                max = val;
            else if(min > val)
                min = val;
        }
        sum += val;
        sum2 += val*val;
        nsamp++;
    }

    double mean() const {
        return sum/nsamp;
    }

    double std() const {
        return sqrt(sum2/nsamp - (sum/nsamp)*(sum/nsamp));
    }
};

std::ostream& operator<<(std::ostream& strm, const Sampler& samp)
{
    Restore R(strm);
    strm<<"N="<<samp.nsamp<<" "<<samp.mean()<<" +- "<<samp.std()<<" ["<<samp.min<<", "<<samp.max<<"] first="<<samp.first;
    return strm;
}

struct StopWatch {
    epicsUInt64 start = 0u;

    epicsUInt64 click() {
        epicsUInt64 now(epicsMonotonicGet());
        epicsUInt64 ret = now-start;
        start = now;
        return ret;
    }
};

void benchAllocNTScalar()
{
    testDiag("%s", __func__);

    constexpr size_t niter = 1000u;

    const Value prototype(nt::NTScalar{TypeCode::UInt64, true, true, true}.create());

    std::vector<Value> can(niter);

    Sampler S;

    for(auto n : range(niter)) {
        StopWatch W;

        (void)W.click();
        can[n] = prototype.cloneEmpty();
        S.sample(W.click());
    }

    testShow()<<S;
}

template<typename E>
void benchArraySerDes(bool be, const shared_array<const E>& arr)
{
    testDiag("%s<%s>() endian=%s", __func__, typeid (E).name(), be==hostBE ? "Host" : "Swap");

    constexpr size_t niter = 1000u;

    shared_array<const void> scratch;

    evbuf ebuf(__FILE__, __LINE__, evbuffer_new());

    Sampler Tser, Tdes;

    for(auto n : range(niter)) {
        (void)n;
        StopWatch W;

        {
            EvOutBuf buf(be, ebuf.get());
            auto varr(arr.template castTo<const void>());
            (void)W.click();
            to_wire<E>(buf, varr);
            Tser.sample(W.click());
        }

        {
            EvInBuf buf(be, ebuf.get());
            (void)W.click();
            from_wire<E>(buf, scratch);
            Tdes.sample(W.click());
        }

        auto iarr(arr.template castTo<const E>());
        auto iscratch(scratch.castTo<const E>());

        if(iarr.size()!=iscratch.size()
                || !std::equal(iarr.begin(), iarr.end(), iscratch.begin()))
            testArrEq(arr.template castTo<const E>(), scratch.castTo<const E>());
    }

    testShow()<<" Ser "<<Tser;
    testShow()<<" Des "<<Tdes;
}

} // namespace

MAIN(benchdata)
{
    testPlan(0);
    benchAllocNTScalar();

    constexpr size_t nelem = 10000u;
    testDiag("test optimization for fixed size (POD) elements");
    {
        shared_array<uint64_t> temp(nelem);
        for(auto n : range(temp.size())) {
            temp[n] = n;
        }
        shared_array<const uint64_t> arr(temp.freeze());
        benchArraySerDes<uint64_t>(hostBE, arr);
        benchArraySerDes<uint64_t>(!hostBE, arr);
    }
    testDiag("baseline unoptimized for a variable size element");
    {
        shared_array<std::string> temp(nelem);
        for(auto n : range(temp.size())) {
            temp[n] = SB()<<"test"<<n;
        }
        shared_array<const std::string> arr(temp.freeze());
        benchArraySerDes<std::string>(hostBE, arr);
        benchArraySerDes<std::string>(!hostBE, arr);
    }
    return testDone();
}
