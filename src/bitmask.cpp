/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>

#include "bitmask.h"
#include "pvaproto.h"
#include "utilpvt.h"

namespace pvxs {


BitMask::BitMask(BitMask&& o) noexcept
    :_words(std::move(o._words))
    ,_size(o._size)
{
    o._size = 0u;
}

BitMask& BitMask::operator=(BitMask&& o) noexcept
{
    _words = std::move(o._words);
    _size = o._size;
    o._size = 0u;
    return *this;
}

BitMask::BitMask(std::initializer_list<size_t> bits, size_t nbits)
{
    if(bits.size()>0u) {
        auto it_max = std::max_element(bits.begin(), bits.end());
        resize(std::max(nbits, 1u+*it_max));
        for(auto bit : bits) {
            (*this)[bit] = true;
        }
    } else {
        resize(nbits);
    }
}

void BitMask::resize(size_t bits) {
    // round up to multiple of 64
    size_t storebits = ((bits-1u)|0x3f)+1u;
    _words.resize(storebits/64u, 0u);
    _size = uint16_t(bits);
}

size_t BitMask::findSet(size_t start) const
{
    while(start < _size) {
        size_t word = start/64u,
                bit = start%64u;

        // first see if we can skip to next word
        uint64_t mask = ~((1ull<<bit)-1); // mask of bit and higher
        uint64_t masked = _words[word]&mask;
        if(masked==0u) {
            start = (word+1u)*64u;
            continue;
        }

        // the answer is in range [bit, 64)

        // count consecutive "trailing" zeros.
        // http://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightParallel

        masked &= -masked; // and with two's complement.  neat.  clears all except the bit we care about

        // now a binary search
        // we know masked is non-zero, and can start from 63
        //bit = 64u;
        //if(masked) bit--;
        bit = 63u;
        if(masked&0x00000000ffffffffull) bit -= 32u;
        if(masked&0x0000ffff0000ffffull) bit -= 16u;
        if(masked&0x00ff00ff00ff00ffull) bit -= 8u;
        if(masked&0x0f0f0f0f0f0f0f0full) bit -= 4u;
        if(masked&0x3333333333333333ull) bit -= 2u; // 0xb0011 repeated
        if(masked&0x5555555555555555ull) bit -= 1u; // 0xb0101 repeated

        return (word*64u) | bit;
    }

    return _size;
}

std::ostream& operator<<(std::ostream& strm, const BitMask& mask)
{
    strm.put('{');
    bool first = true;
    for(auto bit : mask.onlySet()) {
        if(first) first = false;
        else strm<<", ";
        strm<<bit;
    }
    strm.put('}');
    return strm;
}

bool operator==(const BitMask& lhs, const BitMask& rhs)
{
    if(lhs.size()!=rhs.size())
        return false;

    return std::equal(lhs._words.begin(),
                      lhs._words.end(),
                      rhs._words.begin());
}

namespace impl {

PVXS_API
void to_wire(Buffer& buf, const BitMask& mask)
{
    // ignore trailing zeros
    size_t nwords=mask.wsize();
    size_t extra = 0u;
    while(nwords) {
        auto last = mask.word(nwords-1u);
        if(last&0xff00000000000000ull) break;
        nwords--;
        if(last==0) continue;
        else if(last&0x00ff000000000000ull) extra=7u;
        else if(last&0x0000ff0000000000ull) extra=6u;
        else if(last&0x000000ff00000000ull) extra=5u;
        else if(last&0x00000000ff000000ull) extra=4u;
        else if(last&0x0000000000ff0000ull) extra=3u;
        else if(last&0x000000000000ff00ull) extra=2u;
        else if(last&0x00000000000000ffull) extra=1u;
        break;
    }
    size_t nbytes = nwords*8u + extra;

    to_wire(buf, Size{nbytes});
    for(auto i : range(nwords)) {
        to_wire(buf, mask.word(i));
    }
    if(extra) {
        uint64_t last = mask.word(nwords);
        for(auto i : range(extra)) {
            to_wire(buf, uint8_t(last>>(8u*i)));
        }
    }
}

PVXS_API
void from_wire(Buffer& buf, BitMask& mask)
{
    Size nbytes{0u};

    from_wire(buf, nbytes);
    mask.resize(8u*nbytes.size);

    size_t nwords = nbytes.size / 8u;
    size_t extra = nbytes.size % 8u; // trailing single bytes

    for(auto i : range(nwords)) {
        from_wire(buf, mask.word(i));
    }
    if(extra) {
        uint64_t& last = mask.word(nwords);
        for(auto i : range(extra)) {
            uint8_t b=0;
            from_wire(buf, b);
            last |= uint64_t(b)<<(8u*i);
        }
    }
}

} // namespace impl
} // namespace pvxs
