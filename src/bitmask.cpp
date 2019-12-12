/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>

#include <pvxs/bitmask.h>
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
    _size = bits;
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

namespace impl {

PVXS_API
void to_wire(Buffer& buf, const BitMask& mask)
{
    size_t nbytes = (mask.size() + 7u)/8u; // round up #bits to bytes
    size_t nwords = nbytes / 8u;
    size_t extra = nbytes % 8u; // trailing single bytes

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
