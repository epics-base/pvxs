/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_BITMASK_H
#define PVXS_BITMASK_H

#include <ostream>
#include <stdexcept>
#include <vector>
#include <algorithm>
#include <cstdint>

#include <pvxs/version.h>

namespace pvxs {

namespace detail {
// base type, defines operations which can be performed on an BitMask expression
template <typename Sub>
struct BitBase {
    size_t size() const { return (*static_cast<const Sub*>(this)).size(); }
    size_t wsize() const { return (*static_cast<const Sub*>(this)).wsize(); }
    uint64_t word(size_t i) const { return (*static_cast<const Sub*>(this)).word(i); }
};

// unary negate
template <typename Inp>
struct BitNot : public BitBase<BitNot<Inp>>
{
    const Inp& inp;
    BitNot(const Inp& inp) :inp(inp) {}
    size_t size() const { return inp.size(); }
    size_t wsize() const { return inp.wsize(); }
    uint64_t word(size_t i) const { return ~inp.word(i); }
};

template <typename Inp>
constexpr
BitNot<BitBase<Inp>>
operator!(const BitBase<Inp>& inp)
{
    return BitNot<BitBase<Inp>>{inp};
}

// binary bitwise and
template <typename Lhs, typename Rhs>
struct BitAnd : public BitBase<BitAnd<Lhs,Rhs>>
{
    const Lhs& lhs;
    const Rhs& rhs;
    BitAnd(const Lhs& lhs, const Rhs& rhs) :lhs(lhs), rhs(rhs) {}
    size_t size() const { return std::min(lhs.size(), rhs.size()); }
    size_t wsize() const { return std::min(lhs.wsize(), rhs.wsize()); }
    uint64_t word(size_t i) const { return lhs.word(i) & rhs.word(i); }
};

template<typename Lhs, typename Rhs>
BitAnd<BitBase<Lhs>, BitBase<Rhs>>
operator &(const BitBase<Lhs>& lhs, const BitBase<Rhs>& rhs)
{
    if(lhs.size()!=rhs.size())
        throw std::logic_error("op size mis-match"); // this sucks, need to figure out a way to handle different size input
    return BitAnd<BitBase<Lhs>, BitBase<Rhs>>{lhs, rhs};
}

// binary bitwise or
template <typename Lhs, typename Rhs>
struct BitOr : public BitBase<BitOr<Lhs,Rhs>>
{
    const Lhs& lhs;
    const Rhs& rhs;
    BitOr(const Lhs& lhs, const Rhs& rhs) :lhs(lhs), rhs(rhs) {}
    size_t size() const { return std::max(lhs.size(), rhs.size()); }
    size_t wsize() const { return std::max(lhs.wsize(), rhs.wsize()); }
    uint64_t word(size_t i) const { return lhs.word(i) | rhs.word(i); }
};

template<typename Lhs, typename Rhs>
BitOr<BitBase<Lhs>, BitBase<Rhs>>
operator |(const BitBase<Lhs>& lhs, const BitBase<Rhs>& rhs)
{
    if(lhs.size()!=rhs.size())
        throw std::logic_error("op size mis-match");
    return BitOr<BitBase<Lhs>, BitBase<Rhs>>{lhs, rhs};
}

} // namespace detail

class BitMask : public detail::BitBase<BitMask> {
    // bit  0 - lsb of word 0
    // bit 63 - msb of word 0
    // bit 64 - lsb of word 1
    std::vector<uint64_t> _words;
    // actual size in bits
    // _words.size()*64u >= _size
    uint16_t _size=0u;

public:

    typedef bool value_type;

    //! Empty mask with size()==0
    BitMask() = default;
    // movable, not copyable
    BitMask(const BitMask&) = delete;
    BitMask(BitMask&&) noexcept;
    BitMask& operator=(const BitMask&) = delete;
    BitMask& operator=(BitMask&&) noexcept;
    ~BitMask() = default;

    //! cleared mask with size()==0
    explicit BitMask(size_t nbits) {
        resize(nbits);
    }
    //! Initialize certain bit numbers.  ensure size()>=nbits.
    PVXS_API
    BitMask(std::initializer_list<size_t> bits, size_t nbits=0);

    //! number of bits
    inline size_t size() const { return _size; }
    //! size()==0
    inline bool empty() const { return _size==0u; }

    //! number of storage words
    inline size_t wsize() const { return _words.size(); }
    //! storage word
    inline uint64_t& word(size_t i) { return _words[i]; }
    inline const uint64_t& word(size_t i) const { return _words[i]; }

    PVXS_API
    void resize(size_t bits);

    //! Returns index of first set bit in range [start, size()] inclusive.
    //! Returns size() if no bits are set.
    PVXS_API
    size_t findSet(size_t start=0u) const;

private:
    template<typename BR>
    class _BitRef {
        friend class BitMask;
        BR* _mask;
        size_t _bit;
        constexpr _BitRef(BR* mask, size_t bit) :_mask(mask), _bit(bit) {}
    public:

        operator bool() const {
            return _mask->_words[_bit/64u]&(uint64_t(1)<<(_bit%64u));
        }
        _BitRef& operator=(bool v) {
            auto& word = _mask->_words[_bit/64u];
            if(v)
                word |= uint64_t(1)<<(_bit%64u);
            else
                word &= ~(uint64_t(1)<<(_bit%64u));
            return *this;
        }
    };
    template<typename BR> friend class _BitRef;
public:
    typedef _BitRef<BitMask> reference;
    typedef _BitRef<const BitMask> const_reference;

    reference operator[](size_t bit) { return _BitRef<BitMask>{this, bit}; }
    const_reference operator[](size_t bit) const { return _BitRef<const BitMask>{this, bit}; }

private:
    class _SetIter {
        friend BitMask;
        const BitMask* _mask = nullptr;
        size_t _bit = 0u;
    public:
        constexpr _SetIter() = default;
        constexpr _SetIter(const BitMask* mask, size_t bit) :_mask(mask), _bit(bit) {}

        size_t operator*() const { return _bit; }
        _SetIter& operator++() { _bit=_mask->findSet(_bit+1); return *this; }
        _SetIter operator++(int) { _SetIter ret{*this}; _bit=_mask->findSet(_bit+1); return ret;}

        bool operator==(const _SetIter& o) { return _bit==o._bit; }
        bool operator!=(const _SetIter& o) { return _bit!=o._bit; }
    };
    class _OnlySet {
        friend BitMask;
        const BitMask* _mask;
        size_t a, b;
        constexpr explicit _OnlySet(const BitMask* mask, size_t a, size_t b) :_mask(mask), a(a), b(b) {}
    public:
        typedef _SetIter iterator;
        iterator begin() const { return iterator{_mask, _mask->findSet(a)}; }
        iterator end() const { return iterator{_mask, b}; }
    };

public:
    //! return object which can be iterated to find all set bits
    _OnlySet onlySet() const { return _OnlySet{this, 0u, size()}; }
    //! return object which can be iterated to find all set bits in range [a, b)
    _OnlySet onlySet(size_t a, size_t b) const { return _OnlySet{this, a, b}; }
    // all()

    // evaluate expression
    template<typename Inp>
    BitMask(const detail::BitBase<Inp>& expr) {
        resize(expr.size());
        for(size_t i=0, N=expr.wsize(); i<N; i++)
            _words[i] = expr.word(i);
    }

    // evaluate expression
    template<typename Inp>
    BitMask& operator=(const detail::BitBase<Inp>& expr) {
        resize(expr.size());
        for(size_t i=0, N=expr.wsize(); i<N; i++)
            _words[i] = expr.word(i);
        return *this;
    }

    // evaluate expression
    template<typename Inp>
    BitMask& operator|=(const detail::BitBase<Inp>& expr) {
        resize(expr.size());
        for(size_t i=0, N=expr.wsize(); i<N; i++)
            _words[i] |= expr.word(i);
        return *this;
    }

    // evaluate expression
    template<typename Inp>
    BitMask& operator&=(const detail::BitBase<Inp>& expr) {
        resize(expr.size());
        for(size_t i=0, N=expr.wsize(); i<N; i++)
            _words[i] &= expr.word(i);
        return *this;
    }

    friend
    PVXS_API
    bool operator==(const BitMask& lhs, const BitMask& rhs);
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const BitMask& mask);

PVXS_API
bool operator==(const BitMask& lhs, const BitMask& rhs);

inline bool operator!=(const BitMask& lhs, const BitMask& rhs) {
    return !(lhs==rhs);
}

namespace impl {
struct Buffer;

PVXS_API
void to_wire(Buffer& buf, const BitMask& mask);

PVXS_API
void from_wire(Buffer& buf, BitMask& mask);
}

} // namespace pvxs

#endif // PVXS_BITMASK_H
