/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_SHAREDVECTOR_H
#define PVXS_SHAREDVECTOR_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <algorithm>
#include <iosfwd>
#include <iterator>

#include <pvxs/version.h>

namespace pvxs {

class Value;

template<typename E, class Enable = void> class shared_array;

//! Identify real array type in void specializations of shared_array.
//! @see shared_array::original_type()
enum class ArrayType : uint8_t {
    Null  = 0xff, //!< Untyped
    Bool  = 0x08, //!< bool
    Int8  = 0x28, //!< int8_t
    Int16 = 0x29, //!< int16_t
    Int32 = 0x2a, //!< int32_t
    Int64 = 0x2b, //!< int64_t
    UInt8 = 0x2c, //!< uint8_t
    UInt16= 0x2d, //!< uint16_t
    UInt32= 0x2e, //!< uint32_t
    UInt64= 0x2f, //!< uint64_t
    Float32=0x4a, //!< float
    Float64=0x4b, //!< double
    String= 0x68, //!< std::string
    Value = 0x88, //!< Value
    // also used for 0x89 and 0x8a
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, ArrayType code);

//! Return storage size (aka. sizeof() ) for array element type
//! @throws std::logic_error for invalid types.
PVXS_API
size_t elementSize(ArrayType type);

//! Return a void array usable for the given storage type
PVXS_API
shared_array<void> allocArray(ArrayType type, size_t count);

namespace detail {
template<typename T>
struct CaptureCode;

#define CASE(TYPE, CODE) \
template<> struct CaptureCode<TYPE> { static constexpr ArrayType code{ArrayType::CODE}; }
CASE(bool, Bool);
CASE(int8_t,  Int8);
CASE(int16_t, Int16);
CASE(int32_t, Int32);
CASE(int64_t, Int64);
CASE(uint8_t,  UInt8);
CASE(uint16_t, UInt16);
CASE(uint32_t, UInt32);
CASE(uint64_t, UInt64);
CASE(float, Float32);
CASE(double, Float64);
CASE(std::string, String);
CASE(Value, Value);
#undef CASE

template<typename T>
using CaptureBase = CaptureCode<typename std::remove_cv<T>::type>;

template<typename T, typename Enable=void>
struct sizeofx {
    static inline size_t op() { return sizeof(T); }
};
template<typename T>
struct sizeofx<T, typename std::enable_if<std::is_void<T>::value>::type> {
    static inline size_t op() { return 1u; } // treat void* as pointer to bytes
};

template<typename E>
struct sa_default_delete {
    void operator()(E* e) const { delete[] e; }
};

template<typename E>
struct sa_base {
protected:
    template<typename E1> friend struct sa_base;

    std::shared_ptr<E> _data;
    size_t             _count;
public:

    // shared_array()
    // shared_array(const shared_array&)
    // shared_array(shared_array&&)
    // shared_array(size_t, T)
    // shared_array(T*, size_t)
    // shared_array(T*, d, size_t)
    // shared_array(shared_ptr<T>, size_t)
    // shared_array(shared_ptr<T>, T*, size_t)

    //! empty
    constexpr sa_base() :_count(0u) {}

    // copyable
    sa_base(const sa_base&) = default;
    // movable
    inline sa_base(sa_base&& o) noexcept
        :_data(std::move(o._data)), _count(o._count)
    {
        o._count = 0;
    }
    sa_base& operator=(const sa_base&) =default;
    inline sa_base& operator=(sa_base&& o) noexcept
    {
        _data = std::move(o._data);
        _count = o._count;
        o._count = 0;
        return *this;
    }

    // use existing alloc with delete[]
    template<typename A>
    sa_base(A* a, size_t len)
        :_data(a, sa_default_delete<E>()),_count(len)
    {}

    // use existing alloc w/ custom deletor
    template<typename B>
    sa_base(E* a, B b, size_t len)
        :_data(a, b),_count(len)
    {}

    // build around existing shared_ptr
    sa_base(const std::shared_ptr<E>& a, size_t len)
        :_data(a),_count(len)
    {}

    // alias existing shared_ptr
    template<typename A>
    sa_base(const std::shared_ptr<A>& a, E* b, size_t len)
        :_data(a, b),_count(len)
    {}

    void clear() noexcept {
        _data.reset();
        _count = 0;
    }

    void swap(sa_base& o) noexcept {
        std::swap(_data, o._data);
        std::swap(_count, o._count);
    }

    //! Number of elements
    inline size_t size() const { return _count; }
    inline bool empty() const noexcept { return _count==0; }

    inline bool unique() const noexcept { return !_data || _data.use_count()<=1; }

    E* data() const noexcept { return _data.get(); }

    const std::shared_ptr<E>& dataPtr() const { return _data; }
};

//! Provide options when rendering with std::ostream.
class Limiter {
    const void* _base;
    size_t _count;
    size_t _limit=0u;
    ArrayType _type;
    friend
    PVXS_API
    std::ostream& operator<<(std::ostream& strm, const Limiter& lim);
public:
    Limiter(const void* base, size_t count, ArrayType type)
        :_base(base), _count(count), _type(type)
    {}
    //! Maximum number of array elements to print.
    //! "..." is printed in place of any further elements.
    Limiter& limit(size_t l) { _limit = l; return *this; }
};

PVXS_API
std::ostream& operator<<(std::ostream& strm, const Limiter&);

PVXS_API
void _throw_bad_cast(ArrayType from, ArrayType to);

PVXS_API
void convertArr(ArrayType dtype,       void *dbase,
                ArrayType stype, const void *sbase,
                size_t count);

PVXS_API
shared_array<void> copyAs(ArrayType dtype, ArrayType stype, const void *sbase, size_t count);

} // namespace detail

/** std::vector-like contiguous array of items passed by reference.
 *
 * shared_array comes in const and non-const, as well as void and non-void variants.
 *
 * A non-const array is allocated and filled, then last non-const reference is exchanged for new const reference.
 * This const reference can then be safely shared between various threads.
 *
 * @code
 *   shared_array<uint32_t> arr({1, 2, 3});
 *   assert(arr.size()==3);
 *   shared_ptr<const uint32_t> constarr(arr.freeze());
 *   assert(arr.size()==0);
 *   assert(constarr.size()==3);
 * @endcode
 *
 * The void / non-void variants allow arrays to be moved without explicit typing.
 * However, the void variant preserves the original ArrayType.
 *
 * @code
 *   shared_array<uint32_t> arr({1, 2, 3});
 *   assert(arr.size()==3);
 *   shared_array<void> voidarr(arr.castTo<void>());
 *   assert(arr.size()==0);
 *   assert(voidarr.size()==3); // void size() in elements
 * @endcode
 */
template<typename E, class Enable>
class shared_array : public detail::sa_base<E> {
    static_assert (!std::is_void<E>::value, "non-void specialization");

    template<typename E1, class Enable1> friend class shared_array;

    typedef detail::sa_base<E> base_t;
    typedef typename std::remove_const<E>::type _E_non_const;
public:
    typedef E value_type;
    typedef E& reference;
    typedef typename std::add_const<E>::type& const_reference;
    typedef E* pointer;
    typedef typename std::add_const<E>::type* const_pointer;
    typedef E* iterator;
    typedef std::reverse_iterator<iterator> reverse_iterator;
    typedef typename std::add_const<E>::type* const_iterator;
    typedef std::reverse_iterator<const_iterator> const_reverse_iterator;
    typedef std::ptrdiff_t difference_type;
    typedef size_t size_type;

    typedef E element_type;

    constexpr shared_array() noexcept :base_t() {}

    //! allocate new array and populate from initializer list
    template<typename A>
    shared_array(std::initializer_list<A> L)
        :base_t(new _E_non_const[L.size()], L.size())
    {
        auto raw = const_cast<_E_non_const*>(this->data());
        std::copy(L.begin(), L.end(), raw);
    }

    //! Construct a copy of another a sequence.
    //! Requires random access iterators.
    template<typename Iter, typename std::iterator_traits<Iter>::difference_type=0>
    shared_array(Iter begin, Iter end)
        :shared_array(std::distance(begin, end))
    {
        std::copy(begin, end, const_cast<_E_non_const*>(this->begin()));
    }

    //! @brief Allocate (with new[]) a new vector of size c
    explicit shared_array(size_t c)
        :base_t(new _E_non_const[c], c)
    {}

    //! @brief Allocate (with new[]) a new vector of size c and fill with value e
    template<typename V>
    shared_array(size_t c, V e)
        :base_t(new _E_non_const[c], c)
    {
        std::fill_n((_E_non_const*)this->_data.get(), this->_count, e);
    }

    //! use existing alloc with delete[]
    shared_array(E* a, size_t len)
        :base_t(a, len)
    {}

    //! use existing alloc w/ custom deletor
    template<typename B>
    shared_array(E* a, B b, size_t len)
        :base_t(a, b, len)
    {}

    //! build around existing shared_ptr
    shared_array(const std::shared_ptr<E>& a, size_t len)
        :base_t(a, len)
    {}

    //! alias existing shared_array
    template<typename A>
    shared_array(const std::shared_ptr<A>& a, E* b, size_t len)
        :base_t(a, b, len)
    {}

#ifdef _DOXYGEN_
    // documentation for sa_base method since this is an implementation detail

    //! Number of elements
    size_t size() const;
    //! size()==0
    bool empty() const;
    //! True if this instance is the only (strong) reference
    bool unique() const;
    //! Reset size()==0
    void clear();
    //! Exchange contents with other
    void swap(shared_array& o);
    //! Access to raw pointer.
    //! May be nullptr if size()==0
    E* data() const noexcept;
#endif

    size_t max_size() const noexcept {return ((size_t)-1)/sizeof(E);}

    inline void reserve(size_t i) {}

    //! Extend size.  Implies make_unique()
    void resize(size_t i) {
        if(!this->unique() || i!=this->_count) {
            shared_array o(i);
            std::copy_n(this->begin(), std::min(this->size(), i), o.begin());
            this->swap(o);
        }
    }

    //! Ensure exclusive ownership of array data
    inline void make_unique() {
        this->resize(this->size());
    }

private:
    /* Hack alert.
     * For reasons of simplicity and efficiency, we want to use raw pointers for iteration.
     * However, shared_ptr::get() isn't defined when !_data, although practically it gives NULL.
     * Unfortunately, many of the MSVC (<= VS 2010) STL methods assert() that iterators are never NULL.
     * So we fudge here by abusing 'this' so that our iterators are always !NULL.
     */
    inline E* base_ptr() const {
#if defined(_MSC_VER) && _MSC_VER<=1600
        return this->_count ? this->_data.get() : (E*)(this-1);
#else
        return this->_data.get();
#endif
    }
public:
    // STL iterators

    //! begin iteration
    inline iterator begin() const noexcept{return this->base_ptr();}
    inline const_iterator cbegin() const noexcept{return begin();}

    //! end iteration
    inline iterator end() const noexcept{return this->base_ptr()+this->_count;}
    inline const_iterator cend() const noexcept{return end();}

    inline reverse_iterator rbegin() const noexcept{return reverse_iterator(end());}
    inline const_reverse_iterator crbegin() const noexcept{return rbegin();}

    inline reverse_iterator rend() const noexcept{return reverse_iterator(begin());}
    inline const_reverse_iterator crend() const noexcept{return rend();}

    inline reference front() const noexcept{return (*this)[0];}
    inline reference back() const noexcept{return (*this)[this->_count-1];}

    //! @brief Member access
    //! Use sa.data() instead of &sa[0]
    //! @pre !empty() && i<size()
    inline reference operator[](size_t i) const noexcept {return this->_data.get()[i];}

    //! @brief Member access
    //! @throws std::out_of_range if empty() || i>=size().
    reference at(size_t i) const
    {
        if(i > this->_count)
            throw std::out_of_range("Index out of bounds");
        return (*this)[i];
    }

    //! Cast to const, consuming this
    //! @pre unique()==true
    //! @post empty()==true
    //! @throws std::logic_error if !unique()
    shared_array<typename std::add_const<E>::type>
    freeze() {
        if(!this->unique())
            throw std::logic_error("Can't freeze non-unique shared_array");

        // alias w/ implied cast to const.
        shared_array<typename std::add_const<E>::type> ret(this->_data, this->_data.get(), this->_count);

        // c++20 provides a move()-able alternative to the aliasing constructor.
        // until this stops being the future, we consume the src ref. and
        // inc. + dec. the ref counter...
        this->clear();
        return ret;
    }

    /** Return non-const (maybe) copy.  consuming this
     * @post empty()==true
     * @since 1.1.2
     *
     * If unique(), transforms this reference into the returned const reference.
     * If not unique(), returns a copy and clears this reference.
     * In either case, the returned reference will be unique().
     */
    shared_array<typename std::remove_const<E>::type>
    thaw() {
        if(this->unique()) { // only reference, avoid copy
            shared_array<typename std::remove_const<E>::type> ret(this->_data, (typename std::remove_const<E>::type*)this->_data.get(), this->_count);

            this->clear();
            return ret;

        } else { // other references, copy
            shared_array<typename std::remove_const<E>::type> ret(this->_data.get(),
                                                                  this->_data.get() + this->_count);
            this->clear();
            return ret;
        }
    }

#if _DOXYGEN_
    /** Cast to/from void, preserving const-ness.
     *
     * A "safe" version of static_cast<>()
     *
     * Allowed casts depend upon two aspects of type parameter E.
     *
     * Whether the base type is void or non-void.
     * And whether or not the const qualifier is present.
     *
     * Type E may always be cast to itself.
     *
     * Casts must preserve const-ness.
     * Either both of E and TO, or neither, must be const qualified.
     *
     * At most one of E or TO may have different non-void base type.
     *
     * @throws std::logic_error on void -> non-void cast when requested type and the original_type() do not match.
     */
    template<typename TO>
    shared_array<TO>
    castTo() const;

    /** Cast with fallback to copy.  Preserves const-ness
     *
     * Return either a reference or a copy of this array.
     * A copy will be made if the requested type and the original_type() do not match.
     * Otherwise functions like castTo().
     */
    template<typename TO>
    shared_array<TO>
    convertTo() const;
#endif

    template<typename TO, typename std::enable_if<std::is_void<TO>::value && (std::is_const<E>::value == std::is_const<TO>::value), int>::type =0>
    shared_array<TO>
    castTo() const {
        return shared_array<TO>(this->_data, this->_data.get(), this->_count); // implied cast to void*
    }

    template<typename TO, typename std::enable_if<std::is_same<TO, E>::value, int>::type =0>
    shared_array<TO>
    castTo() const {
        return *this;
    }

    // static_cast<TO>() to non-void, preserving const-ness
    template<typename TO, typename std::enable_if<!std::is_void<TO>::value && (std::is_const<E>::value == std::is_const<TO>::value), int>::type =0>
    shared_array<TO>
    castToUnsafe() const {
        return shared_array<TO>(this->_data, static_cast<TO*>(this->_data.get()), this->_count);
    }

    // static_cast<TO>() to void, preserving const-ness
    template<typename TO, typename std::enable_if<std::is_void<TO>::value && (std::is_const<E>::value == std::is_const<TO>::value), int>::type =0>
    shared_array<TO>
    castToUnsafe() const {
        return shared_array<TO>(this->_data, this->_data.get(), this->_count); // implied cast to void*
    }

    template<typename TO, typename std::enable_if<!std::is_void<TO>::value && (std::is_const<E>::value == std::is_const<TO>::value), int>::type =0>
    shared_array<TO>
    convertTo() const {
        shared_array<TO> ret(this->_count);
        detail::convertArr(detail::CaptureBase<TO>::code, (void*)ret._data.get(),
                           detail::CaptureBase<E>::code, this->_data.get(),
                           this->_count);
        return ret;
    }

    /** Provide options when rendering with std::ostream.
     *
     * @code
     *   shared_array<int32_t> arr({1,2,3,4});
     *   // print entire array
     *   //   {4}[1,2,3,4]
     *   std::cout<<arr;
     *   // print at most 3 elements
     *   //   {4}[1,2,3,...]
     *   std::cout<<arr.format().limit(3);
     * @endcode
     */
    detail::Limiter format() const {
        return detail::Limiter(this->_data.get(),
                               this->_count,
                               detail::CaptureBase<E>::code);
    }

#ifdef _DOXYGEN_
    //! return type of underlying array.  (void only)
    inline ArrayType original_type() const;
#endif
};


template<typename E>
class shared_array<E, typename std::enable_if<std::is_void<E>::value>::type >
    : public detail::sa_base<E>
{
    static_assert (std::is_void<E>::value, "void specialization");

    template<typename E1, class Enable1> friend class shared_array;

    typedef detail::sa_base<E> base_t;
    typedef typename std::remove_const<E>::type _E_non_const;

    ArrayType _type;
public:
    typedef E value_type;
    typedef E* pointer;
    typedef std::ptrdiff_t difference_type;
    typedef size_t size_type;

    //! empty array, untyped
    constexpr shared_array() noexcept :base_t(), _type(ArrayType::Null) {}
    //! empty array, typed
    constexpr explicit shared_array(ArrayType code) noexcept :base_t(), _type(code) {}
    //! copy
    shared_array(const shared_array& o) = default;
    //! move
    inline shared_array(shared_array&& o) noexcept
        :base_t(std::move(o))
        ,_type(o._type)
    {
        o._type = ArrayType::Null;
    }
    //! assign
    shared_array& operator=(const shared_array&) =default;
    //! move
    inline shared_array& operator=(shared_array&& o) noexcept
    {
        base_t::operator=(std::move(o));
        _type = o._type;
        o._type = ArrayType::Null;
        return *this;
    }

    //! use existing alloc with delete[]
    shared_array(E* a, size_t len, ArrayType type)
        :base_t(a, len)
        ,_type(type)
    {}

    //! use existing alloc w/ custom deletor
    template<typename B>
    shared_array(E* a, B b, size_t len, ArrayType type)
        :base_t(a, b, len)
        ,_type(type)
    {}

    //! build around existing shared_ptr and length
    shared_array(const std::shared_ptr<E>& a, size_t len, ArrayType type)
        :base_t(a, len)
        ,_type(type)
    {}

    //! alias existing shared_ptr and length
    template<typename A>
    shared_array(const std::shared_ptr<A>& a, E* b, size_t len)
        :base_t(a, b, len)
        ,_type(detail::CaptureBase<A>::code)
    {}

private:
    template<typename A>
    shared_array(const std::shared_ptr<A>& a, E* b, size_t len, ArrayType code)
        :base_t(a, b, len)
        ,_type(code)
    {}
public:

    //! clear data and become untyped
    void clear() noexcept {
        base_t::clear();
        _type = ArrayType::Null;
    }

    //! exchange
    void swap(shared_array& o) noexcept {
        base_t::swap(o);
        std::swap(_type, o._type);
    }

    size_t max_size() const noexcept{return (size_t)-1;}

    inline ArrayType original_type() const { return _type; }

    shared_array<typename std::add_const<E>::type>
    freeze() {
        if(!this->unique())
            throw std::logic_error("Can't freeze non-unique shared_array");

        // alias w/ implied cast to const.
        shared_array<typename std::add_const<E>::type> ret(this->_data, this->_data.get(), this->_count, this->_type);

        // c++20 provides a move()-able alternative to the aliasing constructor.
        // until this stops being the future, we consume the src ref. and
        // inc. + dec. the ref counter...
        this->clear();
        return ret;
    }

    shared_array<typename std::remove_const<E>::type>
    thaw() {
        if(this->unique()) { // only reference, avoid copy
            shared_array<typename std::remove_const<E>::type> ret(this->_data, (typename std::remove_const<E>::type*)this->_data.get(), this->_count, this->_type);

            this->clear();
            return ret;

        } else { // other references, copy
            auto copy(allocArray(this->_type, this->_count));
            detail::convertArr(this->_type, copy._data.get(), this->_type, this->_data.get(), this->_count);
            this->clear();
            return copy.template castTo<typename std::remove_const<E>::type>();
        }
    }

    // static_cast<TO>() to non-void, preserving const-ness
    template<typename TO, typename std::enable_if<!std::is_void<TO>::value && (std::is_const<E>::value == std::is_const<TO>::value), int>::type =0>
    shared_array<TO>
    castTo() const {
        if(this->_data && _type!=detail::CaptureBase<TO>::code) {
            detail::_throw_bad_cast(_type, detail::CaptureBase<TO>::code);
        }
        return shared_array<TO>(this->_data, static_cast<TO*>(this->_data.get()), this->_count);
    }

    template<typename TO, typename std::enable_if<std::is_void<TO>::value && (std::is_const<E>::value == std::is_const<TO>::value), int>::type =0>
    shared_array<TO>
    castTo() const {
        return *this;
    }

    // static_cast<TO>() to non-void, preserving const-ness
    template<typename TO, typename std::enable_if<!std::is_void<TO>::value && (std::is_const<E>::value == std::is_const<TO>::value), int>::type =0>
    shared_array<TO>
    castToUnsafe() const {
        return shared_array<TO>(this->_data, static_cast<TO*>(this->_data.get()), this->_count);
    }

    // static_cast<TO>() to void, preserving const-ness
    template<typename TO, typename std::enable_if<std::is_void<TO>::value && (std::is_const<E>::value == std::is_const<TO>::value), int>::type =0>
    shared_array<TO>
    castToUnsafe() const {
        // in reality this is either void -> void, or const void -> const void
        // aka. simple copy
        return *this;
    }

    template<typename TO, typename std::enable_if<!std::is_void<TO>::value && (std::is_const<E>::value == std::is_const<TO>::value), int>::type =0>
    shared_array<TO>
    convertTo() const {
        if(detail::CaptureBase<TO>::code==_type) {
            return castTo<TO>();
        } else {
            shared_array<TO> ret(this->_count);
            detail::convertArr(detail::CaptureBase<TO>::code, (void*)ret._data.get(),
                               _type, this->_data.get(),
                               this->_count);
            return ret;
        }
    }

    template<typename TO, typename std::enable_if<std::is_void<TO>::value && (std::is_const<E>::value == std::is_const<TO>::value), int>::type =0>
    shared_array<TO>
    convertTo() const {
        return castTo<TO>();
    }

    //! Provide options when rendering with std::ostream.
    detail::Limiter format() const {
        return detail::Limiter(this->_data.get(),
                               this->_count,
                               this->_type);
    }
};

// non-const -> const
template <typename SRC>
static inline
shared_array<typename std::add_const<typename SRC::value_type>::type>
freeze(SRC&& src)
{
    return src.freeze();
}

// change type, while keeping same const
template<typename TO, typename FROM>
static inline
shared_array<TO>
shared_array_static_cast(const shared_array<FROM>& src)
{
    return src.template castTo<TO>();
}

template<typename E>
std::ostream& operator<<(std::ostream& strm, const shared_array<E>& arr)
{
    return strm<<arr.format();
}

} // namespace pvxs

#endif // PVXS_SHAREDVECTOR_H
