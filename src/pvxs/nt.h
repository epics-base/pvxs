/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_NT_H
#define PVXS_NT_H

#include <pvxs/version.h>
#include <pvxs/data.h>

struct epicsTimeStamp; // epicsTime.h

namespace pvxs {
namespace nt {

/** The time_t struct
 *
 * @code
 * // equivalent
 * struct time_t {
 *     int64_t secondsPastEpoch;
 *     int32_t nanoseconds;
 *     int32_t userTag;
 * };
 * @endcode
 * @since 0.1.4
 */
struct TimeStamp {
    PVXS_API
    TypeDef build();
};

/** The alarm_t struct
 *
 * @code
 * // equivalent
 * struct alarm_t {
 *     int32_t severity;
 *     int32_t status;
 *     string message;
 * };
 * @endcode
 * @since 0.1.4
 */
struct Alarm {
    PVXS_API
    TypeDef build();
};

/** A scalar, or array of scalars, and meta-data
 *
 * @code
 * auto def = pvxs::nt::NTScalar{TypeCode::Float64}.build();
 * def += {
 *      Member(TypeCode::String, "myspecial"),
 * };
 * auto value = def.create(); // instantiate a Value
 * @endcode
 */
struct NTScalar {
    //! Type of the ".value" field.
    TypeCode value;
    //! Include display (range) meta-data
    bool display;
    //! Include control (range) meta-data
    bool control;
    //! Include alarm (range) meta-data
    bool valueAlarm;

    constexpr
    NTScalar(TypeCode value = TypeCode::Float64,
             bool display = false,
             bool control = false,
             bool valueAlarm = false)
        :value(value), display(display), control(control), valueAlarm(valueAlarm)
    {}

    //! A TypeDef which can be appended
    PVXS_API
    TypeDef build() const;
    //! Instantiate
    inline Value create() const {
        return build().create();
    }
};

/** An enumerated value (choice from a list of strings)
 *
 * @since 0.1.5
 */
struct NTEnum {
    //! A TypeDef which can be appended
    PVXS_API
    TypeDef build() const;
    //! Instantiate
    inline Value create() const {
        return build().create();
    }
};

/** The areaDetector inspired N-dimension array/image container.
 *
 * @code
 * auto def = pvxs::nt::NTNDArray{}.build();
 * auto value = def.create(); // instantiate a Value
 * @endcode
 */
struct NTNDArray {
    //! A TypeDef which can be appended
    PVXS_API
    TypeDef build() const;
    //! Instantiate
    inline Value create() const {
        return build().create();
    }
};

class PVXS_API NTURI {
    TypeDef _def;
public:
    NTURI(std::initializer_list<Member> mem);

    //! A TypeDef which can be appended
    inline
    TypeDef build() const { return _def; }

    //! Instantiate
    inline Value create() const {
        return build().create();
    }

private:
    template<typename Iter, typename T, typename ...Args>
    static
    void _assign(Iter& cur, const Iter& end, const T& v, Args... args)
    {
        if(cur==end)
            throw std::logic_error("Too many arguments");
        (*cur).template from<T>(v);
        ++cur;
        _assign(cur, end, args...);
    }
    template<typename Iter>
    static
    void _assign(Iter& cur, const Iter& end)
    {}
public:

    template<typename ...Args>
    Value call(Args... args) const {
        auto val(create());
        auto iterable = val["query"].ichildren();
        auto it = iterable.begin();
        _assign(it, iterable.end(), args...);
        return val;
    }
};

}} // namespace pvxs::nt

#endif // PVXS_NT_H
