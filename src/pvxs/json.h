/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_JSON_H
#define PVXS_JSON_H

#include <string>

#include <stdlib.h>
#include <string.h>

#include <pvxs/version.h>

#ifdef PVXS_EXPERT_API_ENABLED

namespace pvxs {
class Value;

namespace json {

/** Parse JSON string
 *
 *  String must be complete JSON value, object, or sequence.
 *  Leading and trailing whitespace is allowed and ignored.
 *
 *  A character array must remain valid and unmodified for
 *  the lifetime of the Parse object referencing it.
 *
 *  @section jsonassign Assignment
 *
 *  When assigning JSON to Value, Value::from() is used.
 *  So the same range of implicit type conversions are attempted.
 *  eg.
 *
 *  @code
 *  Value top = TypeDef(TypeCode::Int32).build();
 *
 *  json::Parse("42").into(top);
 *  // equivalent to
 *  top.from(42);
 *
 *  and
 *
 *  json::Parse("\"42\"").into(top);
 *  // equivalent to
 *  top.from("42");
 *  @endcode
 *
 *  @since UNRELEASED
 */
struct Parse {
private:
    const char* base;
    size_t count;
public:

    //! Parse from Nil terminated string.
    inline
    Parse(const char *s) noexcept
        :base(s)
        ,count(s ? strlen(s) : 0u)
    {}
    //! Parse Character array without terminating Nil.
    inline
    constexpr Parse(const char *s, size_t c) noexcept
        :base(s)
        ,count(c)
    {}
    //! Parse from String
    inline
    Parse(const std::string& s) noexcept
        :base(s.c_str())
        ,count(s.size())
    {}

    /** Assign previously created Value from parsed string.
     *
     *  Provided Value may be modified on error.
     *
     *  @pre v.valid()
     *  @throws std::runtime_error on Parse error
     */
    PVXS_API
    void into(Value& v) const;

    /** Infer type from JSON value
     *
     *  Attempts to interpret the provided JSON into one of the supported Value types.
     *  The returned Value will be assigned from the parsed JSON.
     *
     *  @throws std::runtime_error on Parse or type inference error
     *
     *  Not all types may be inferred.  The currently supported inferences are:
     *
     *  - null -> TypeCode::Any
     *  - Boolean -> TypeCode::Bool
     *  - String -> TypeCode::String
     *  - Number -> TypeCode::Int64 or TypeCode::Float64 (if value appears to be real)
     *  - Mapping -> Struct
     *  - Sequence -> Array depending on element types.
     *    Currently only BoolA, Int64A, Float64A, or StringA may be inferred.
     */
    PVXS_API
    Value as() const;
};

} // namespace json
} // namespace pvxs

#endif // PVXS_EXPERT_API_ENABLED

#endif // PVXS_JSON_H
