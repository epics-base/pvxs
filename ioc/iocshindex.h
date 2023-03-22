/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_IOCSHINDEX_H
#define PVXS_IOCSHINDEX_H

#include <cstdlib>

// index_sequence from:
//http://stackoverflow.com/questions/17424477/implementation-c14-make-integer-sequence

namespace pvxs {
namespace ioc {

template<std::size_t ...I>
struct index_sequence {
    using type = index_sequence;
    using value_type = std::size_t;
    static constexpr std::size_t size() {
        return sizeof ... (I);
    }
};

template<typename Seq1, typename Seq2>
struct concat_sequence;

template<std::size_t ... I1, std::size_t ... I2>
struct concat_sequence<index_sequence<I1 ...>, index_sequence<I2 ...> >
        : public index_sequence<I1 ...,
                                (sizeof ... (I1) + I2) ...> {
};

template<std::size_t I>
struct make_index_sequence : public concat_sequence<typename make_index_sequence<I / 2>::type,
                                                    typename make_index_sequence<I - I / 2>::type> {
};

template<>
struct make_index_sequence<0> : public index_sequence<> {
};

template<>
struct make_index_sequence<1> : public index_sequence<0> {
};

}
}
#endif //PVXS_IOCSHINDEX_H
