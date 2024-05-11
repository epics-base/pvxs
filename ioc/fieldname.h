/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_FIELDNAME_H
#define PVXS_FIELDNAME_H

#include <ostream>
#include <string>

#include "fieldnamecomponent.h"

#define PADDING_CHARACTER  ' '
#define PADDING_WIDTH 15

namespace pvxs {
namespace ioc {

/**
 * Implements a group field as a delegate over a vector of group field components.
 * Therefore it can be used as a vector with size(), empty(), operator[], back() and swap() methods implemented.
 *
 * The group field is a vector of group field components.
 *
 */
class FieldName {
private:
public:
    FieldNameComponents fieldNameComponents;

    explicit FieldName(const std::string& fieldName);
    std::string to_string(size_t padLength = 0) const;

/**
 * Show this field name.  All components are shown as they were configured.
 *
 * @param suffix the suffix to add to the field name, defaults to none
 */
    void show(const std::string& suffix) const {
        printf("%s%s", to_string(PADDING_WIDTH - suffix.size()).c_str(), suffix.c_str());
    }

/**
 * swap delegate
 *
 * @param o
 */
    void swap(FieldName& o) {
        fieldNameComponents.swap(o.fieldNameComponents);
    }

/**
 * empty delegate
 *
 * @return
 */
    bool empty() const {
        return fieldNameComponents.empty() || (fieldNameComponents.size() == 1 && fieldNameComponents[0].name.empty());
    }

/**
 * size delegate
 *
 * @return
 */
    size_t size() const {
        return fieldNameComponents.size();
    }

/**
 * back() delegate
 *
 * @return
 */
    const FieldNameComponent& back() const {
        return fieldNameComponents.back();
    }

/**
 * operator[] delegate
 *
 * @param i
 * @return
 */
    const FieldNameComponent& operator[](size_t i) const {
        return fieldNameComponents[i];
    }

/**
 * Get the leaf field name of this field
 *
 * @return the leaf field name
 */
    const std::string& leafFieldName() const {
        return fieldNameComponents[fieldNameComponents.size() - 1].name;
    }

    friend std::ostream& operator<<(std::ostream&, const FieldName&);
};

std::ostream& operator<<(std::ostream&, const FieldName&);

} // pvxs
} // ioc

#endif //PVXS_FIELDNAME_H
