/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_FIELDNAMECOMPONENT_H
#define PVXS_FIELDNAMECOMPONENT_H

#include <string>
#include <vector>
#include <utility>
#include <cstdint>

namespace pvxs {
namespace ioc {

/**
 * A field component.  Fields can be made up of any number of components.  e.g. a.b[1].c
 * Each of the components (a, b, or c) are represented by a component.
 * isArray() determines whether this component is an array of structures or not, by looking
 * at the index field.  If it is -1 then its not an array of structures otherwise it is a simple scalar
 * or an array of scalars.
 *
 * An array of structures is an array whose elements are themselves structures.
 */
class FieldNameComponent {
/**
 * Construct an simple Field name component holder.  -1 means not a structure array
 */
    FieldNameComponent()
            :index((uint32_t)-1) {
    }
public:
    // the name of this field component
    std::string name;
    // If this is a structure array then this is the index that is referred to by this field name component.
    // -1 means that it is not a structure array
    uint32_t index;

/**
 * Construct an Field Name Component from the given name and index
 *
 * @param name the field name component
 * @param index the index of the field name component if the component is an array of structures.  Note
 *              that index will only ever be specified in configuration if this is an array of structures.
 */
    explicit FieldNameComponent(std::string name, uint32_t index = (uint32_t)-1)
            :name(std::move(name)), index(index) {
    }

/**
 * Is this an array of structures.  Determines whether this component is an array of structures or not, by looking
 * at the index field.  If it is -1 then its not an array of structures otherwise it is a simple scalar
 * or an array of scalars
 *
 * @return true if this is an array of structures
 */
    bool isArray() const {
        return index != (uint32_t)-1;
    }

};

typedef std::vector<FieldNameComponent> FieldNameComponents;

} // pvxs
} // ioc

#endif //PVXS_FIELDNAMECOMPONENT_H
