/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <string>
#include <sstream>
#include <stdexcept>
#include <cstdlib>

#include "fieldname.h"
#include "utilpvt.h"

namespace pvxs {
namespace ioc {

/**
 * Construct a Group field name from a field name string.  The string is a sequence of components separated by
 * periods each of which may be optionally followed by an array specifier. e.g. a.b[1].c.
 *
 * This constructor breaks the string on periods and stores each component in the fieldNameComponents member,
 * while extracting the array reference where specified.
 * @param fieldName
 */
FieldName::FieldName(const std::string& fieldName) {
    if (!fieldName.empty()) {
        // Split field name on periods
        std::istringstream splitter(fieldName);
        std::string fieldNamePart;
        while (std::getline(splitter, fieldNamePart, '.')) {
            if (fieldNamePart.empty()) {
                throw std::runtime_error("Empty field component in: " + fieldName);
            }

            // If this is an array reference then extract the index
            auto endArraySpecifier = fieldNamePart.size();
            if (fieldNamePart[endArraySpecifier - 1] == ']') {
                const size_t startArraySpecifier = fieldNamePart.find_last_of('[');
                if (startArraySpecifier == std::string::npos) {
                    throw std::runtime_error("Invalid field array sub-script in : " + fieldName);
                }

                auto arrayIndex = fieldNamePart.substr(startArraySpecifier + 1);
                long index = 0;
                char* endScan;
                index = strtol(arrayIndex.c_str(), &endScan, 10);
                if (*endScan != ']') {
                    throw std::runtime_error("Invalid field array sub-script in : " + fieldName);
                }

                fieldNameComponents.emplace_back(fieldNamePart.substr(0, startArraySpecifier), index);
            } else {
                // Otherwise this is a regular field part
                fieldNameComponents.emplace_back(fieldNamePart);
            }
        }

        // If empty then throw an error
        if (fieldNameComponents.empty()) {
            throw std::runtime_error("Empty field name");
        }
    }
}

/**
 * Convert this group field name to a string.
 *
 * @param padLength the amount of padding to add, defaults to none
 */
std::string FieldName::to_string(size_t padLength) const {
    std::ostringstream strm;
    strm<<(*this);
    auto sofar(strm.tellp());
    if(sofar >=0 && size_t(sofar) < padLength) {
        for(auto i : range(padLength - size_t(sofar))) {
            (void)i;
            strm.put(PADDING_CHARACTER);
        }
    }
    return strm.str();
}

std::ostream& operator<<(std::ostream& strm, const FieldName& name)
{
    if (name.fieldNameComponents.empty()) {
        strm<<"/";
    } else {
        bool first = true;
        for (const auto& fieldNameComponent: name.fieldNameComponents) {
            if (!first) {
                strm.put('.');
            } else {
                first = false;
            }
            strm<<fieldNameComponent.name;
            if (fieldNameComponent.isArray()) {
                strm<<'['<<fieldNameComponent.index<<']';
            }
        }
    }
    return strm;
}

} // pvxs
} // ioc
