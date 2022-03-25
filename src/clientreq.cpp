/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <stdexcept>
#include <map>
#include <string>

#include <pvxs/version.h>
#include <pvxs/client.h>
#include "dataimpl.h"
#include "utilpvt.h"

namespace pvxs {
namespace client {
namespace detail {

struct CommonBase::Req {
    Value pvRequest;

    Member fields;

    std::map<std::string, Value> options;

    Req()
        :fields(TypeCode::Struct, "field")
    {}
};

CommonBase::~CommonBase() {}

void CommonBase::_rawRequest(const Value& raw)
{
    if(!req)
        req = std::make_shared<Req>();
    req->pvRequest = raw;
}
void CommonBase::_field(const std::string& s)
{
    if(!req)
        req = std::make_shared<Req>();

    size_t idx=0u;

    decltype (req->fields) *cur = &req->fields;

    while(idx<s.size()) {
        auto sep = s.find_first_of('.', idx);

        if(sep==idx) {
            idx++;
            continue;

        }
        std::string child;

        if(sep==std::string::npos) {
            child = s.substr(idx);
            idx = sep;

        } else {
            child = s.substr(idx, sep-idx);
            idx = sep+1;
        }

        size_t idx = cur->children.size();
        for(auto x : range(cur->children.size())) {
            auto& c = cur->children[x];
            if(c.name==child) {
                idx = x;
                break;
            }
        }

        if(idx==cur->children.size()) {
            cur->addChild(Member(TypeCode::Struct, child));
        }

        cur = &cur->children[idx];
    }
}

void CommonBase::_record(const std::string& key, const void* value, StoreType vtype)
{
    if(!req)
        req = std::make_shared<Req>();

    req->options[key] = Value::Helper::build(value, vtype);
}

struct PVRParser
{
    /* Grammar
     *
     * PVR :
     *     |  ENT
     *     |  ENT PVR
     * ENT : FIELD | RECORD | name
     * FIELD : "field" '(' FIELD_LIST ')'
     * RECORD : "record" '[' OPTIONS '}'
     * FIELD_LIST :
     *            | name
     *            | FIELD_LIST ',' name
     * OPTIONS ->
     *            | name '=' name
     *            | OPTIONS ',' name '=' name
     */
    enum token_t {
        // terminals
        comma = ',',
        lp = '(',
        rp = ')',
        lb = '[',
        rb = ']',
        eq = '=',
        field = 'f',
        record = 'r',
        name = 'n',
        tEOF = -1,
    };

    token_t lextok = tEOF;
    std::string lexval;

    const char* input;

    CommonBase& target;

    PVRParser(CommonBase& target, const char* input)
        :input(input)
        ,target(target)
    {}

    void lex()
    {
        lexval.clear();

        if(!*input) {
            lextok = tEOF;
            return;
        }

        // skip leading whitespace
        while(' '==*input)
            input++;

        switch(*input) {
        case '[':
        case ']':
        case '(':
        case ')':
        case ',':
        case '=':
            lextok = token_t(*input++);
            return;
        default:
            break;
        }

        auto isname = [](char c) {
            return ((c>='a' && c<='z'))
                    || ((c>='A' && c<='Z'))
                    || ((c>='0' && c<='9'))
                    || c=='.' || c=='_';
        };

        auto start = input;
        while(isname(*input))
            input++;

        if(start==input)
            throw std::runtime_error("invalid character near: "+std::string(start));

        lexval = std::string(start, input-start);

        if(lexval=="field") {
            lextok = field;

        } else if(lexval=="record") {
            lextok = record;

        } else {
            lextok = name;
        }
    }

    void parse()
    {
        while(input) {
            auto start = input;

            lex();

            if(lextok==tEOF) {
                break;

            } else if(lextok==field) {
                lex();
                if(lextok!=lp)
                    throw std::runtime_error(SB()<<"Expected field( at "<<start);
                parse_fields();
                if(lextok!=rp)
                    throw std::runtime_error(SB()<<"Expected field(...) at "<<start);

            } else if(lextok==record) {
                lex();
                if(lextok!=lb)
                    throw std::runtime_error(SB()<<"Expected record[ at "<<start);
                parse_options();
                if(lextok!=rb)
                    throw std::runtime_error(SB()<<"Expected record[...] at "<<start);

            } else if(lextok==name) {
                // short-hand for field(name)

                if(lexval=="field" || lexval=="record")
                    std::logic_error("pvReq regex alternative order logic error");

                target._field(lexval);

            } else {
                throw std::runtime_error(SB()<<"Expected field|record|name|EOF at "<<start<<" not token="<<lextok<<"("<<lexval<<")");
            }
        }
    }

    void parse_fields()
    {
        do {
            lex();
            if(lextok==name) {
                target._field(lexval);
                continue;
            } else if(lextok==comma) {
                continue;
            } else {
                break; // caller signals error
            }
        } while(true);
    }

    void parse_options()
    {
        lex();
        do {
            auto start = input;
            std::string key, val;

            if(lextok==rb) {
                break;

            } else if(lextok==name) {
                key = lexval;

                bool ok = true;
                lex();
                ok &= lextok==eq;
                lex();
                ok &= lextok==name;
                val = lexval;

                if(!ok) {
                    throw std::runtime_error(SB()<<"Expected K=V or K=V,... at "<<start);
                }
                target._record(key, &val, StoreType::String);

                lex();
                if(lextok==comma) {
                    lex();
                    continue;
                } else {
                    break; // caller signals error
                }

            } else {
                break; // caller signals error
            }

        } while(true);
    }
};

void CommonBase::_parse(const std::string& req)
{
    if(!req.empty())
        PVRParser(*this, req.c_str()).parse();
}

Value CommonBase::_buildReq() const
{
    if(req && req->pvRequest) {
        return req->pvRequest;

    } else if(!req) {
        using namespace pvxs::members;
        return TypeDef(TypeCode::Struct, {
                           Struct("field", {}),
                       }).create();

    } else {
        using namespace pvxs::members;

        auto def = TypeDef(TypeCode::Struct, {
                                req->fields,
                            });

        if(!req->options.empty()) {
            std::vector<Member> opts;
            for(auto& pair : req->options) {
                opts.push_back(TypeDef(pair.second).as(pair.first));
            }
            def += {Struct("record", {Struct("_options", opts)})};
        }

        auto inst = def.create();

        auto opt = inst["record._options"];
        for(auto& pair : req->options) {
            opt[pair.first].assign(pair.second);
        }

        return inst;
    }
}

} // namespace detail
} // namespace client
} // namespace pvxs
