/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <stdexcept>
#include <map>
#include <string>
#include <regex>

#include <pvxs/version.h>
#include <pvxs/client.h>
#include "utilpvt.h"

namespace pvxs {
namespace client {
namespace detail {

struct CommonBase::Req {
    Value pvRequest;

    Member fields;

    std::map<std::string, Value> options;
    Member record;

    Req()
        :fields(TypeCode::Struct, "fields")
        ,record(TypeCode::Struct, "record", {
                Member(TypeCode::Struct, "_options")
        })
    {}
};

CommonBase::~CommonBase() {}

void CommonBase::_rawRequest(Value&& raw)
{
    if(!req)
        req = std::make_shared<Req>();
    req->pvRequest = std::move(raw);
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

    TypeCode base;
    switch (vtype) {
    case StoreType::Bool:     base = TypeCode::Bool; break;
    case StoreType::Integer:  base = TypeCode::Int64; break;
    case StoreType::UInteger: base = TypeCode::UInt64; break;
    case StoreType::Real:     base = TypeCode::Float64; break;
    case StoreType::String:   base = TypeCode::String; break;
    default:
        throw std::logic_error("record() only support scalar values");
    }

    Value v = TypeDef(base).create();
    v.copyIn(value, vtype);

    if(req->options.find(key)==req->options.end()) {
        req->record.children[0].addChild(Member(base, key));
    }

    req->options[key] = std::move(v);
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

    std::regex lexer;
    token_t lextok = tEOF;
    std::string lexval;

    const char* input;

    CommonBase& target;

    PVRParser(CommonBase& target, const char* input)
        :lexer(R"re((?:([\[\],\(\)=])|([a-zA-Z0-9_.]+))(.*))re")
        //   (?: literal | name ) remaining
        //          \1       \2      \3
        ,input(input)
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

        std::cmatch M;
        std::regex_match(input, M, lexer);
        if(M.empty())
            throw std::runtime_error("invalid charactor near: "+std::string(input));

        if(M[1].matched) {
            lextok = token_t(input[M.position(1)]);

        } else if(M[2].matched) {
            lexval = M[2].str();
            if(lexval=="field") {
                lextok = field;

            } else if(lexval=="record") {
                lextok = record;

            } else {
                lextok = name;
            }

        } else {
            throw std::logic_error("pvRequest lexer logic error invalid state");
        }

        if(!M[3].matched)
            throw std::logic_error("pvRequest lexer logic error no continuation");

        input += M.position(3);
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

Value CommonBase::_build() const
{
    if(!req) {
        using namespace pvxs::members;
        return TypeDef(TypeCode::Struct, {
                           Struct("field", {}),
                       }).create();

    } else if(req->pvRequest) {
        return req->pvRequest;

    } else {
        auto inst = TypeDef(TypeCode::Struct, {
                                req->fields,
                                req->record,
                            }).create();

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
