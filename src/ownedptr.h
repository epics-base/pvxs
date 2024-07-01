/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_OWNED_PTR_H_
#define PVXS_OWNED_PTR_H_

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "sqlite3.h"
#include "utilpvt.h"

namespace pvxs {

template <typename T>
struct ssl_delete;

template <typename T>
struct ssl_delete_all;

template <typename T>
struct file_delete;

template <typename T>
struct sqlite_delete;

#define DEFINE_SSL_DELETER_FOR_(TYPE)                    \
    template <>                                          \
    struct ssl_delete<TYPE> {                            \
        inline void operator()(TYPE *base_pointer) {     \
            if (base_pointer) TYPE##_free(base_pointer); \
        }                                                \
    }

#define DEFINE_SSL_DELETER_ALL_FOR_(TYPE)                    \
    template <>                                              \
    struct ssl_delete_all<TYPE> {                            \
        inline void operator()(TYPE *base_pointer) {         \
            if (base_pointer) TYPE##_free_all(base_pointer); \
        }                                                    \
    }

#define DEFINE_FILE_DELETER_FOR_(TYPE)               \
    template <>                                      \
    struct file_delete<TYPE> {                       \
        inline void operator()(TYPE *base_pointer) { \
            if (base_pointer) fclose(base_pointer);  \
        }                                            \
    }

#define DEFINE_SQLITE_DELETER_FOR_(TYPE)                   \
    template <>                                            \
    struct sqlite_delete<TYPE> {                           \
        inline void operator()(TYPE *base_pointer) {       \
            if (base_pointer) sqlite3_close(base_pointer); \
        }                                                  \
    }

#define DEFINE_SSL_STACK_DELETER_FOR_(TYPE)                     \
    template <>                                                 \
    struct ssl_delete<STACK_OF(TYPE)> {                         \
        inline void operator()(STACK_OF(TYPE) * base_pointer) { \
            if (base_pointer) sk_##TYPE##_free(base_pointer);   \
        }                                                       \
    }

#define DEFINE_SSL_INFO_STACK_DELETER_FOR_(TYPE)                               \
    template <>                                                                \
    struct ssl_delete<STACK_OF(TYPE)> {                                        \
        inline void operator()(STACK_OF(TYPE) * base_pointer) {                \
            if (base_pointer) sk_##TYPE##_pop_free(base_pointer, TYPE##_free); \
        }                                                                      \
    }

#define DEFINE_OPENSSL_DELETER_FOR_(TYPE)                 \
    template <>                                           \
    struct ssl_delete<TYPE> {                             \
        inline void operator()(TYPE *base_pointer) {      \
            if (base_pointer) OPENSSL_free(base_pointer); \
        }                                                 \
    }

DEFINE_FILE_DELETER_FOR_(FILE);
DEFINE_SQLITE_DELETER_FOR_(sqlite3);
DEFINE_OPENSSL_DELETER_FOR_(char);
DEFINE_SSL_DELETER_FOR_(ASN1_OBJECT);
DEFINE_SSL_DELETER_FOR_(ASN1_TIME);
DEFINE_SSL_DELETER_FOR_(BIO);
DEFINE_SSL_DELETER_ALL_FOR_(BIO);
DEFINE_SSL_DELETER_FOR_(EVP_MD_CTX);
DEFINE_SSL_DELETER_FOR_(EVP_PKEY);
DEFINE_SSL_DELETER_FOR_(EVP_PKEY_CTX);
DEFINE_SSL_DELETER_FOR_(OCSP_REQUEST);
DEFINE_SSL_DELETER_FOR_(OCSP_RESPONSE);
DEFINE_SSL_DELETER_FOR_(OCSP_BASICRESP);
DEFINE_SSL_DELETER_FOR_(OSSL_LIB_CTX);
DEFINE_SSL_DELETER_FOR_(PKCS12);
DEFINE_SSL_DELETER_FOR_(SSL);
DEFINE_SSL_DELETER_FOR_(SSL_CTX);
DEFINE_SSL_DELETER_FOR_(X509);
DEFINE_SSL_DELETER_FOR_(X509_ATTRIBUTE);
DEFINE_SSL_DELETER_FOR_(X509_EXTENSION);
DEFINE_SSL_DELETER_FOR_(X509_NAME);
DEFINE_SSL_DELETER_FOR_(X509_STORE);
DEFINE_SSL_DELETER_FOR_(X509_STORE_CTX);
DEFINE_SSL_INFO_STACK_DELETER_FOR_(X509_INFO);
DEFINE_SSL_STACK_DELETER_FOR_(X509);
DEFINE_SSL_STACK_DELETER_FOR_(X509_ATTRIBUTE);

#undef DEFINE_FILE_DELETER_FOR_
#undef DEFINE_SSL_DELETER_FOR_
#undef DEFINE_SSL_STACK_DELETER_FOR_

/**
 * @class OwnedPtr
 * @brief A smart pointer class that owns and manages the lifetime of a
 * dynamically allocated object.
 *
 * OwnedPtr is a derived class of std::unique_ptr<T, D>, providing additional
 * functionality for managing the lifetime of dynamically allocated objects. It
 * is similar to std::unique_ptr, but with a few modifications. Notably it
 * allows for acquiring a new managed object (and this releasing the currently
 * managed one). This is used when a function takes a pointer to a place to
 * store a dynamically generated object that we want to manage.  See below for
 * more details.
 *
 * @tparam T The type of the object to manage.
 * @tparam D The deleter type.
 */
template <typename T, typename D>
struct OwnedPtr : public std::unique_ptr<T, D> {
    typedef std::unique_ptr<T, D> base_t;

    constexpr OwnedPtr() {}

    constexpr OwnedPtr(std::nullptr_t np) : base_t(np) {}
    explicit OwnedPtr(const char *file, int line, T *ptr) : base_t(ptr) {
        if (!*this) throw loc_bad_alloc(file, line);
    }
    explicit OwnedPtr(T *ptr, bool fail_on_null = true) : base_t(ptr) {
        if (fail_on_null && !*this)
            throw loc_bad_alloc(__FILE__, __LINE__);
    }

    // When we have a function that sets a given argument pointer to a pointer
    // to point to some stored value (T) that we don't manage on return, but we
    // want to store this new pointed to pointer in the OwnedPtr. (e.g. void
    // someFunction(T** pp_result) In this case we need to replace the pointer
    // value of the OwnedPtr with the pointed to by the returned value. To do
    // this for OwnedPtr variable `x` do the following:
    //   OwnedPtr<T> x;
    //   someFunction(x.acquire());
    struct Acquisition {
        base_t *o;
        T *ptr = nullptr;

        operator T **() { return &ptr; }
        constexpr Acquisition(base_t *o) : o(o) {}
        constexpr Acquisition(OwnedPtr<T, ssl_delete<T>> *o) : o(o) {}
        ~Acquisition() { o->reset(ptr); }
    };

    Acquisition acquire() { return Acquisition{this}; }
};

// Use OwnedPtr to define a manager for a SSL object with all the custom SSL
// deleters defined above
template <typename T>
using ossl_ptr = OwnedPtr<T, ssl_delete<T>>;

template <typename T>
using ossl_ptr_all = OwnedPtr<T, ssl_delete_all<T>>;

using file_ptr = OwnedPtr<FILE, file_delete<FILE>>;

using sql_ptr = OwnedPtr<sqlite3, sqlite_delete<sqlite3>>;

/**
 * An SSL Owned pointer.  This is a managed shared pointer that
 * will use SSL deleters to delete the managed object when the last reference to
 * them goes out of scope and the manager is being deleted.
 *
 * Uses the DEFINE_SSL_DELETER_FOR_ macros to define the custom deleters for any
 * class you want to manage in this way.  e.g. `DEFINE_SSL_DELETER_FOR_(X509)`
 *
 * Example usage:
 * @code
 *   // create a managed X.509 certificate with a constructor
 *   ossl_shared_ptr<X509> cert(PEM_read_bio_X509(bio.get(), NULL, NULL, NULL));
 * @endcode
 *
 * Note: Acquisition does not make sense for shared objects because you should
 * never change the object pointed to by the shared object manager.  That's the
 * whole point.
 *
 * @tparam T SSL the type to manage
 * @tparam D the deleter, either your custom deleter or defaults to
 *           the custom SSL deleters defined above
 */
template <typename T, typename D = ssl_delete<T>>
class ossl_shared_ptr : public std::shared_ptr<T> {
   public:
    using base_t = std::shared_ptr<T>;

    ossl_shared_ptr() = default;
    ossl_shared_ptr(std::nullptr_t np) : base_t(np) {}
    explicit ossl_shared_ptr(const char *file, int line, T *ptr) : base_t(ptr, D()) {
        if (!*this) throw loc_bad_alloc(file, line);
    }
    explicit ossl_shared_ptr(T *ptr, D d = D()) : base_t(ptr, d) {
        if (!*this) throw loc_bad_alloc(__FILE__, __LINE__);
    }
};

}  // namespace pvxs
#endif  // PVXS_OWNED_PTR_H_
