#include <ruby.h>
#include <crypto_auth_hmacsha512256.h>
#include <crypto_hash_sha512.h>
#include <crypto_secretbox.h>

#include <stdlib.h>

#ifndef _NA_CL_H
#define _NA_CL_H

#define RB_NACL_CHECK_STRING(str) \
    Check_Type((str), T_STRING)

#define RB_NACL_CHECK_STRING_LEN(str, len)                                  \
    do {                                                                    \
        RB_NACL_CHECK_STRING((str));                                        \
        if ((unsigned long long)RSTRING_LEN((str)) != (len))                \
            rb_raise(rb_eArgError, #str " must be %llu bytes long", (len)); \
    } while (0)

#define RB_NACL_CALLOC(p, len, block)              \
    if (!((p) = calloc((len), sizeof((p))))) {     \
        block;                                     \
        rb_raise(rb_eNoMemError, "NoMemoryError"); \
    }

#define RB_NACL_CFREE(p, len)  \
    if ((p)) {                 \
        memset(p, 0, len);     \
        free(p);               \
    }

extern VALUE cNaClError;

#endif _NA_CL_H
