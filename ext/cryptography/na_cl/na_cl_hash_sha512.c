#include "na_cl_hash_sha512.h"

static VALUE ruby_crypto_hash_sha512(
     VALUE self,
     VALUE message
) {
    VALUE hash = 0;

    unsigned long long mlen = RSTRING_LEN(message);
    unsigned long long hlen = crypto_hash_sha512_BYTES;
    unsigned char      *m   = 0;
    unsigned char      *h   = 0;

    RB_NACL_CHECK_STRING(message);

    RB_NACL_CALLOC(m, mlen, 0);
    RB_NACL_CALLOC(h, hlen, RB_NACL_CFREE(m, mlen));

    memcpy(m, RSTRING_PTR(message), mlen);

    if (!crypto_hash_sha512(h, m, mlen))
        hash = rb_str_new(h, hlen);

    RB_NACL_CFREE(m, mlen);
    RB_NACL_CFREE(h, hlen);

    if (!hash)
        rb_raise(cNaClError, "crypto_secretbox_hash_sha512 call failed");

    return hash;
}

void Init_na_cl_hash_sha512(VALUE mNaCl) {
    VALUE mHash   = rb_define_module_under(mNaCl, "Hash");
    VALUE mSHA512 = rb_define_module_under(mHash, "SHA512");

    rb_define_const(mSHA512, "PRIMITIVE", ID2SYM(rb_intern("sha512")));
    rb_define_const(mSHA512, "HASH_LEN",  INT2FIX(crypto_hash_sha512_BYTES));

    rb_define_module_function(mSHA512, "digest", ruby_crypto_hash_sha512, 1);
}
