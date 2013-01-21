#include "na_cl_auth_hmacsha256.h"

static VALUE ruby_crypto_auth_hmacsha256(
    VALUE self,
    VALUE message,
    VALUE key
) {
    VALUE authenticator = 0;

    unsigned long long mlen = RSTRING_LEN(message);
    unsigned long long klen = crypto_auth_hmacsha256_KEYBYTES;
    unsigned long long alen = crypto_auth_hmacsha256_BYTES;
    unsigned char      *m   = RSTRING_PTR(message);
    unsigned char      *k   = RSTRING_PTR(key);
    unsigned char      *a   = 0;

    RB_NACL_CHECK_STRING(message);
    RB_NACL_CHECK_STRING_LEN(key, klen);

    RB_NACL_CALLOC(a, alen, (void) 0);

    if (!crypto_auth_hmacsha256(a, m, mlen, k))
        authenticator = rb_str_new(a, alen);

    RB_NACL_CFREE(a, alen);

    if (!authenticator)
        rb_raise(cNaClError, "crypto_auth_hmacsha256 call failed");

    return authenticator;
}

static VALUE ruby_crypto_auth_hmacsha256_verify(
    VALUE self,
    VALUE authenticator,
    VALUE message,
    VALUE key
) {
    unsigned long long mlen = RSTRING_LEN(message);
    unsigned long long klen = crypto_auth_hmacsha256_KEYBYTES;
    unsigned long long alen = crypto_auth_hmacsha256_BYTES;
    unsigned char      *m   = RSTRING_PTR(message);
    unsigned char      *k   = RSTRING_PTR(key);
    unsigned char      *a   = RSTRING_PTR(authenticator);

    RB_NACL_CHECK_STRING(message);
    RB_NACL_CHECK_STRING_LEN(key,           klen);
    RB_NACL_CHECK_STRING_LEN(authenticator, alen);

    if (!crypto_auth_hmacsha256_verify(a, m, mlen, k))
        return Qtrue;

    return Qfalse;
}

void Init_na_cl_auth_hmacsha256(VALUE module) {
    VALUE mAuth       = rb_define_module_under(module, "Auth");
    VALUE mHMACSHA256 = rb_define_module_under(mAuth,  "HMACSHA256");

    rb_define_const(mHMACSHA256, "PRIMITIVE", ID2SYM(rb_intern("hmacsha256")));
    rb_define_const(mHMACSHA256, "KEY_LEN",   INT2FIX(crypto_auth_hmacsha256_KEYBYTES));
    rb_define_const(mHMACSHA256, "HMAC_LEN",  INT2FIX(crypto_auth_hmacsha256_BYTES));

    rb_define_module_function(mHMACSHA256, "auth",        ruby_crypto_auth_hmacsha256, 2);
    rb_define_module_function(mHMACSHA256, "auth_verify", ruby_crypto_auth_hmacsha256_verify, 3);
}
