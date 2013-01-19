#include "na_cl_secret_box.h"

static VALUE ruby_crypto_secretbox(
    VALUE self,
    VALUE message,
    VALUE nonce,
    VALUE key
) {
    VALUE ciphertext = 0;

    unsigned long long mpadlen = crypto_secretbox_ZEROBYTES;
    unsigned long long cpadlen = crypto_secretbox_BOXZEROBYTES;
    unsigned long long mlen    = RSTRING_LEN(message) + mpadlen;
    unsigned char      *m      = 0;
    unsigned char      *c      = 0;
    unsigned char      *n      = RSTRING_PTR(nonce);
    unsigned char      *k      = RSTRING_PTR(key);

    RB_NACL_CHECK_STRING(message);
    RB_NACL_CHECK_STRING_LEN(key,   crypto_secretbox_KEYBYTES);
    RB_NACL_CHECK_STRING_LEN(nonce, crypto_secretbox_NONCEBYTES);

    RB_NACL_CALLOC(m, mlen, 0);
    RB_NACL_CALLOC(c, mlen, RB_NACL_CFREE(m, mlen));

    memcpy(m + mpadlen, RSTRING_PTR(message), RSTRING_LEN(message));

    if (!crypto_secretbox(c, m, mlen, n, k))
        ciphertext = rb_str_new(c + cpadlen, mlen - cpadlen);

    RB_NACL_CFREE(m, mlen);
    RB_NACL_CFREE(c, mlen);

    if (!ciphertext)
        rb_raise(cNaClError, "crypto_secretbox call failed");

    return ciphertext;
}

static VALUE ruby_crypto_secretbox_open(
    VALUE self,
    VALUE ciphertext,
    VALUE nonce,
    VALUE key
) {
    VALUE message = 0;

    unsigned long long mpadlen = crypto_secretbox_ZEROBYTES;
    unsigned long long cpadlen = crypto_secretbox_BOXZEROBYTES;
    unsigned long long clen    = RSTRING_LEN(ciphertext) + cpadlen;
    unsigned char      *m      = 0;
    unsigned char      *c      = 0;
    unsigned char      *n      = RSTRING_PTR(nonce);
    unsigned char      *k      = RSTRING_PTR(key);

    RB_NACL_CHECK_STRING(ciphertext);
    RB_NACL_CHECK_STRING_LEN(key,   crypto_secretbox_KEYBYTES);
    RB_NACL_CHECK_STRING_LEN(nonce, crypto_secretbox_NONCEBYTES);

    RB_NACL_CALLOC(m, clen, 0);
    RB_NACL_CALLOC(c, clen, RB_NACL_CFREE(m, clen));

    memcpy(c + cpadlen, RSTRING_PTR(ciphertext), RSTRING_LEN(ciphertext));

    if (!crypto_secretbox_open(m, c, clen, n, k))
        message = rb_str_new(m + mpadlen, clen - mpadlen);

    RB_NACL_CFREE(m, clen);
    RB_NACL_CFREE(c, clen);

    if (!message)
        rb_raise(cNaClError, "crypto_secretbox_open call failed");

    return message;
}

void Init_na_cl_secret_box(VALUE mNaCl) {
    VALUE mSecretBox = rb_define_module_under(mNaCl, "SecretBox");

    rb_define_const(mSecretBox, "PRIMITIVE", ID2SYM(rb_intern(crypto_secretbox_PRIMITIVE)));
    rb_define_const(mSecretBox, "NONCE_LEN", INT2FIX(crypto_secretbox_NONCEBYTES));
    rb_define_const(mSecretBox, "KEY_LEN",   INT2FIX(crypto_secretbox_KEYBYTES));

    rb_define_module_function(mSecretBox, "secretbox",      ruby_crypto_secretbox,      3);
    rb_define_module_function(mSecretBox, "secretbox_open", ruby_crypto_secretbox_open, 3);
}
