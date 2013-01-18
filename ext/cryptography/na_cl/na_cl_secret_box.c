#include "na_cl_secret_box.h"

static VALUE ruby_crypto_secretbox(
    VALUE self,
    VALUE message,
    VALUE nonce,
    VALUE key
) {
    VALUE ciphertext = 0;

    unsigned long long padlen  = crypto_secretbox_ZEROBYTES;
    unsigned long long mlen    = RSTRING_LEN(message) + padlen;
    unsigned char      *m      = 0;
    unsigned char      *c      = 0;
    unsigned char      *n      = RSTRING_PTR(nonce);
    unsigned char      *k      = RSTRING_PTR(key);

    RB_NACL_CHECK_STRING(message);
    RB_NACL_CHECK_STRING_LEN(key,   crypto_secretbox_KEYBYTES);
    RB_NACL_CHECK_STRING_LEN(nonce, crypto_secretbox_NONCEBYTES);

    RB_NACL_CALLOC(m, mlen);
    RB_NACL_CALLOC(c, mlen);

    memcpy(m + padlen, RSTRING_PTR(message), RSTRING_LEN(message));

    if (!crypto_secretbox(c, m, mlen, n, k))
        ciphertext = rb_str_new(c + padlen, RSTRING_LEN(message));

    RB_NACL_CFREE(m, mlen);
    RB_NACL_CFREE(c, mlen);

    if (!ciphertext)
        rb_raise(cNaClError, "crypto_secretbox call failed");

    return ciphertext;
}

void Init_na_cl_secret_box(VALUE mNaCl) {
    VALUE mSecretBox = rb_define_module_under(mNaCl, "SecretBox");

    rb_define_const(mSecretBox, "PRIMITIVE", ID2SYM(rb_intern(crypto_secretbox_PRIMITIVE)));
    rb_define_const(mSecretBox, "NONCE_LEN", INT2FIX(crypto_secretbox_NONCEBYTES));
    rb_define_const(mSecretBox, "KEY_LEN",   INT2FIX(crypto_secretbox_KEYBYTES));

    rb_define_module_function(mSecretBox, "secretbox",      ruby_crypto_secretbox, 3);
    // rb_define_module_function(mSecretBox, "secretbox_open", ruby__secretbox_open,  3);
}
