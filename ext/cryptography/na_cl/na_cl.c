#include <ruby.h>
#include <crypto_secretbox.h>

#include <stdlib.h>

#define RB_CALLOC(p, len)                          \
    if (!((p) = calloc((len), sizeof((p)))))       \
        rb_raise(rb_eNoMemError, "NoMemoryError"); \

static VALUE cNaClError = 0;

static VALUE ruby_crypto_secretbox(
    VALUE self,
    VALUE message,
    VALUE nonce,
    VALUE key
) {
    VALUE ciphertext = 0;

    unsigned long long padlen  = 0;
    unsigned long long mlen    = 0;
    unsigned char      *m      = 0;
    unsigned char      *c      = 0;
    unsigned char      *n      = 0;
    unsigned char      *k      = 0;

    // Check_Type(message, T_STRING);
    // CHECK_STRING_LENGTH(nonce, crypto_secretbox_NONCEBYTES);
    // CHECK_STRING_LENGTH(key, crypto_secretbox_KEYBYTES);

    padlen = crypto_secretbox_ZEROBYTES;
    mlen   = RSTRING_LEN(message) + padlen;

    RB_CALLOC(m, mlen);
    RB_CALLOC(c, mlen);

    n = RSTRING_PTR(nonce);
    k = RSTRING_PTR(key);

    memcpy(m + padlen, RSTRING_PTR(message), RSTRING_LEN(message));

    if (!crypto_secretbox(c, m, mlen, n, k))
        ciphertext = rb_str_new(c + padlen, RSTRING_LEN(message));

    memset(m, 0, mlen);
    free(m);
    free(c);

    if (!ciphertext)
        rb_raise(cNaClError, "crypto_secretbox call failed");

    return ciphertext;
}

void Init_na_cl(void) {
    VALUE mCryptography = rb_define_module("Cryptography");
    VALUE mNaCl         = rb_define_module_under(mCryptography, "NaCl");

    rb_define_const(mNaCl, "SECRETBOX_NONCE_LEN", INT2FIX(crypto_secretbox_NONCEBYTES));
    rb_define_const(mNaCl, "SECRETBOX_KEY_LEN",   INT2FIX(crypto_secretbox_KEYBYTES));

    cNaClError = rb_define_class_under(mNaCl, "Error", rb_eStandardError);

    rb_define_module_function(mNaCl, "secretbox",      ruby_crypto_secretbox, 3);
    // rb_define_module_function(mNaCl, "secretbox_open", ruby__secretbox_open,  3);
}
