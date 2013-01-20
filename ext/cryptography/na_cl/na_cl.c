#include "na_cl.h"
#include "na_cl_hash_sha512.h"
#include "na_cl_secret_box.h"

VALUE cNaClError = 0;

void Init_na_cl(void) {
    VALUE mCryptography = rb_define_module("Cryptography");
    VALUE mNaCl         = rb_define_module_under(mCryptography, "NaCl");

    cNaClError = rb_define_class_under(mNaCl, "Error", rb_eStandardError);

    Init_na_cl_hash_sha512(mNaCl);
    Init_na_cl_secret_box(mNaCl);
}
