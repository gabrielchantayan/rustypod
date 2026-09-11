//! The OpenSSL copy Apple vendored into retailOS.
//!
//! Its object-identifier database sits in 0x0805e000..0x08064000 —
//! `OBJ_obj2nid` @ 0x0805f074, `OBJ_obj2txt` @ 0x0805f110,
//! `OBJ_ln2nid` @ 0x0805edc4, `OBJ_sn2nid` @ 0x0805f2c4, all sharing
//! the generic `OBJ_bsearch` @ 0x0805eb04 — with the `lhash` machinery
//! it registers runtime objects in over in 0x082d7xxx
//! (`lh_retrieve` @ 0x082d7e0c, `getrn` @ 0x080e82cc).
//!
//! Identifying strings, binary-verified: `"ssl2-md5"` / `"ssl3-md5"` /
//! `"ssl3-sha1"` / `"RSA-SHA1"` @ 0x0805f574 and `"signature has
//! problems, re-make with post SSLeay045"` @ 0x08063268. Apple's own
//! arc shows up as `"1.3.6.1.4.1.63.42"` / `"iPod Serial Number"`
//! @ 0x080782bc.
//!
//! The proprietary AES-like cipher cluster hangs off here too:
//! [`cipher_name`] ports its name gate, which accepts only the
//! `"STANDARD"` cipher (`s_STANDARD` @ 0x0802e0c4).
//!
//! [`obj_dat`] ports the NID lookup.
//!
//! [`digest_init`] is NOT OpenSSL: it ports the init of Apple's
//! proprietary MBA-obfuscated digest (custom IVs, 16/20-byte states)
//! feeding the HMAC machinery in 0x082f0xxx..0x0835xxxx.
//!
//! [`evp_digest_update`] IS OpenSSL: the three-word `EVP_DigestUpdate`
//! @ 0x0804a728, one of four EVP entry points sharing the assertion
//! string `"ctx->digest->md_size <= EVP_MAX_MD_SIZE"` @ 0x0804a694.
//! [`evp_md_ctx_cleanup`] ports `EVP_MD_CTX_cleanup` @ 0x0804ac2c: it
//! dispatches descriptor teardown, conditionally releases `md_data`, and
//! clears the 16-byte context.
//! [`evp_pkey`] ports `EVP_PKEY_free` @ 0x0804ae6c, the reference-
//! counted destructor of the p_lib.c `EVP_PKEY` wrapper (its
//! constructor/type-normalizer/size siblings sit at 0x0804aeb4 /
//! 0x0804af30 / 0x0804af10).
//!
//! [`bn_num_bits`] ports the `BIGNUM` bit-length query from bn_lib.c
//! (the 0x0803d800..0x08041000 bignum cluster: `d`/`top`/`dmax`/`neg`/
//! `flags` layout, RSA-1024 `== 0x400` caller in the X.509 chain walk).
//! [`bn_ucmp`] ports its unsigned magnitude comparison from the same
//! file.
pub mod add_lock;
pub mod bio_printf;
pub mod bio_snprintf;
pub mod bio_ctrl;
pub mod bio_copy_next_retry;
pub mod bn_num_bits;
pub mod bn_ucmp;
pub mod cipher_name;
pub mod digest_init;
pub mod evp_digest_init_ex;
pub mod evp_digest_final_ex;
pub mod evp_digest_update;
pub mod evp_md_ctx_cleanup;
pub mod evp_sha1;
pub mod evp_pkey;
pub mod obj_dat;
pub mod xor_f6_in_place;
pub mod standard_cipher_table_three;
pub mod x509v3_add_value;
pub mod standard_cipher_table_four;
pub mod standard_cipher_table_five;
pub mod standard_cipher_table_six;
