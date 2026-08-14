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
//! [`obj_dat`] ports the NID lookup.
pub mod obj_dat;
