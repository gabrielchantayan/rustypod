//! `identified_vtable_flagged_pair_construct` — original: `FUN_08205a38` @
//! **0x08205a38** (52 instruction bytes plus the four-byte literal-pool
//! vtable word at 0x08205a70; 56 bytes total).
//!
//! # Extent and reachability, binary-verified
//!
//! Raw ARM begins with `push {r4-r6,lr}` at 0x08205a38, ends with
//! `pop {r4-r6,pc}` at 0x08205a6c, and loads its vtable literal `0x089918bc`
//! from 0x08205a70. The separately linked next function starts at 0x08205a74
//! (`cmp r0,#0`). Decoding every ARM B/BL immediate in `osos.dec` finds seven
//! direct inbound calls, all unconditional `bl` (0x08147c1c, 0x08147d1c,
//! 0x08147e90, 0x0815ef1c, 0x081a2708, 0x081ba010, and 0x081fb3cc); there
//! are no predicated forms, plain-`b` transfers, or aligned data-word
//! references to the entry.
//!
//! # Algorithm
//!
//! Call the shared base constructor at 0x08274f10 with `this`; replace the
//! base vtable on its returned pointer with `0x089918bc`; clear words +0x34
//! and +0x38; store the low byte of r3 at +0x3c; copy r1 and r2 to +0x10 and
//! +0x14; and return the base result. No argument, NULL, or alignment guard
//! exists. The seven callers provide no recovered class identity, so the name
//! states only this verified identified-vtable, pair, and flag behavior.
//!
//! # Deliberate deviations
//!
//! `FUN_08274f10` is still unported. This function deliberately reuses
//! [`crate::cxx::identified_vtable_object_construct::IDENTIFIED_VTABLE_OBJECT_OPS`],
//! the existing faithful seam whose default reproduces its decoded vtable,
//! zero, identifier, and counter-increment operations exactly.

use crate::cxx::identified_vtable_object_construct::IDENTIFIED_VTABLE_OBJECT_OPS;

/// Derived vtable literal at 0x08205a70.
pub const IDENTIFIED_VTABLE_FLAGGED_PAIR_VTABLE_ADDRESS: u32 = 0x0899_18bc;

/// Prefix initialized by the base and derived constructors.
#[repr(C)]
pub struct IdentifiedVtableFlaggedPairPrefix {
    /// +0x00: derived vtable after construction.
    pub vtable: u32,
    /// +0x04: identifier assigned by the shared base constructor.
    pub instance_id: u32,
    /// +0x08 and +0x0c: cleared by the shared base constructor.
    pub base_zeroes: [u32; 2],
    /// +0x10 and +0x14: input words r1 and r2.
    pub pair: [u32; 2],
    /// +0x18..+0x33: untouched by this constructor.
    pub untouched: [u8; 0x1c],
    /// +0x34 and +0x38: explicitly cleared.
    pub derived_zeroes: [u32; 2],
    /// +0x3c: low byte of r3.
    pub flag: u8,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(IdentifiedVtableFlaggedPairPrefix, vtable)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(IdentifiedVtableFlaggedPairPrefix, instance_id)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(IdentifiedVtableFlaggedPairPrefix, base_zeroes)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(IdentifiedVtableFlaggedPairPrefix, pair)];
const _: [u8; 0x34] = [0; core::mem::offset_of!(IdentifiedVtableFlaggedPairPrefix, derived_zeroes)];
const _: [u8; 0x3c] = [0; core::mem::offset_of!(IdentifiedVtableFlaggedPairPrefix, flag)];

/// Constructs the verified identified-vtable prefix and returns the shared
/// base constructor's result.
///
/// # Safety
///
/// `this`, and the pointer returned by the installed base constructor, must
/// point to at least 61 writable bytes and be four-byte aligned for word
/// stores. The retail constructor has no NULL or alignment guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.identified_vtable_flagged_pair_construct")]
pub unsafe extern "C" fn identified_vtable_flagged_pair_construct(
    this: *mut u8,
    input_at_16: u32,
    input_at_20: u32,
    flag_at_60: u8,
) -> *mut u8 {
    let base_ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IDENTIFIED_VTABLE_OBJECT_OPS)) };
    let constructed = unsafe { (base_ops.construct_base)(this) };
    unsafe {
        constructed.cast::<u32>().write_volatile(IDENTIFIED_VTABLE_FLAGGED_PAIR_VTABLE_ADDRESS);
        constructed.add(0x34).cast::<u32>().write_volatile(0);
        constructed.add(0x38).cast::<u32>().write_volatile(0);
        constructed.add(0x3c).write_volatile(flag_at_60);
        constructed.add(0x10).cast::<u32>().write_volatile(input_at_16);
        constructed.add(0x14).cast::<u32>().write_volatile(input_at_20);
    }
    constructed
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::identified_vtable_object_construct::{
        tests::IDENTIFIED_VTABLE_BASE_TEST_LOCK, DEFAULT_IDENTIFIED_VTABLE_OBJECT_OPS,
        IdentifiedVtableObjectOps,
    };

    #[repr(C, align(4))]
    struct ObjectBytes([u8; 0x40]);

    unsafe fn word_at(object: *const u8, offset: usize) -> u32 {
        unsafe { object.add(offset).cast::<u32>().read() }
    }

    fn reset_base_constructor() {
        unsafe { IDENTIFIED_VTABLE_OBJECT_OPS = DEFAULT_IDENTIFIED_VTABLE_OBJECT_OPS };
    }

    #[test]
    fn initializes_base_pair_flag_and_derived_fields() {
        let _base_lock = IDENTIFIED_VTABLE_BASE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_base_constructor();
        let mut object = ObjectBytes([0xa5; 0x40]);
        let this = object.0.as_mut_ptr();

        let returned = unsafe {
            identified_vtable_flagged_pair_construct(this, 0x0123_4567, 0x89ab_cdef, 0xfe)
        };

        assert_eq!(returned, this);
        assert_eq!(unsafe { word_at(this, 0x00) }, IDENTIFIED_VTABLE_FLAGGED_PAIR_VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(this, 0x08) }, 0);
        assert_eq!(unsafe { word_at(this, 0x0c) }, 0);
        assert_eq!(unsafe { word_at(this, 0x10) }, 0x0123_4567);
        assert_eq!(unsafe { word_at(this, 0x14) }, 0x89ab_cdef);
        assert_eq!(unsafe { word_at(this, 0x34) }, 0);
        assert_eq!(unsafe { word_at(this, 0x38) }, 0);
        assert_eq!(unsafe { this.add(0x3c).read() }, 0xfe);
        assert_eq!(&object.0[0x18..0x34], &[0xa5; 0x1c]);
    }

    static mut FORWARDED_THIS: *mut u8 = core::ptr::null_mut();
    static mut BASE_RETURN: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn redirecting_base_construct(this: *mut u8) -> *mut u8 {
        unsafe {
            FORWARDED_THIS = this;
            BASE_RETURN
        }
    }

    #[test]
    fn derives_every_store_from_the_base_return_not_the_entry_pointer() {
        let _base_lock = IDENTIFIED_VTABLE_BASE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut entry = ObjectBytes([0xa5; 0x40]);
        let mut redirected = ObjectBytes([0x3c; 0x40]);
        unsafe {
            FORWARDED_THIS = core::ptr::null_mut();
            BASE_RETURN = redirected.0.as_mut_ptr();
            IDENTIFIED_VTABLE_OBJECT_OPS = IdentifiedVtableObjectOps {
                construct_base: redirecting_base_construct,
            };
        }

        let returned = unsafe {
            identified_vtable_flagged_pair_construct(entry.0.as_mut_ptr(), 7, 9, 0x12)
        };

        assert_eq!(unsafe { FORWARDED_THIS }, entry.0.as_mut_ptr());
        assert_eq!(returned, redirected.0.as_mut_ptr());
        assert_eq!(unsafe { word_at(redirected.0.as_ptr(), 0x00) }, IDENTIFIED_VTABLE_FLAGGED_PAIR_VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(redirected.0.as_ptr(), 0x10) }, 7);
        assert_eq!(unsafe { word_at(redirected.0.as_ptr(), 0x14) }, 9);
        assert_eq!(unsafe { word_at(redirected.0.as_ptr(), 0x34) }, 0);
        assert_eq!(unsafe { word_at(redirected.0.as_ptr(), 0x38) }, 0);
        assert_eq!(unsafe { redirected.0.as_ptr().add(0x3c).read() }, 0x12);
        assert_eq!(&entry.0, &[0xa5; 0x40]);
        reset_base_constructor();
    }
}
