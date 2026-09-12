//! `identified_vtable_object_construct` — original: `FUN_081f6080` @
//! **0x081f6080** (68 bytes: 64 bytes of code plus the literal-pool vtable
//! word at 0x081f60c0; Ghidra reports only the 64 instruction bytes).
//!
//! # Extent and reachability, binary-verified
//!
//! Raw ARM starts with `push {r4-r8,lr}` at 0x081f6080, ends with
//! `pop {r4-r8,pc}` at 0x081f60bc, and loads its derived-vtable literal
//! `0x08990364` from 0x081f60c0. The next separately linked function starts
//! at 0x081f60c4 (`cmp r0,#0`). Decoding every ARM B/BL immediate in
//! `osos.dec` finds exactly 10 direct inbound calls — all unconditional `bl`
//! (0x0810dd8c, 0x0810ed58, 0x0811029c, 0x0811e7f0, 0x081307a0, 0x081443b8,
//! 0x08158b24, 0x0816df30, 0x081df6f8, 0x08205d5c); there are no predicated
//! forms, tail `b` calls, or aligned data-word references to this entry.
//!
//! # Algorithm
//!
//! The constructor first invokes the unported 0x08274f10 base constructor.
//! Its raw 44-byte body is fully decoded: it installs vtable `0x089a5f98`,
//! clears base words +8 and +12, assigns the current word at `0x08a09f00` to
//! +4, then increments that global. This derived constructor replaces the
//! base vtable with `0x08990364`, clears words +0x40 and +0x44, stores its
//! `r3` and stack-byte inputs at +0x48 and +0x49, copies `r1` and `r2` to
//! +0x10 and +0x14, and returns the base constructor's `r0`.
//!
//! The concrete class identity is not established, so the name states only
//! the verified object behavior: a vtable-backed object with a monotonically
//! assigned base identifier. All ten callers are derived constructors that
//! overwrite the vtable again and initialize fields from +0x50 onward.
//!
//! # Deliberate deviations
//!
//! `FUN_08274f10` is not ported. [`IDENTIFIED_VTABLE_OBJECT_OPS`] is the
//! project dispatch seam for it; its default is not a stub and reproduces the
//! seven decoded stores/load-increment sequence exactly. This keeps the hook
//! behaviorally complete now and permits a future direct base port without
//! changing this caller.

/// Vtable installed by the unported base constructor at 0x08274f10.
pub const BASE_VTABLE_ADDRESS: u32 = 0x089a_5f98;
/// Vtable literal at 0x081f60c0 installed by this constructor.
pub const DERIVED_VTABLE_ADDRESS: u32 = 0x0899_0364;
/// Runtime-owned monotonically increasing base-object identifier.
#[cfg(target_os = "none")]
const BASE_ID_COUNTER: *mut u32 = 0x08a0_9f00 as *mut u32;

/// The initialized prefix. The complete derived objects are larger; fields
/// after +0x49 remain the responsibility of their derived constructors.
#[repr(C)]
pub struct IdentifiedVtableObjectPrefix {
    /// +0x00: derived vtable after construction.
    pub vtable: u32,
    /// +0x04: identifier read from the base counter before incrementing it.
    pub instance_id: u32,
    /// +0x08 and +0x0c: cleared by the base constructor.
    pub base_zeroes: [u32; 2],
    /// +0x10 and +0x14: input words r1 and r2.
    pub inputs: [u32; 2],
    /// +0x18..+0x3f: untouched by this constructor.
    pub untouched: [u8; 0x28],
    /// +0x40 and +0x44: explicitly cleared.
    pub derived_zeroes: [u32; 2],
    /// +0x48 and +0x49: low bytes of r3 and the fifth ABI argument.
    pub flags: [u8; 2],
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(IdentifiedVtableObjectPrefix, vtable)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(IdentifiedVtableObjectPrefix, instance_id)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(IdentifiedVtableObjectPrefix, base_zeroes)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(IdentifiedVtableObjectPrefix, inputs)];
const _: [u8; 0x40] = [0; core::mem::offset_of!(IdentifiedVtableObjectPrefix, derived_zeroes)];
const _: [u8; 0x48] = [0; core::mem::offset_of!(IdentifiedVtableObjectPrefix, flags)];

/// ABI of the unported base constructor at 0x08274f10.
pub type IdentifiedVtableBaseConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// The one unported base-constructor dependency.
#[derive(Clone, Copy)]
pub struct IdentifiedVtableObjectOps {
    pub construct_base: IdentifiedVtableBaseConstruct,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn default_construct_base(this: *mut u8) -> *mut u8 {
    unsafe {
        this.cast::<u32>().write_volatile(BASE_VTABLE_ADDRESS);
        this.add(8).cast::<u32>().write_volatile(0);
        this.add(12).cast::<u32>().write_volatile(0);
        let id = BASE_ID_COUNTER.read_volatile();
        this.add(4).cast::<u32>().write_volatile(id);
        BASE_ID_COUNTER.write_volatile(id.wrapping_add(1));
    }
    this
}

#[cfg(not(target_os = "none"))]
static mut HOST_BASE_ID_COUNTER: u32 = 0;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_construct_base(this: *mut u8) -> *mut u8 {
    unsafe {
        this.cast::<u32>().write_volatile(BASE_VTABLE_ADDRESS);
        this.add(8).cast::<u32>().write_volatile(0);
        this.add(12).cast::<u32>().write_volatile(0);
        let id = core::ptr::addr_of!(HOST_BASE_ID_COUNTER).read_volatile();
        this.add(4).cast::<u32>().write_volatile(id);
        core::ptr::addr_of_mut!(HOST_BASE_ID_COUNTER).write_volatile(id.wrapping_add(1));
    }
    this
}

/// Faithful default before 0x08274f10 has its own port.
pub const DEFAULT_IDENTIFIED_VTABLE_OBJECT_OPS: IdentifiedVtableObjectOps =
    IdentifiedVtableObjectOps { construct_base: default_construct_base };

/// Active base-constructor boundary. Target builds use the exact decoded
/// default; tests may replace it to prove that this constructor uses the
/// base's returned pointer, as the ARM `str` instructions do after `bl`.
pub static mut IDENTIFIED_VTABLE_OBJECT_OPS: IdentifiedVtableObjectOps =
    DEFAULT_IDENTIFIED_VTABLE_OBJECT_OPS;

#[inline(always)]
unsafe fn ops() -> IdentifiedVtableObjectOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IDENTIFIED_VTABLE_OBJECT_OPS)) }
}

/// Constructs the identified vtable-object prefix and returns the base
/// constructor's result.
///
/// # Safety
///
/// `this`, and the pointer returned by the installed base constructor, must
/// point to at least 74 writable bytes and be 4-byte aligned for word stores.
/// The retail constructor has no null or alignment guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.identified_vtable_object_construct")]
pub unsafe extern "C" fn identified_vtable_object_construct(
    this: *mut u8,
    input_at_16: u32,
    input_at_20: u32,
    flag_at_48: u8,
    flag_at_49: u8,
) -> *mut u8 {
    let constructed = unsafe { (ops().construct_base)(this) };
    unsafe {
        constructed.cast::<u32>().write_volatile(DERIVED_VTABLE_ADDRESS);
        constructed.add(0x40).cast::<u32>().write_volatile(0);
        constructed.add(0x44).cast::<u32>().write_volatile(0);
        constructed.add(0x48).write_volatile(flag_at_48);
        constructed.add(0x49).write_volatile(flag_at_49);
        constructed.add(0x10).cast::<u32>().write_volatile(input_at_16);
        constructed.add(0x14).cast::<u32>().write_volatile(input_at_20);
    }
    constructed
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    pub(crate) static IDENTIFIED_VTABLE_BASE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_THIS: *mut u8 = core::ptr::null_mut();
    static mut BASE_RETURN: *mut u8 = core::ptr::null_mut();

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = IDENTIFIED_VTABLE_BASE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            IDENTIFIED_VTABLE_OBJECT_OPS = DEFAULT_IDENTIFIED_VTABLE_OBJECT_OPS;
            HOST_BASE_ID_COUNTER = 0;
            FORWARDED_THIS = core::ptr::null_mut();
            BASE_RETURN = core::ptr::null_mut();
        }
        Bench { _lock: lock }
    }

    #[repr(C, align(4))]
    struct ObjectBytes([u8; 0x50]);

    unsafe fn word_at(object: *const u8, offset: usize) -> u32 {
        unsafe { object.add(offset).cast::<u32>().read() }
    }

    #[test]
    fn initializes_the_base_derived_and_argument_fields_in_stock_order() {
        let _bench = bench();
        unsafe { HOST_BASE_ID_COUNTER = 0x1357_9bdf };
        let mut object = ObjectBytes([0xa5; 0x50]);
        let this = object.0.as_mut_ptr();

        let returned = unsafe {
            identified_vtable_object_construct(this, 0x0123_4567, 0x89ab_cdef, 0xff, 0x80)
        };

        assert_eq!(returned, this);
        assert_eq!(unsafe { word_at(this, 0x00) }, DERIVED_VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(this, 0x04) }, 0x1357_9bdf);
        assert_eq!(unsafe { word_at(this, 0x08) }, 0);
        assert_eq!(unsafe { word_at(this, 0x0c) }, 0);
        assert_eq!(unsafe { word_at(this, 0x10) }, 0x0123_4567);
        assert_eq!(unsafe { word_at(this, 0x14) }, 0x89ab_cdef);
        assert_eq!(unsafe { word_at(this, 0x40) }, 0);
        assert_eq!(unsafe { word_at(this, 0x44) }, 0);
        assert_eq!(unsafe { this.add(0x48).read() }, 0xff);
        assert_eq!(unsafe { this.add(0x49).read() }, 0x80);
        assert_eq!(&object.0[0x18..0x40], &[0xa5; 0x28]);
        assert_eq!(&object.0[0x4a..], &[0xa5; 6]);
        assert_eq!(unsafe { HOST_BASE_ID_COUNTER }, 0x1357_9be0);
    }

    #[test]
    fn default_base_assigns_successive_wrapping_identifiers() {
        let _bench = bench();
        unsafe { HOST_BASE_ID_COUNTER = u32::MAX };
        let mut first = ObjectBytes([0; 0x50]);
        let mut second = ObjectBytes([0; 0x50]);

        unsafe {
            identified_vtable_object_construct(first.0.as_mut_ptr(), 0, 0, 0, 0);
            identified_vtable_object_construct(second.0.as_mut_ptr(), 0, 0, 0, 0);
        }

        assert_eq!(unsafe { word_at(first.0.as_ptr(), 4) }, u32::MAX);
        assert_eq!(unsafe { word_at(second.0.as_ptr(), 4) }, 0);
        assert_eq!(unsafe { HOST_BASE_ID_COUNTER }, 1);
    }

    unsafe extern "C" fn redirecting_base_construct(this: *mut u8) -> *mut u8 {
        unsafe {
            FORWARDED_THIS = this;
            BASE_RETURN
        }
    }

    #[test]
    fn derives_every_store_from_the_base_return_not_the_entry_pointer() {
        let _bench = bench();
        let mut entry = ObjectBytes([0xa5; 0x50]);
        let mut redirected = ObjectBytes([0x3c; 0x50]);
        unsafe {
            BASE_RETURN = redirected.0.as_mut_ptr();
            IDENTIFIED_VTABLE_OBJECT_OPS = IdentifiedVtableObjectOps {
                construct_base: redirecting_base_construct,
            };
        }

        let returned = unsafe {
            identified_vtable_object_construct(entry.0.as_mut_ptr(), 7, 9, 0x12, 0x34)
        };

        assert_eq!(unsafe { FORWARDED_THIS }, entry.0.as_mut_ptr());
        assert_eq!(returned, redirected.0.as_mut_ptr());
        assert_eq!(unsafe { word_at(redirected.0.as_ptr(), 0) }, DERIVED_VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(redirected.0.as_ptr(), 0x10) }, 7);
        assert_eq!(unsafe { word_at(redirected.0.as_ptr(), 0x14) }, 9);
        assert_eq!(unsafe { redirected.0.as_ptr().add(0x48).read() }, 0x12);
        assert_eq!(unsafe { redirected.0.as_ptr().add(0x49).read() }, 0x34);
        assert_eq!(&entry.0, &[0xa5; 0x50]);
    }
}
