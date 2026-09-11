//! `vtable_flag_payload_construct` — original: `FUN_081b6968` @
//! **0x081b6968** (28 instruction bytes, followed by its four-byte
//! literal-pool vtable word at 0x081b6984; 32 bytes through the next function).
//!
//! # Extent and reachability, binary-verified
//!
//! Raw ARM runs from `mov r2,r1` at 0x081b6968 through `pop {pc}` at
//! 0x081b6980. The following pool word is `0x0898c2a4`; the distinct next
//! function starts at 0x081b6988 (`cmp r0,#0`). Decoding every ARM B/BL
//! immediate in `osos.dec` finds exactly ten inbound calls, all unconditional
//! `bl` (0x08135ba8, 0x0813ee48, 0x08143a6c, 0x08148790, 0x08177f0c,
//! 0x08187080, 0x0819cd3c, 0x081ba988, 0x081deb68, and 0x0820b210). There
//! are no predicated calls or plain-`b` transfers to the entry.
//!
//! # Algorithm
//!
//! Call the shared base constructor at 0x08135788 with `this`, retain the
//! incoming payload across that call, replace the base vtable on its returned
//! pointer with `0x0898c2a4`, store the payload at +8, and return that pointer.
//! The decoded base constructor installs `0x08984948` at +0 and clears byte
//! +4. No argument, NULL, or alignment guard exists.
//!
//! # Deliberate deviations
//!
//! The base constructor is not yet ported (and has no ledger entry), so the
//! call uses a volatile replaceable seam. Its default reproduces the fully
//! decoded base stores on both host and target; a later direct port can replace
//! the seam without changing this constructor. The wider class identity is
//! unestablished, so names describe only the observed vtable, flag, and payload
//! behavior.

/// Base vtable installed by unported `FUN_08135788` before this constructor
/// replaces it.
pub const VTABLE_FLAG_BASE_VTABLE_ADDRESS: u32 = 0x0898_4948;
/// Derived vtable literal at 0x081b6984.
pub const VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS: u32 = 0x0898_c2a4;

/// The initialized prefix shared by the base and derived constructor.
#[repr(C)]
pub struct VtableFlagPayloadPrefix {
    /// +0x00: base vtable, then [`VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS`].
    pub vtable: u32,
    /// +0x04: zeroed by the base constructor.
    pub flag: u8,
    /// +0x05..+0x07: not touched by either decoded constructor.
    pub unresolved_05: [u8; 3],
    /// +0x08: incoming payload retained across the base call.
    pub payload: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x00] = [0; core::mem::offset_of!(VtableFlagPayloadPrefix, vtable)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(VtableFlagPayloadPrefix, flag)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(VtableFlagPayloadPrefix, payload)];

/// ABI of the unported base constructor at 0x08135788.
pub type VtableFlagBaseConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// One dependency of [`vtable_flag_payload_construct`].
#[derive(Clone, Copy)]
pub struct VtableFlagPayloadConstructOps {
    pub construct_base: VtableFlagBaseConstruct,
}

/// Behavioral model of the fully decoded, still-unported base constructor.
unsafe extern "C" fn default_construct_base(this: *mut u8) -> *mut u8 {
    unsafe {
        this.cast::<u32>()
            .write_volatile(VTABLE_FLAG_BASE_VTABLE_ADDRESS);
        this.add(4).write_volatile(0);
    }
    this
}

/// Default base-constructor seam until 0x08135788 receives its own port.
pub const DEFAULT_VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS: VtableFlagPayloadConstructOps =
    VtableFlagPayloadConstructOps {
        construct_base: default_construct_base,
    };

/// Active base-constructor boundary. Tests replace it to preserve the raw
/// post-call use of the base constructor's returned pointer.
pub static mut VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS: VtableFlagPayloadConstructOps =
    DEFAULT_VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS;

#[inline(always)]
unsafe fn ops() -> VtableFlagPayloadConstructOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS)) }
}

/// Constructs the observed vtable/flag/payload prefix and returns the base
/// constructor's result.
///
/// # Safety
///
/// `this`, and the pointer returned by the installed base constructor, must
/// point to at least 12 writable bytes and be four-byte aligned for the word
/// stores. The retail function dereferences both without a NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_flag_payload_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_flag_payload_construct(
    this: *mut u8,
    payload: u32,
) -> *mut u8 {
    let constructed = unsafe { (ops().construct_base)(this) };
    unsafe {
        constructed
            .cast::<u32>()
            .write_volatile(VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS);
        constructed.add(8).cast::<u32>().write_volatile(payload);
    }
    constructed
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut BASE_CALLS: u32 = 0;
    static mut BASE_INPUT: *mut u8 = ptr::null_mut();
    static mut BASE_RESULT: *mut u8 = ptr::null_mut();

    struct OpsReset;

    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS)
                    .write_volatile(DEFAULT_VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS);
            }
        }
    }

    unsafe extern "C" fn relocating_base(this: *mut u8) -> *mut u8 {
        unsafe {
            BASE_CALLS += 1;
            BASE_INPUT = this;
            BASE_RESULT
        }
    }

    fn install_relocating_base(result: *mut u8) -> (MutexGuard<'static, ()>, OpsReset) {
        let lock = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            BASE_CALLS = 0;
            BASE_INPUT = ptr::null_mut();
            BASE_RESULT = result;
            ptr::addr_of_mut!(VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS).write_volatile(
                VtableFlagPayloadConstructOps {
                    construct_base: relocating_base,
                },
            );
        }
        (lock, OpsReset)
    }

    #[repr(C, align(4))]
    struct AlignedBytes([u8; 20]);

    unsafe fn word_at(bytes: *const u8, offset: usize) -> u32 {
        unsafe { bytes.add(offset).cast::<u32>().read() }
    }

    #[test]
    fn default_base_initializes_prefix_and_payload_without_touching_padding() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _reset = OpsReset;
        unsafe {
            ptr::addr_of_mut!(VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS)
                .write_volatile(DEFAULT_VTABLE_FLAG_PAYLOAD_CONSTRUCT_OPS);
        }
        let mut storage = AlignedBytes([0xa5; 20]);
        let object = unsafe { storage.0.as_mut_ptr().add(4) };

        let returned = unsafe { vtable_flag_payload_construct(object, u32::MAX) };

        assert_eq!(returned, object);
        assert_eq!(unsafe { word_at(object, 0) }, VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS);
        assert_eq!(unsafe { object.add(4).read() }, 0);
        assert_eq!(unsafe { &*object.add(5).cast::<[u8; 3]>() }, &[0xa5; 3]);
        assert_eq!(unsafe { word_at(object, 8) }, u32::MAX);
        assert_eq!(&storage.0[..4], &[0xa5; 4]);
        assert_eq!(&storage.0[16..], &[0xa5; 4]);
    }

    #[test]
    fn writes_derived_fields_to_base_return_and_preserves_call_input() {
        let mut storage = AlignedBytes([0x3c; 20]);
        let input = storage.0.as_mut_ptr();
        let result = unsafe { storage.0.as_mut_ptr().add(4) };
        let (_lock, _reset) = install_relocating_base(result);

        let returned = unsafe { vtable_flag_payload_construct(input, 0x1357_9bdf) };

        assert_eq!(returned, result);
        assert_eq!(unsafe { BASE_CALLS }, 1);
        assert_eq!(unsafe { BASE_INPUT }, input);
        assert_eq!(unsafe { word_at(input, 0) }, 0x3c3c_3c3c);
        assert_eq!(unsafe { word_at(result, 0) }, VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(result, 8) }, 0x1357_9bdf);
    }
}
