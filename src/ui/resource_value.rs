//! C-string resource-value lookup — `FUN_08290450` @ **0x08290450**.
//!
//! Raw ARM proves the complete 44-byte extent is `0x08290450..0x0829047c`:
//! `push {r2,r3,r4,lr}`, construct a one-word COW string at `sp+4` from the
//! incoming C string, call the separately entered `0x0829047c`, release the
//! temporary, restore its returned word, and return. The next function opens
//! with `mov r1,r0; push {r4,lr}` at `0x0829047c`; there is no literal pool.
//! Decoding every ARM B/BL word in `osos.dec` finds **10 direct inbound `bl`
//! call sites**, all unconditional (0x08159318, 0x0815ea04, 0x0815ea10,
//! 0x0815ea1c, 0x081a3324, 0x081a3434, 0x081a3460, 0x081a3470, 0x081a34a4,
//! and 0x081a4a54), with no predicated forms or direct `b` references.
//!
//! The callers pass UI resource names such as `"Stopwatch:SmallPlay Image"`
//! and consume the returned word as their resource value. The resident helper
//! at 0x0829047c constructs the lookup from the COW string and the global map
//! at 0x08ad7c6c; it reaches a separately unported string-keyed-map entry at
//! 0x083db75c. This port deliberately keeps 0x0829047c as a fixed-address
//! target boundary rather than claiming an identity for that map class. Host
//! tests supply the boundary through [`UI_RESOURCE_VALUE_OPS`].

use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

const UI_RESOURCE_VALUE_LOOKUP_ADDRESS: usize = 0x0829_047c;

type UiResourceValueLookup = unsafe extern "C" fn(*mut *mut u8) -> u32;

/// Host/target operation for the resident COW-string resource-value lookup.
#[derive(Clone, Copy)]
pub struct UiResourceValueOps {
    pub lookup: UiResourceValueLookup,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_resource_value_lookup(key: *mut *mut u8) -> u32 {
    let lookup: UiResourceValueLookup = unsafe { core::mem::transmute(UI_RESOURCE_VALUE_LOOKUP_ADDRESS) };
    unsafe { lookup(key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_value_lookup(_key: *mut *mut u8) -> u32 {
    0
}

/// Host default before a test supplies the resident lookup.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_UI_RESOURCE_VALUE_OPS: UiResourceValueOps = UiResourceValueOps {
    lookup: missing_resource_value_lookup,
};

/// Host-side seam for the unported resident helper at 0x0829047c. Target
/// builds retain that helper's verified fixed entry directly.
#[cfg(not(target_os = "none"))]
pub static mut UI_RESOURCE_VALUE_OPS: UiResourceValueOps = DEFAULT_UI_RESOURCE_VALUE_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resource_value_lookup(key: *mut *mut u8) -> u32 {
    unsafe { firmware_resource_value_lookup(key) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resource_value_lookup(key: *mut *mut u8) -> u32 {
    let lookup = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(UI_RESOURCE_VALUE_OPS.lookup))
    };
    unsafe { lookup(key) }
}

/// Resolves a UI resource's C-string name to its mapped value word.
///
/// The incoming `name` is passed unchanged to `basic_string(const char *)`.
/// Its resulting one-word COW string object is valid only for the resident
/// lookup call and is released before this function returns, even when the
/// lookup produces zero. The raw ARM has no NULL guard for `name`.
///
/// # Safety
///
/// `name` must point to a readable NUL-terminated byte sequence. On firmware,
/// the resource-value map rooted at 0x08ad7c6c and the helper at 0x0829047c
/// must remain live.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_resource_value_from_cstr(name: *const u8) -> u32 {
    let mut key = core::ptr::null_mut();
    unsafe {
        cxx_string_from_cstr(core::ptr::addr_of_mut!(key), name);
        let value = resource_value_lookup(core::ptr::addr_of_mut!(key));
        cxx_string_release(core::ptr::addr_of_mut!(key));
        value
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUP_CALLS: u32 = 0;
    static mut LOOKUP_VALUE: u32 = 0;
    static mut SEEN: [u8; 32] = [0; 32];
    static mut SEEN_LEN: usize = 0;
    static mut STRING_ALLOCATION: [u32; 16] = [0; 16];

    unsafe extern "C" fn lookup_stub(key: *mut *mut u8) -> u32 {
        LOOKUP_CALLS += 1;
        SEEN_LEN = 0;
        let bytes = *key;
        while *bytes.add(SEEN_LEN) != 0 {
            SEEN[SEEN_LEN] = *bytes.add(SEEN_LEN);
            SEEN_LEN += 1;
        }
        LOOKUP_VALUE
    }

    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
        _heap: std::sync::MutexGuard<'static, ()>,
        saved: UiResourceValueOps,
    }

    impl OpsGuard {
        fn install() -> Self {
            let lock = OPS_LOCK.lock();
            let heap = crate::heap::veneers::tests::mock_heap();
            let saved = unsafe {
                core::ptr::read_volatile(core::ptr::addr_of!(UI_RESOURCE_VALUE_OPS))
            };
            unsafe {
                UI_RESOURCE_VALUE_OPS = UiResourceValueOps { lookup: lookup_stub };
                LOOKUP_CALLS = 0;
                LOOKUP_VALUE = 0;
                SEEN = [0; 32];
                SEEN_LEN = 0;
                STRING_ALLOCATION = [0; 16];
                crate::heap::veneers::tests::set_alloc_ret(
                    core::ptr::addr_of_mut!(STRING_ALLOCATION).cast(),
                );
            }
            Self { _lock: lock, _heap: heap, saved }
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { UI_RESOURCE_VALUE_OPS = self.saved; }
        }
    }

    #[test]
    fn resolves_exact_name_through_a_temporary_cow_string() {
        let _guard = OpsGuard::install();
        unsafe { LOOKUP_VALUE = 0xc001_d00d; }
        let name = b"Stopwatch:SmallPlay Image\0";

        let value = unsafe { ui_resource_value_from_cstr(name.as_ptr()) };

        assert_eq!(value, 0xc001_d00d);
        unsafe {
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(&SEEN[..SEEN_LEN], &name[..name.len() - 1]);
        }
        let (frees, freed, tag) = crate::heap::veneers::tests::free_log();
        assert_eq!(frees, 1);
        assert_eq!(freed, core::ptr::addr_of_mut!(STRING_ALLOCATION).cast());
        assert_eq!(tag, 2);
    }

    #[test]
    fn forwards_an_empty_name_and_preserves_a_zero_lookup_value() {
        let _guard = OpsGuard::install();
        let name = b"\0";
        unsafe { LOOKUP_VALUE = 0; }

        let value = unsafe { ui_resource_value_from_cstr(name.as_ptr()) };

        assert_eq!(value, 0);
        unsafe { assert_eq!(LOOKUP_CALLS, 1); }
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
    }
}
