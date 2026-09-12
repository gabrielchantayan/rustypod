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
//! and consume the returned word. The separately entered helper
//! [`ui_resource_value_from_cow_string`] resolves the constructed COW string
//! through the global map at 0x08ad7c6c and the still-unported map operation
//! at 0x083db75c. The map class has not been established; its operation stays
//! a typed fixed-address boundary on firmware and a swappable host seam.

use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

const UI_RESOURCE_VALUE_MAP_ADDRESS: usize = 0x08ad_7c6c;
const UI_RESOURCE_VALUE_MAP_LOOKUP_ADDRESS: usize = 0x083d_b75c;

type UiResourceValueMapLookup = unsafe extern "C" fn(*mut u8, *mut *mut u8) -> *const u32;

/// Host/target operation for the unported COW-string-keyed map.
#[derive(Clone, Copy)]
struct UiResourceValueMapOps {
    map: *mut u8,
    lookup: UiResourceValueMapLookup,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_resource_value_map_lookup(
    map: *mut u8,
    key: *mut *mut u8,
) -> *const u32 {
    let lookup: UiResourceValueMapLookup =
        unsafe { core::mem::transmute(UI_RESOURCE_VALUE_MAP_LOOKUP_ADDRESS) };
    unsafe { lookup(map, key) }
}

#[cfg(not(target_os = "none"))]
static mut MISSING_RESOURCE_VALUE: u32 = 0;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_value_map_lookup(
    _map: *mut u8,
    _key: *mut *mut u8,
) -> *const u32 {
    core::ptr::addr_of!(MISSING_RESOURCE_VALUE)
}

/// Host default before a test supplies the resident map operation.
#[cfg(not(target_os = "none"))]
const DEFAULT_UI_RESOURCE_VALUE_MAP_OPS: UiResourceValueMapOps = UiResourceValueMapOps {
    map: core::ptr::null_mut(),
    lookup: missing_resource_value_map_lookup,
};

/// Host-side seam for the unported map operation at 0x083db75c.
#[cfg(not(target_os = "none"))]
static mut UI_RESOURCE_VALUE_MAP_OPS: UiResourceValueMapOps =
    DEFAULT_UI_RESOURCE_VALUE_MAP_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resource_value_map_lookup(key: *mut *mut u8) -> *const u32 {
    unsafe {
        firmware_resource_value_map_lookup(UI_RESOURCE_VALUE_MAP_ADDRESS as *mut u8, key)
    }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resource_value_map_lookup(key: *mut *mut u8) -> *const u32 {
    let ops = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(UI_RESOURCE_VALUE_MAP_OPS))
    };
    unsafe { (ops.lookup)(ops.map, key) }
}
/// Resolves a COW string object to its UI resource value — `FUN_0829047c` @
/// **0x0829047c**.
///
/// Raw ARM establishes a 28-byte extent, `0x0829047c..0x08290498`: six ARM
/// instructions plus the literal 0x08ad7c6c. It moves the COW-string object
/// from `r0` to `r1`, supplies the global map address as `r0`, calls
/// 0x083db75c, then loads and returns the first word of that result. Decoding
/// every ARM B/BL word in `osos.dec` finds **seven direct inbound `bl` sites**,
/// all unconditional (0x08134394, 0x081343a8, 0x08134560, 0x081345e0,
/// 0x08134624, 0x0816dc80, and 0x08290464), with no predicated forms, direct
/// `b` references, or data-word references. The raw function has no NULL
/// guards for its COW string, map-operation result, or returned word.
///
/// Deliberate deviation: the still-unidentified map operation at 0x083db75c
/// is a typed fixed-address target on firmware and a swappable seam on host;
/// the map itself remains the verified global address 0x08ad7c6c.
///
/// # Safety
///
/// `key` must be a valid COW string object accepted by the resident map. The
/// map operation must return a readable, aligned value word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_resource_value_from_cow_string(key: *mut *mut u8) -> u32 {
    let value = unsafe { resource_value_map_lookup(key) };
    unsafe { core::ptr::read(value) }
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
/// the resource-value map rooted at 0x08ad7c6c and its operation at
/// 0x083db75c must remain live.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_resource_value_from_cstr(name: *const u8) -> u32 {
    let mut key = core::ptr::null_mut();
    unsafe {
        cxx_string_from_cstr(core::ptr::addr_of_mut!(key), name);
        let value = ui_resource_value_from_cow_string(core::ptr::addr_of_mut!(key));
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
    static mut LOOKUP_MAP: *mut u8 = core::ptr::null_mut();
    static mut MAP_STORAGE: [u8; 1] = [0];
    static mut SEEN: [u8; 32] = [0; 32];
    static mut SEEN_LEN: usize = 0;
    static mut STRING_ALLOCATION: [u32; 16] = [0; 16];

    unsafe extern "C" fn lookup_stub(map: *mut u8, key: *mut *mut u8) -> *const u32 {
        LOOKUP_CALLS += 1;
        LOOKUP_MAP = map;
        SEEN_LEN = 0;
        let bytes = *key;
        while *bytes.add(SEEN_LEN) != 0 {
            SEEN[SEEN_LEN] = *bytes.add(SEEN_LEN);
            SEEN_LEN += 1;
        }
        core::ptr::addr_of!(LOOKUP_VALUE)
    }

    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
        _heap: std::sync::MutexGuard<'static, ()>,
        saved: UiResourceValueMapOps,
    }

    impl OpsGuard {
        fn install() -> Self {
            let lock = OPS_LOCK.lock();
            let heap = crate::heap::veneers::tests::mock_heap();
            let saved = unsafe {
                core::ptr::read_volatile(core::ptr::addr_of!(UI_RESOURCE_VALUE_MAP_OPS))
            };
            unsafe {
                UI_RESOURCE_VALUE_MAP_OPS = UiResourceValueMapOps {
                    map: core::ptr::addr_of_mut!(MAP_STORAGE).cast(),
                    lookup: lookup_stub,
                };
                LOOKUP_CALLS = 0;
                LOOKUP_VALUE = 0;
                LOOKUP_MAP = core::ptr::null_mut();
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
            unsafe { UI_RESOURCE_VALUE_MAP_OPS = self.saved; }
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
    fn resolves_a_cow_string_through_the_global_resource_map() {
        let _guard = OpsGuard::install();
        unsafe { LOOKUP_VALUE = 0x1bad_b002; }
        let name = b"Voice Memo Image\0";
        let mut key = name.as_ptr().cast_mut();

        let value = unsafe { ui_resource_value_from_cow_string(&mut key) };

        assert_eq!(value, 0x1bad_b002);
        unsafe {
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(LOOKUP_MAP, core::ptr::addr_of_mut!(MAP_STORAGE).cast());
            assert_eq!(&SEEN[..SEEN_LEN], &name[..name.len() - 1]);
        }
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
