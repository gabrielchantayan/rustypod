//! Derive the first navigation key from a string object.
//!
//! The byte-map getter at `0x0820b234` has an unrecovered identity. Raw ARM
//! confirms that it returns the three-word range/byte-map consumed below, so
//! device builds retain that boundary rather than assigning it a speculative
//! locale API name.

use super::string_object::{string_object_codepoint_at, StringObject};

const BYTE_MAP_GETTER_ADDRESS: usize = 0x0820_b234;
const INITIAL_SORT_KEY_CHARACTER_FLAGS_ADDRESS: usize = 0x083e_cfdd;
const REJECTED_KEY: u32 = 0x21;
const UNSUPPORTED_KEY: u32 = 0x23;
const DIGIT_FLAG: u8 = 0x10;

/// The raw three-word byte-map object returned by `FUN_0820b234`.
///
/// Its identity is unrecovered. The independently decoded lookup
/// `FUN_0829f1f4` reads these signed inclusive bounds and then a byte at the
/// unadjusted character index.
#[repr(C)]
pub struct ByteMap {
    pub first: i32,
    pub last: i32,
    pub bytes: *const u8,
}

/// ABI of the unidentified byte-map getter at `0x0820b234`.
pub type ByteMapGetter = unsafe extern "C" fn() -> *const ByteMap;

/// Host replacement for the device's fixed byte-map getter and flag table.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct StringObjectInitialSortKeyOps {
    pub byte_map: ByteMapGetter,
    pub character_flags: *const u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_byte_map() -> *const ByteMap {
    let getter: ByteMapGetter = core::mem::transmute(BYTE_MAP_GETTER_ADDRESS);
    getter()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_byte_map() -> *const ByteMap {
    panic!("string_object_initial_sort_key requires byte-map getter 0x0820b234")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_STRING_OBJECT_INITIAL_SORT_KEY_OPS: StringObjectInitialSortKeyOps =
    StringObjectInitialSortKeyOps {
        byte_map: missing_byte_map,
        character_flags: core::ptr::null(),
    };

/// Active host byte-map and flag-table boundary.
#[cfg(not(target_os = "none"))]
pub static mut STRING_OBJECT_INITIAL_SORT_KEY_OPS: StringObjectInitialSortKeyOps =
    DEFAULT_STRING_OBJECT_INITIAL_SORT_KEY_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn current_byte_map() -> *const ByteMap {
    firmware_byte_map()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn current_byte_map() -> *const ByteMap {
    (core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_INITIAL_SORT_KEY_OPS)).byte_map)()
}

#[cfg(target_os = "none")]
#[inline(always)]
fn current_character_flags() -> *const u8 {
    INITIAL_SORT_KEY_CHARACTER_FLAGS_ADDRESS as *const u8
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn current_character_flags() -> *const u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_INITIAL_SORT_KEY_OPS)).character_flags
}

/// Replicates the signed-bounds byte lookup in `FUN_0829f1f4`.
#[inline(always)]
unsafe fn byte_map_lookup(map: *const ByteMap, character: u32) -> u8 {
    let character_signed = character as i32;
    if (*map).first <= character_signed && character_signed <= (*map).last {
        (*map).bytes.add(character as usize).read()
    } else {
        0
    }
}

/// `string_object_initial_sort_key` — original: `FUN_080dadfc` @ `0x080dadfc`
/// (108 bytes: 104 instruction bytes plus the 4-byte character-flag-table
/// literal at `0x080dae68`; the next separately linked function begins at
/// `0x080dae6c`). Ten direct `bl` call sites were verified by decoding every
/// ARM B/BL word in `osos.dec`; all ten are unconditional plain `bl`, with no
/// predicated calls or direct `b` tail sites.
///
/// Skip leading U+0020 codepoints, map the first remaining codepoint through
/// the current raw byte map, then reject mapped characters whose flag byte has
/// bit 0x10. A zero map result returns 0x21 for a terminator or input at least
/// U+2E80, otherwise 0x23; a mapped digit also returns 0x23. The map's lookup
/// preserves the retail signed inclusive range checks from `FUN_0829f1f4`.
///
/// Deliberate deviation: the unported map getter remains a typed fixed-address
/// device call and a host seam. Its 20-byte lookup leaf is inlined here, and
/// the fixed flag table is likewise a host seam; neither changes observable
/// return values.
///
/// # Safety
///
/// `value` must meet [`string_object_codepoint_at`]'s readable object/payload
/// contract. The installed byte map and character-flag table must be valid for
/// every selected lookup. As in retailOS, there are no NULL guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_initial_sort_key(value: *const StringObject) -> u32 {
    let mut index = 0_u32;
    let first_codepoint = loop {
        let codepoint = string_object_codepoint_at(value, index as i32);
        if codepoint != b' ' as u32 {
            break codepoint;
        }
        index = index.wrapping_add(1);
    };

    let mapped_key = byte_map_lookup(current_byte_map(), first_codepoint);
    if mapped_key == 0 {
        return if first_codepoint == 0 || first_codepoint >= 0x2e80 {
            REJECTED_KEY
        } else {
            UNSUPPORTED_KEY
        };
    }

    if current_character_flags().add(mapped_key as usize).read() & DIGIT_FLAG != 0 {
        UNSUPPORTED_KEY
    } else {
        mapped_key as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use parking_lot::Mutex;
    use std::ptr;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut MAP_BYTES: [u8; 256] = [0; 256];
    static mut CHARACTER_FLAGS: [u8; 256] = [0; 256];
    static mut BYTE_MAP_GETTER_CALLS: usize = 0;

    unsafe extern "C" fn test_byte_map() -> *const ByteMap {
        BYTE_MAP_GETTER_CALLS += 1;
        core::ptr::addr_of!(TEST_BYTE_MAP)
    }

    static mut TEST_BYTE_MAP: ByteMap = ByteMap {
        first: 0,
        last: 0x7f,
        bytes: core::ptr::null(),
    };

    struct OpsRestore;

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                STRING_OBJECT_INITIAL_SORT_KEY_OPS = DEFAULT_STRING_OBJECT_INITIAL_SORT_KEY_OPS;
            }
        }
    }

    fn with_fixture(run: impl FnOnce()) {
        let _lock = OPS_LOCK.lock();
        unsafe {
            MAP_BYTES = [0; 256];
            CHARACTER_FLAGS = [0; 256];
            BYTE_MAP_GETTER_CALLS = 0;
            TEST_BYTE_MAP.bytes = core::ptr::addr_of!(MAP_BYTES).cast();
            STRING_OBJECT_INITIAL_SORT_KEY_OPS = StringObjectInitialSortKeyOps {
                byte_map: test_byte_map,
                character_flags: core::ptr::addr_of!(CHARACTER_FLAGS).cast(),
            };
        }
        let _restore = OpsRestore;
        run();
    }

    fn string(bytes: &[u8]) -> StringObject {
        StringObject {
            vtable: ptr::null(),
            payload: bytes.as_ptr().cast_mut(),
        }
    }

    #[test]
    fn skips_spaces_then_returns_the_mapped_key() {
        with_fixture(|| unsafe {
            MAP_BYTES[b'a' as usize] = b'A';
            let value = string(b"   alpha\0");

            assert_eq!(string_object_initial_sort_key(&value), b'A' as u32);
            assert_eq!(BYTE_MAP_GETTER_CALLS, 1);
        });
    }

    #[test]
    fn distinguishes_unmapped_terminator_small_and_cjk_codepoints() {
        with_fixture(|| unsafe {
            let empty = string(b"\0");
            let punctuation = string(b"!\0");
            let cjk = string(&[0xe4, 0xb8, 0x80, 0]);

            assert_eq!(string_object_initial_sort_key(&empty), REJECTED_KEY);
            assert_eq!(string_object_initial_sort_key(&punctuation), UNSUPPORTED_KEY);
            assert_eq!(string_object_initial_sort_key(&cjk), REJECTED_KEY);
        });
    }

    #[test]
    fn rejects_digit_flag_after_mapping_but_keeps_unflagged_high_byte_keys() {
        with_fixture(|| unsafe {
            MAP_BYTES[b'9' as usize] = b'9';
            CHARACTER_FLAGS[b'9' as usize] = DIGIT_FLAG;
            let digit = string(b"9\0");
            assert_eq!(string_object_initial_sort_key(&digit), UNSUPPORTED_KEY);

            MAP_BYTES[b'x' as usize] = 0x80;
            let high_key = string(b"x\0");
            assert_eq!(string_object_initial_sort_key(&high_key), 0x80);
        });
    }
}
