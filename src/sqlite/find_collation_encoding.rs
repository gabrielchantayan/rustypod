//! Select one encoding-specific SQLite collation descriptor.
//!
//! - `find_collation_encoding` — original: `FUN_08378ad0` @ `0x08378ad0`
//!   (52 bytes; 13 `bl` call sites, binary-scanned — all unconditional).
//!
//! The retail body chooses the three-`CollSeq` set for `name`: a NULL name
//! loads the handle's default set from word 11 (`sqlite3 + 0x2c`); otherwise
//! it calls the unported `0x082ce220` helper with `(db, name, name_len,
//! create)`. A non-NULL set is then indexed as `(encoding - 1) * 20`; a NULL
//! set stays NULL. Its raw instructions are a `movs` NULL test, the optional
//! direct `bl`, and `encoding * 20 - 20` address arithmetic.
//!
//! Deliberate deviation: the direct call to unported `0x082ce220` is a
//! volatile hook. On target its default calls that exact retail address; host
//! tests install a recorder. The helper's precise symbolic identity is not
//! claimed here — only its observed input/output contract is used.

/// RetailOS load address of the helper reached by the non-NULL-name path.
pub const COLLATION_SET_LOOKUP_ADDRESS: usize = 0x082c_e220;

/// The unported helper's observed ABI: obtain the base of a three-element,
/// 20-byte-stride collation set for `(name, name_len, create)`.
pub type CollationSetLookup = unsafe extern "C" fn(
    db: *mut u8,
    name: *const u8,
    name_len: i32,
    create: i32,
) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_collation_set_lookup(
    db: *mut u8,
    name: *const u8,
    name_len: i32,
    create: i32,
) -> *mut u8 {
    let lookup: CollationSetLookup = core::mem::transmute(COLLATION_SET_LOOKUP_ADDRESS);
    lookup(db, name, name_len, create)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_collation_set_lookup(
    _db: *mut u8,
    _name: *const u8,
    _name_len: i32,
    _create: i32,
) -> *mut u8 {
    panic!("find_collation_encoding requires retail helper @ 0x082ce220")
}

/// The unported collation-set lookup, replaceable in host tests.
#[derive(Clone, Copy)]
pub struct FindCollationEncodingHooks {
    pub lookup: CollationSetLookup,
}

/// On target, retain the stock call to the unresolved helper.
#[cfg(target_os = "none")]
pub const DEFAULT_FIND_COLLATION_ENCODING_HOOKS: FindCollationEncodingHooks =
    FindCollationEncodingHooks {
        lookup: retail_collation_set_lookup,
    };

/// Host callers must provide the unresolved helper explicitly.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_FIND_COLLATION_ENCODING_HOOKS: FindCollationEncodingHooks =
    FindCollationEncodingHooks {
        lookup: missing_collation_set_lookup,
    };

/// Active unported-helper dispatch. The volatile load preserves the target
/// call and prevents LLVM from replacing the default with a builtin or fold.
pub static mut FIND_COLLATION_ENCODING_HOOKS: FindCollationEncodingHooks =
    DEFAULT_FIND_COLLATION_ENCODING_HOOKS;

#[inline(always)]
unsafe fn collation_set_lookup_op() -> CollationSetLookup {
    core::ptr::read_volatile(core::ptr::addr_of!(FIND_COLLATION_ENCODING_HOOKS.lookup))
}

/// Select the `encoding` member of a collation set.
///
/// # Safety
/// `db` must be a valid SQLite handle. When `name` is NULL, word 11 of `db`
/// must hold the default collation-set pointer. Otherwise `name` must be
/// readable for `name_len` (or meet the stock helper's negative-length
/// convention); on target the helper at [`COLLATION_SET_LOOKUP_ADDRESS`] must
/// be callable. `encoding` is the retail SQLite encoding selector, 1 through
/// 3.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn find_collation_encoding(
    db: *mut u32,
    encoding: u32,
    name: *const u8,
    name_len: i32,
    create: i32,
) -> *mut u8 {
    let set = if name.is_null() {
        // `ldr r0,[r0,#44]`: use a word index so host pointer width cannot
        // move this 32-bit target field.
        db.add(11).read() as usize as *mut u8
    } else {
        collation_set_lookup_op()(db.cast(), name, name_len, create)
    };

    if set.is_null() {
        core::ptr::null_mut()
    } else {
        // `add r1,r4,r4,lsl #2; add r0,r0,r1,lsl #2; sub r0,r0,#20`.
        // The valid retail encodings are 1, 2, and 3.
        set.add(encoding.wrapping_sub(1) as usize * 20)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec;
    use std::vec::Vec;

    static HOOK_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_FIND_COLLATION_ENCODING, 0x1000).map(|p| p as usize)
    });
    static mut LOOKUP_RESULT: *mut u8 = core::ptr::null_mut();
    static mut LOOKUP_CALLS: Vec<(*mut u8, *const u8, i32, i32)> = Vec::new();

    unsafe extern "C" fn recording_lookup(
        db: *mut u8,
        name: *const u8,
        name_len: i32,
        create: i32,
    ) -> *mut u8 {
        (*core::ptr::addr_of_mut!(LOOKUP_CALLS)).push((db, name, name_len, create));
        *core::ptr::addr_of!(LOOKUP_RESULT)
    }

    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            unsafe {
                FIND_COLLATION_ENCODING_HOOKS = DEFAULT_FIND_COLLATION_ENCODING_HOOKS;
            }
        }
    }

    fn install_recorder(result: *mut u8) -> HookGuard {
        unsafe {
            LOOKUP_RESULT = result;
            (*core::ptr::addr_of_mut!(LOOKUP_CALLS)).clear();
            FIND_COLLATION_ENCODING_HOOKS = FindCollationEncodingHooks {
                lookup: recording_lookup,
            };
        }
        HookGuard
    }

    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|p| p as *mut u8)
    }

    unsafe fn set_default_set(slab: *mut u8, set: *mut u8) {
        slab.cast::<u32>().add(11).write(set as u32);
    }

    #[test]
    fn null_name_selects_default_without_lookup() {
        let _lock = HOOK_LOCK.lock();
        let Some(slab) = try_slab() else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        let default_set = unsafe { slab.add(0x100) };
        unsafe {
            set_default_set(slab, default_set);
            let _hooks = install_recorder(slab.add(0x200));
            let found = find_collation_encoding(slab.cast(), 2, core::ptr::null(), -1, 1);
            assert_eq!(found, default_set.add(20));
            assert!(LOOKUP_CALLS.is_empty(), "NULL name bypasses the helper");
        }
    }

    #[test]
    fn named_lookup_forwards_arguments_then_selects_requested_encoding() {
        let _lock = HOOK_LOCK.lock();
        let Some(slab) = try_slab() else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        let set = unsafe { slab.add(0x200) };
        let name = b"NOCASE\0";
        unsafe {
            let _hooks = install_recorder(set);
            let found = find_collation_encoding(slab.cast(), 3, name.as_ptr(), -1, 0);
            assert_eq!(found, set.add(40));
            assert_eq!(LOOKUP_CALLS, vec![(slab, name.as_ptr(), -1, 0)]);
        }
    }

    #[test]
    fn failed_named_lookup_stays_null() {
        let _lock = HOOK_LOCK.lock();
        let Some(slab) = try_slab() else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        let name = b"missing\0";
        unsafe {
            let _hooks = install_recorder(core::ptr::null_mut());
            assert!(find_collation_encoding(slab.cast(), 1, name.as_ptr(), 7, 1).is_null());
            assert_eq!(LOOKUP_CALLS, vec![(slab, name.as_ptr(), 7, 1)]);
        }
    }

    #[test]
    fn each_valid_encoding_selects_its_twenty_byte_record() {
        let _lock = HOOK_LOCK.lock();
        let Some(slab) = try_slab() else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        let default_set = unsafe { slab.add(0x100) };
        unsafe {
            set_default_set(slab, default_set);
            let _hooks = install_recorder(core::ptr::null_mut());
            for encoding in 1..=3 {
                assert_eq!(
                    find_collation_encoding(slab.cast(), encoding, core::ptr::null(), 0, 0),
                    default_set.add((encoding - 1) as usize * 20),
                );
            }
            assert!(LOOKUP_CALLS.is_empty());
        }
    }
}
