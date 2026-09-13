//! `locale_guard_restore` — original: `FUN_0826713c` @ `0x0826713c`
//! (44 bytes).
//!
//! This is the destructor for the two-word temporary-locale guard assembled
//! by the adjacent constructor at `0x082670e0`. Its first word is the locale
//! category mask; its second is an owned copy of the prior locale spelling.
//! When that copy is non-NULL, the destructor restores it through
//! `setlocale_core`, releases it with tag-3 C++ delete, and returns the guard
//! unchanged. A NULL saved-name skips both calls. Raw `osos.dec` has six
//! direct, unconditional `bl` callers at 0x08267488, 0x082a7094, 0x082a71b8,
//! 0x082a79ac, 0x082a7ba4, and 0x082a8744; it has no tail `b` callers.
//!
//! Deviation: the ARM calls are normal Rust calls; `operator_delete_tag3`
//! already models its own target tail branch. Host-only callback substitution
//! observes the two external effects without making host tests use the
//! firmware heap.

use crate::heap::veneers::operator_delete_tag3;
use crate::runtime::locale::setlocale_core;

/// The target's temporary-locale owner: `{ mask, saved_name }`.
///
/// `saved_name` is a target-width pointer, so the target record is eight
/// bytes. `repr(C)` retains that word layout on ARM while keeping host tests
/// correctly laid out for their native-width pointer.
#[repr(C)]
pub struct LocaleGuard {
    pub mask: u32,
    pub saved_name: *const u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::size_of::<LocaleGuard>()];

#[cfg(test)]
#[derive(Clone, Copy)]
struct LocaleGuardTestOps {
    setlocale: unsafe extern "C" fn(u32, *const u8) -> *const u8,
    delete: unsafe extern "C" fn(*mut u8),
}

#[cfg(test)]
static mut TEST_OPS: LocaleGuardTestOps = LocaleGuardTestOps {
    setlocale: setlocale_core,
    delete: operator_delete_tag3,
};

#[cfg(test)]
#[inline(always)]
unsafe fn restore_and_release(mask: u32, saved_name: *const u8) {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(TEST_OPS));
    (ops.setlocale)(mask, saved_name);
    (ops.delete)(saved_name.cast_mut());
}

/// locale_guard_restore — original: `FUN_0826713c` @ `0x0826713c` (44 bytes).
///
/// Restores and releases a non-NULL saved locale name, then returns `guard`.
/// It deliberately leaves both guard words intact, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn locale_guard_restore(guard: *mut LocaleGuard) -> *mut LocaleGuard {
    let saved_name = (*guard).saved_name;
    if !saved_name.is_null() {
        #[cfg(test)]
        restore_and_release((*guard).mask, saved_name);
        #[cfg(not(test))]
        {
            setlocale_core((*guard).mask, saved_name);
            operator_delete_tag3(saved_name.cast_mut());
        }
    }
    guard
}

#[cfg(test)]
mod tests {
    use super::{locale_guard_restore, LocaleGuard, LocaleGuardTestOps, TEST_OPS};

    static mut SETLOCALE_CALLS: u32 = 0;
    static mut DELETE_CALLS: u32 = 0;
    static mut LAST_MASK: u32 = 0;
    static mut LAST_NAME: *const u8 = core::ptr::null();
    static mut LAST_DELETE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_setlocale(mask: u32, name: *const u8) -> *const u8 {
        SETLOCALE_CALLS += 1;
        LAST_MASK = mask;
        LAST_NAME = name;
        core::ptr::null()
    }

    unsafe extern "C" fn record_delete(ptr: *mut u8) {
        DELETE_CALLS += 1;
        LAST_DELETE = ptr;
    }

    #[test]
    fn restores_and_releases_only_nonnull_saved_names() {
        unsafe {
            let original_ops = core::ptr::read_volatile(core::ptr::addr_of!(TEST_OPS));
            core::ptr::addr_of_mut!(TEST_OPS).write(LocaleGuardTestOps {
                setlocale: record_setlocale,
                delete: record_delete,
            });
            SETLOCALE_CALLS = 0;
            DELETE_CALLS = 0;
            LAST_MASK = 0;
            LAST_NAME = core::ptr::null();
            LAST_DELETE = core::ptr::null_mut();

            let saved_name = b"*00000000\0".as_ptr();
            let mut guard = LocaleGuard { mask: 0x1f, saved_name };
            assert_eq!(locale_guard_restore(&mut guard).cast::<()>(), (&mut guard as *mut LocaleGuard).cast());
            assert_eq!(SETLOCALE_CALLS, 1);
            assert_eq!(DELETE_CALLS, 1);
            assert_eq!(LAST_MASK, 0x1f);
            assert_eq!(LAST_NAME, saved_name);
            assert_eq!(LAST_DELETE, saved_name.cast_mut());
            assert_eq!(guard.mask, 0x1f, "destructor must retain the mask word");
            assert_eq!(guard.saved_name, saved_name, "destructor must retain the saved-name word");

            SETLOCALE_CALLS = 0;
            DELETE_CALLS = 0;
            let mut empty_guard = LocaleGuard { mask: 2, saved_name: core::ptr::null() };
            assert_eq!(locale_guard_restore(&mut empty_guard).cast::<()>(), (&mut empty_guard as *mut LocaleGuard).cast());
            assert_eq!(SETLOCALE_CALLS, 0, "NULL skips locale restoration");
            assert_eq!(DELETE_CALLS, 0, "NULL skips tag-3 delete");
            assert_eq!(empty_guard.mask, 2);
            assert!(empty_guard.saved_name.is_null());

            core::ptr::addr_of_mut!(TEST_OPS).write(original_ops);
        }
    }
}
