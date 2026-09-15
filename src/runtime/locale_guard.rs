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
use crate::heap::veneers::operator_new_tag3;
use crate::libc::strcpy::strcpy;
use crate::libc::strlen::strlen;
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
    new: unsafe extern "C" fn(usize) -> *mut u8,
    strcpy: unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8,
    delete: unsafe extern "C" fn(*mut u8),
}

#[cfg(test)]
static mut TEST_OPS: LocaleGuardTestOps = LocaleGuardTestOps {
    setlocale: setlocale_core,
    new: operator_new_tag3,
    strcpy,
    delete: operator_delete_tag3,
};

#[cfg(test)]
#[inline(always)]
unsafe fn restore_and_release(mask: u32, saved_name: *const u8) {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(TEST_OPS));
    (ops.setlocale)(mask, saved_name);
    (ops.delete)(saved_name.cast_mut());
}

/// locale_guard_init — original: `FUN_082670e0` @ `0x082670e0` (92 bytes;
/// next function begins at `0x0826713c`; 5 direct `bl` call sites, all
/// unconditional, binary-scanned by decoding every ARM B/BL word in
/// `osos.dec`).
///
/// Initializes a two-word temporary-locale guard: saves `mask`, captures the
/// current locale name through `setlocale_core(mask, NULL)`, duplicates that
/// non-NULL name in a tag-3 allocation, then installs `name`. The allocation
/// is deliberately attempted only for a non-NULL saved name; allocation
/// failure is still passed to `strcpy`, exactly as the firmware does.
///
/// Deviation: host tests substitute the four external effects so they can
/// observe the target call order and allocation size without using firmware
/// locale state or heap; the target path calls the already ported seams.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn locale_guard_init(guard: *mut LocaleGuard, name: *const u8, mask: u32) -> *mut LocaleGuard {
    (*guard).mask = mask;
    #[cfg(test)]
    let saved_name = {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(TEST_OPS));
        (ops.setlocale)(mask, core::ptr::null())
    };
    #[cfg(not(test))]
    let saved_name = setlocale_core(mask, core::ptr::null());
    (*guard).saved_name = saved_name;
    if !saved_name.is_null() {
        #[cfg(test)]
        {
            let ops = core::ptr::read_volatile(core::ptr::addr_of!(TEST_OPS));
            let copy = (ops.new)(strlen(saved_name).wrapping_add(1));
            (ops.strcpy)(copy, saved_name);
            (*guard).saved_name = copy;
        }
        #[cfg(not(test))]
        {
            let copy = operator_new_tag3(strlen(saved_name).wrapping_add(1));
            strcpy(copy, saved_name);
            (*guard).saved_name = copy;
        }
    }
    #[cfg(test)]
    {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(TEST_OPS));
        (ops.setlocale)(mask, name);
    }
    #[cfg(not(test))]
    setlocale_core(mask, name);
    guard
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
    use super::{locale_guard_init, locale_guard_restore, LocaleGuard, LocaleGuardTestOps, TEST_OPS};
    use crate::libc::strlen::strlen;

    static mut SETLOCALE_CALLS: u32 = 0;
    static mut DELETE_CALLS: u32 = 0;
    static mut LAST_MASK: u32 = 0;
    static mut LAST_NAME: *const u8 = core::ptr::null();
    static mut LAST_DELETE: *mut u8 = core::ptr::null_mut();
    static mut NEW_CALLS: u32 = 0;
    static mut STRCPY_CALLS: u32 = 0;
    static mut LAST_NEW_SIZE: usize = 0;
    static mut LAST_STRCPY_SRC: *const u8 = core::ptr::null();
    static mut LOCALE_RESULT: *const u8 = core::ptr::null();
    static mut LOCALE_CALLS: u32 = 0;
    static mut LAST_LOCALE_NAME: *const u8 = core::ptr::null();
    static mut COPY_BUFFER: [u8; 16] = [0; 16];

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

    unsafe extern "C" fn record_locale(mask: u32, name: *const u8) -> *const u8 {
        SETLOCALE_CALLS += 1;
        LAST_MASK = mask;
        LAST_NAME = name;
        LOCALE_CALLS += 1;
        LAST_LOCALE_NAME = name;
        LOCALE_RESULT
    }

    unsafe extern "C" fn record_new(size: usize) -> *mut u8 {
        NEW_CALLS += 1;
        LAST_NEW_SIZE = size;
        core::ptr::addr_of_mut!(COPY_BUFFER).cast()
    }

    unsafe extern "C" fn record_strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
        STRCPY_CALLS += 1;
        LAST_STRCPY_SRC = src;
        core::ptr::copy_nonoverlapping(src, dst, strlen(src) + 1);
        dst
    }

    #[test]
    fn restores_and_releases_only_nonnull_saved_names() {
        unsafe {
            let original_ops = core::ptr::read_volatile(core::ptr::addr_of!(TEST_OPS));
            core::ptr::addr_of_mut!(TEST_OPS).write(LocaleGuardTestOps {
                setlocale: record_setlocale,
                new: original_ops.new,
                strcpy: original_ops.strcpy,
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

    #[test]
    fn saves_the_prior_locale_then_installs_requested_locale() {
        unsafe {
            let original_ops = core::ptr::read_volatile(core::ptr::addr_of!(TEST_OPS));
            core::ptr::addr_of_mut!(TEST_OPS).write(LocaleGuardTestOps {
                setlocale: record_locale,
                new: record_new,
                strcpy: record_strcpy,
                delete: original_ops.delete,
            });
            let prior_name = b"en_US.UTF-8\0".as_ptr();
            let requested_name = b"C\0".as_ptr();
            LOCALE_RESULT = prior_name;
            SETLOCALE_CALLS = 0;
            NEW_CALLS = 0;
            STRCPY_CALLS = 0;
            LAST_NEW_SIZE = 0;
            LAST_STRCPY_SRC = core::ptr::null();
            LAST_LOCALE_NAME = core::ptr::null();
            COPY_BUFFER = [0; 16];

            let mut guard = LocaleGuard { mask: 0, saved_name: core::ptr::null() };
            assert_eq!(locale_guard_init(&mut guard, requested_name, 0x12).cast::<()>(), (&mut guard as *mut LocaleGuard).cast());
            assert_eq!(SETLOCALE_CALLS, 2);
            assert_eq!(LAST_MASK, 0x12);
            assert_eq!(LAST_NAME, requested_name);
            assert_eq!(LAST_LOCALE_NAME, requested_name);
            assert_eq!(NEW_CALLS, 1);
            assert_eq!(LAST_NEW_SIZE, 12);
            assert_eq!(STRCPY_CALLS, 1);
            assert_eq!(LAST_STRCPY_SRC, prior_name);
            assert_eq!(guard.mask, 0x12);
            assert_eq!(guard.saved_name, core::ptr::addr_of!(COPY_BUFFER).cast());
            assert_eq!(&COPY_BUFFER[..12], b"en_US.UTF-8\0");

            LOCALE_RESULT = core::ptr::null();
            NEW_CALLS = 0;
            STRCPY_CALLS = 0;
            let mut no_saved_name = LocaleGuard { mask: 0, saved_name: prior_name };
            locale_guard_init(&mut no_saved_name, requested_name, 8);
            assert_eq!(NEW_CALLS, 0, "NULL prior name skips allocation");
            assert_eq!(STRCPY_CALLS, 0, "NULL prior name skips copy");
            assert_eq!(no_saved_name.mask, 8);
            assert!(no_saved_name.saved_name.is_null());

            core::ptr::addr_of_mut!(TEST_OPS).write(original_ops);
        }
    }
}
