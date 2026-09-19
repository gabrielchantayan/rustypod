//! Comparator for the eight-byte records in the `StringPool` insertion path.
//!
//! `record_u16_casefold_compare` — original: `FUN_080be778` @ **0x080be778**.
//! Raw `osos.dec` establishes a 164-byte extent: 148 instruction bytes through
//! the tail branch at `0x080be808`, then its four-word literal pool, before
//! `string_pool_copy_entry` starts at `0x080be81c`. There are four inbound
//! plain `bl` call sites and no predicated inbound calls; the body has six
//! plain `bl` instructions, no predicated `bl`, and one tail branch.
//!
//! It orders records by the u16 key at +6. Equal keys lazily creates a
//! 512-byte formatting helper, asks the unported helper to render the left
//! record into the fixed scratch StringObject, then case-fold compares that
//! payload with `right_text.c_str()`. The unported renderer and its lazy
//! constructor remain typed seams; `utf8_strcasecmp_safe` is already an
//! identified but blocked seam because retailOS's runtime fold table is not
//! recoverable from `osos.dec`.
//! Deliberate deviations: fixed firmware globals are Rust statics, and the
//! target-only seam calls replace raw retailOS entries for the two unported
//! callees. Host tests intentionally skip the target-only `cxa_atexit`
//! registration because its firmware allocator is unavailable there. The
//! case-fold core keeps the existing `string_object` seam rather than
//! inventing its unresolved table.

use core::ffi::c_void;

use crate::cxx::string_object::{
    string_object_c_str, StringObject, STRING_OBJECT_UTF8_STRCASECMP_CORE,
};
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};

const FORMATTER_CTOR_ADDRESS: usize = 0x0818_6380;
const RECORD_RENDER_ADDRESS: usize = 0x0813_1e00;
const FORMATTER_DTOR_ADDRESS: usize = 0x0817_b500;
const DSO_HANDLE: i32 = 0x089c_a09c;
const FORMATTER_TAG: u32 = 0x08ad_5d98;
const FORMATTER_CAPACITY: u32 = 0x200;

pub type FormatterCtor = unsafe extern "C" fn(tag: u32, capacity: u32) -> *mut c_void;
pub type RecordRender = unsafe extern "C" fn(
    formatter: *mut c_void,
    record: *const u8,
    scratch: *mut StringObject,
);

static mut RECORD_U16_CASEFOLD_GUARD: u32 = 0;
static mut RECORD_U16_CASEFOLD_FORMATTER: *mut c_void = core::ptr::null_mut();
static mut RECORD_U16_CASEFOLD_SCRATCH: StringObject = StringObject {
    vtable: core::ptr::null(),
    payload: core::ptr::null_mut(),
};

unsafe extern "C" fn firmware_formatter_ctor(tag: u32, capacity: u32) -> *mut c_void {
    #[cfg(target_os = "none")]
    {
        let ctor: FormatterCtor = core::mem::transmute(FORMATTER_CTOR_ADDRESS);
        return ctor(tag, capacity);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (tag, capacity);
        core::ptr::null_mut()
    }
}

unsafe extern "C" fn firmware_record_render(
    formatter: *mut c_void,
    record: *const u8,
    scratch: *mut StringObject,
) {
    #[cfg(target_os = "none")]
    {
        let render: RecordRender = core::mem::transmute(RECORD_RENDER_ADDRESS);
        render(formatter, record, scratch);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (formatter, record, scratch);
    }
}

unsafe fn register_formatter_destructor(formatter: *mut c_void) {
    #[cfg(target_os = "none")]
    {
        use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

        unsafe extern "C" fn formatter_destructor(arg: *mut c_void) {
            let destructor: ShutdownHandlerFn = core::mem::transmute(FORMATTER_DTOR_ADDRESS);
            destructor(arg);
        }

        cxa_atexit(formatter, formatter_destructor, DSO_HANDLE);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = formatter;
    }
}

pub static mut RECORD_U16_CASEFOLD_FORMATTER_CTOR: FormatterCtor = firmware_formatter_ctor;
pub static mut RECORD_U16_CASEFOLD_RENDER: RecordRender = firmware_record_render;

/// Orders `left` against `right_text` after rendering equal-key records.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn record_u16_casefold_compare(
    left: *const u8,
    right: *const u8,
    right_text: *const StringObject,
) -> i32 {
    let left_key = core::ptr::read_unaligned(left.add(6).cast::<u16>());
    let right_key = core::ptr::read_unaligned(right.add(6).cast::<u16>());
    if left_key < right_key {
        return 1;
    }
    if left_key > right_key {
        return -1;
    }

    let guard = core::ptr::addr_of_mut!(RECORD_U16_CASEFOLD_GUARD);
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let formatter = core::ptr::read_volatile(core::ptr::addr_of!(RECORD_U16_CASEFOLD_FORMATTER_CTOR))(
            FORMATTER_TAG,
            FORMATTER_CAPACITY,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!(RECORD_U16_CASEFOLD_FORMATTER), formatter);
        register_formatter_destructor(formatter);
        cxa_guard_release(guard);
    }

    let formatter = core::ptr::read_volatile(core::ptr::addr_of!(RECORD_U16_CASEFOLD_FORMATTER));
    let scratch = core::ptr::addr_of_mut!(RECORD_U16_CASEFOLD_SCRATCH);
    core::ptr::read_volatile(core::ptr::addr_of!(RECORD_U16_CASEFOLD_RENDER))(formatter, left, scratch);
    let compare = core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_UTF8_STRCASECMP_CORE));
    compare((*scratch).payload, string_object_c_str(right_text))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_ARGS: Option<(u32, u32)> = None;
    static mut RENDER_ARGS: Option<(usize, usize)> = None;
    static mut COMPARE_ARGS: Option<(usize, usize)> = None;
    static mut SCRATCH_TEXT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn ctor(tag: u32, capacity: u32) -> *mut c_void {
        CTOR_ARGS = Some((tag, capacity));
        0x1234usize as *mut c_void
    }

    unsafe extern "C" fn render(formatter: *mut c_void, record: *const u8, scratch: *mut StringObject) {
        RENDER_ARGS = Some((formatter as usize, record as usize));
        (*scratch).payload = SCRATCH_TEXT;
    }

    unsafe extern "C" fn compare(a: *const u8, b: *const u8) -> i32 {
        COMPARE_ARGS = Some((a as usize, b as usize));
        -7
    }

    #[test]
    fn orders_keys_and_renders_only_equal_keys() {
        let _lock = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut left = [0u8; 8];
        let mut right = [0u8; 8];
        let mut scratch = *b"left\0";
        let right_cstr = *b"right\0";
        let right_text = StringObject { vtable: core::ptr::null(), payload: right_cstr.as_ptr() as *mut u8 };

        unsafe {
            RECORD_U16_CASEFOLD_GUARD = 0;
            RECORD_U16_CASEFOLD_FORMATTER = core::ptr::null_mut();
            RECORD_U16_CASEFOLD_SCRATCH.payload = core::ptr::null_mut();
            RECORD_U16_CASEFOLD_FORMATTER_CTOR = ctor;
            RECORD_U16_CASEFOLD_RENDER = render;
            SCRATCH_TEXT = scratch.as_mut_ptr();
            CTOR_ARGS = None;
            RENDER_ARGS = None;
            COMPARE_ARGS = None;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(STRING_OBJECT_UTF8_STRCASECMP_CORE), compare);

            left[6..].copy_from_slice(&4u16.to_le_bytes());
            right[6..].copy_from_slice(&5u16.to_le_bytes());
            assert_eq!(record_u16_casefold_compare(left.as_ptr(), right.as_ptr(), &right_text), 1);
            right[6..].copy_from_slice(&3u16.to_le_bytes());
            assert_eq!(record_u16_casefold_compare(left.as_ptr(), right.as_ptr(), &right_text), -1);
            assert!(CTOR_ARGS.is_none());
            assert!(RENDER_ARGS.is_none());

            right[6..].copy_from_slice(&4u16.to_le_bytes());
            assert_eq!(record_u16_casefold_compare(left.as_ptr(), right.as_ptr(), &right_text), -7);
            assert_eq!(CTOR_ARGS, Some((FORMATTER_TAG, FORMATTER_CAPACITY)));
            assert_eq!(RENDER_ARGS, Some((0x1234, left.as_ptr() as usize)));
            assert_eq!(COMPARE_ARGS, Some((scratch.as_ptr() as usize, right_cstr.as_ptr() as usize)));
        }
    }
}
