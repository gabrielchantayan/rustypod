//! `matched_entry_select_nth` — original: `FUN_0826fb4c` @ **0x0826fb4c**
//! (200 bytes; 10 direct `bl` call sites).
//!
//! Raw ARM establishes the exact extent `0x0826fb4c..0x0826fc14`; the next
//! separately linked function opens at `0x0826fc14`. Decoding every ARM B/BL
//! word in `osos.dec` finds exactly ten incoming calls, all unconditional plain
//! `bl`: there are no predicated forms or plain-`b` tail callers.
//!
//! # Algorithm
//!
//! Given an opaque entry source, repeatedly call its matcher with the prior
//! match until reaching the zero-based `occurrence`. It wraps that selected
//! entry in a fresh 28-byte result object and a refcounted handle, optionally
//! asks the result to become ready, assigns the temporary handle to `out`, then
//! drops the temporary reference. A missing source collection, a negative
//! occurrence, or an exhausted match sequence instead constructs `out` from a
//! NULL implementation. This clears `out` without releasing a prior body,
//! exactly as the original's direct handle constructor does.
//!
//! # Deliberate deviations
//!
//! The matcher @ 0x08053b14 is the canonical [`entry_match_next`] Rust port.
//! The readiness helper @ 0x080fe1c4 remains a verified retail edge on device
//! and a host-test replacement. The result constructor is the canonical Rust
//! port.
//! The refcounted-handle constructor @ 0x0839ebc4, attach-equivalent @
//! 0x0839ec2c, dereference alias @ 0x083d6180, and stack-handle release
//! wrapper @ 0x0816ccb0 use their existing canonical Rust ports.

use core::ptr;

use crate::cxx::handle::{
    handle_deref_or_null, refcounted_body_attach, refcounted_body_release_dtor,
    refcounted_handle_construct, RefcountedBody,
};
use crate::heap::veneers::operator_new;

/// Opaque source header consumed by [`matched_entry_select_nth`].
///
/// The first word is not read here. On the target, `entries` is at +0x04 and
/// `entry_kind` is at +0x08. Named fields intentionally preserve that target
/// layout while keeping the host pointer full-width.
#[repr(C)]
pub struct EntryMatchSource {
    pub header: u32,
    pub entries: *mut u8,
    pub entry_kind: u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x00] = [0; core::mem::offset_of!(EntryMatchSource, header)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(EntryMatchSource, entries)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(EntryMatchSource, entry_kind)];

use crate::app::entry_match_next::entry_match_next;
use crate::app::entry_result_construct::entry_result_construct;

/// ABI of the unported readiness helper @ 0x080fe1c4.
pub type EntryResultEnsureReady = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
unsafe fn retail_entry_result_ensure_ready(result: *mut u8, mode: u32) {
    let f: EntryResultEnsureReady = unsafe { core::mem::transmute(0x080f_e1c4usize) };
    unsafe { f(result, mode) }
}

/// Host replacement for the unported readiness helper @ 0x080fe1c4.
#[cfg(not(target_os = "none"))]
pub static mut ENTRY_RESULT_ENSURE_READY: EntryResultEnsureReady = missing_entry_result_ensure_ready;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_entry_result_ensure_ready(_result: *mut u8, _mode: u32) {
    panic!("matched_entry_select_nth requires readiness helper 0x080fe1c4")
}


/// matched_entry_select_nth — original: `FUN_0826fb4c` @ **0x0826fb4c**
/// (200 bytes; 10 unconditional direct `bl` call sites).
///
/// Selects the zero-based `occurrence` matching entry from `source` and
/// publishes its result wrapper through `out`. `ensure_ready` is forwarded as
/// a Boolean: a nonzero value calls the result readiness helper with mode zero.
///
/// # Safety
///
/// `out` and `source` must be valid aligned pointers; `source` is dereferenced
/// without a NULL guard. Its entries and every matched entry must satisfy
/// [`entry_match_next`]'s retail pointer contract. Existing contents of `out`
/// are not released on a no-result path, matching the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn matched_entry_select_nth(
    out: *mut *mut RefcountedBody,
    source: *const EntryMatchSource,
    match_key: u32,
    ensure_ready: u32,
    occurrence: i32,
) {
    let entries = unsafe { (*source).entries };
    if entries.is_null() || occurrence < 0 {
        unsafe { refcounted_handle_construct(out, 0, 0) };
        return;
    }

    let mut entry = ptr::null_mut();
    let mut found = 0u32;
    loop {
        entry = unsafe { entry_match_next(entries, entry, match_key) };
        if entry.is_null() {
            unsafe { refcounted_handle_construct(out, 0, 0) };
            return;
        }
        found = found.wrapping_add(1);
        if found > occurrence as u32 {
            break;
        }
    }

    let block = unsafe { operator_new(28) };
    let result = unsafe { entry_result_construct(block, entry, match_key, (*source).entry_kind) };

    let mut temporary = ptr::null_mut();
    unsafe { refcounted_handle_construct(&mut temporary, result as usize, 0) };
    if ensure_ready != 0 {
        let result = unsafe {
            handle_deref_or_null(
                (&temporary as *const *mut RefcountedBody).cast::<*const *mut u8>(),
            )
        };
        #[cfg(target_os = "none")]
        unsafe {
            retail_entry_result_ensure_ready(result, 0);
        }
        #[cfg(not(target_os = "none"))]
        unsafe {
            let ready = core::ptr::addr_of_mut!(ENTRY_RESULT_ENSURE_READY).read_volatile();
            ready(result, 0);
        }
    }
    unsafe { refcounted_body_attach(out, temporary) };
    unsafe { refcounted_body_release_dtor(&mut temporary) };
}

