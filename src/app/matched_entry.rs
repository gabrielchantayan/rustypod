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
//! The matcher @ 0x08053b14, result constructor @ 0x080fe500, and readiness
//! helper @ 0x080fe1c4 are unported. On device these edges call their verified
//! retail addresses directly; host tests replace only those edges. The
//! refcounted-handle constructor @ 0x0839ebc4, attach-equivalent @ 0x0839ec2c,
//! dereference alias @ 0x083d6180, and stack-handle release wrapper @
//! 0x0816ccb0 use their existing canonical Rust ports.

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

/// ABI of the unported entry matcher @ 0x08053b14.
pub type EntryMatchNext = unsafe extern "C" fn(*mut u8, *mut u8, u32) -> *mut u8;
/// ABI of the unported result constructor @ 0x080fe500.
pub type EntryResultConstruct = unsafe extern "C" fn(*mut u8, *mut u8, u32, u8) -> *mut u8;
/// ABI of the unported readiness helper @ 0x080fe1c4.
pub type EntryResultEnsureReady = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
unsafe fn retail_entry_match_next(
    entries: *mut u8,
    previous: *mut u8,
    match_key: u32,
) -> *mut u8 {
    let f: EntryMatchNext = unsafe { core::mem::transmute(0x0805_3b14usize) };
    unsafe { f(entries, previous, match_key) }
}

#[cfg(target_os = "none")]
unsafe fn retail_entry_result_construct(
    block: *mut u8,
    entry: *mut u8,
    match_key: u32,
    entry_kind: u8,
) -> *mut u8 {
    let f: EntryResultConstruct = unsafe { core::mem::transmute(0x080f_e500usize) };
    unsafe { f(block, entry, match_key, entry_kind) }
}

#[cfg(target_os = "none")]
unsafe fn retail_entry_result_ensure_ready(result: *mut u8, mode: u32) {
    let f: EntryResultEnsureReady = unsafe { core::mem::transmute(0x080f_e1c4usize) };
    unsafe { f(result, mode) }
}

/// Host replacement for the unported entry matcher @ 0x08053b14.
#[cfg(not(target_os = "none"))]
pub static mut ENTRY_MATCH_NEXT: EntryMatchNext = missing_entry_match_next;
/// Host replacement for the unported result constructor @ 0x080fe500.
#[cfg(not(target_os = "none"))]
pub static mut ENTRY_RESULT_CONSTRUCT: EntryResultConstruct = missing_entry_result_construct;
/// Host replacement for the unported readiness helper @ 0x080fe1c4.
#[cfg(not(target_os = "none"))]
pub static mut ENTRY_RESULT_ENSURE_READY: EntryResultEnsureReady = missing_entry_result_ensure_ready;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_entry_match_next(
    _entries: *mut u8,
    _previous: *mut u8,
    _match_key: u32,
) -> *mut u8 {
    panic!("matched_entry_select_nth requires matcher 0x08053b14")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_entry_result_construct(
    _block: *mut u8,
    _entry: *mut u8,
    _match_key: u32,
    _entry_kind: u8,
) -> *mut u8 {
    panic!("matched_entry_select_nth requires result constructor 0x080fe500")
}

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
/// without a NULL guard. The source fields and all installed entry operations
/// must satisfy their retail pointer contracts. Existing contents of `out` are
/// not released on a no-result path, matching the original.
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
        #[cfg(target_os = "none")]
        {
            entry = unsafe { retail_entry_match_next(entries, entry, match_key) };
        }
        #[cfg(not(target_os = "none"))]
        {
            let matcher = unsafe { core::ptr::addr_of_mut!(ENTRY_MATCH_NEXT).read_volatile() };
            entry = unsafe { matcher(entries, entry, match_key) };
        }
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
    #[cfg(target_os = "none")]
    let result = unsafe {
        retail_entry_result_construct(block, entry, match_key, (*source).entry_kind)
    };
    #[cfg(not(target_os = "none"))]
    let result = unsafe {
        let construct = core::ptr::addr_of_mut!(ENTRY_RESULT_CONSTRUCT).read_volatile();
        construct(block, entry, match_key, (*source).entry_kind)
    };

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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut MATCH_RESULTS: [*mut u8; 3] = [ptr::null_mut(); 3];
    static mut MATCH_CALLS: usize = 0;
    static mut MATCH_PREVIOUS: [*mut u8; 3] = [ptr::null_mut(); 3];
    static mut MATCH_ENTRIES: *mut u8 = ptr::null_mut();
    static mut MATCH_KEY: u32 = 0;
    static mut CONSTRUCT_BLOCK: *mut u8 = ptr::null_mut();
    static mut CONSTRUCT_ENTRY: *mut u8 = ptr::null_mut();
    static mut CONSTRUCT_KEY: u32 = 0;
    static mut CONSTRUCT_KIND: u8 = 0;
    static mut ALLOC_BEFORE_CONSTRUCT: (usize, usize, usize) = (0, 0, 0);
    static mut BODY_STORAGE: *mut u8 = ptr::null_mut();
    static mut READY_CALLS: usize = 0;
    static mut READY_RESULT: *mut u8 = ptr::null_mut();
    static mut READY_MODE: u32 = 0;

    unsafe extern "C" fn recording_match_next(
        entries: *mut u8,
        previous: *mut u8,
        match_key: u32,
    ) -> *mut u8 {
        unsafe {
            MATCH_ENTRIES = entries;
            MATCH_KEY = match_key;
            MATCH_PREVIOUS[MATCH_CALLS] = previous;
            let result = MATCH_RESULTS[MATCH_CALLS];
            MATCH_CALLS += 1;
            result
        }
    }

    unsafe extern "C" fn recording_result_construct(
        block: *mut u8,
        entry: *mut u8,
        match_key: u32,
        entry_kind: u8,
    ) -> *mut u8 {
        unsafe {
            CONSTRUCT_BLOCK = block;
            CONSTRUCT_ENTRY = entry;
            CONSTRUCT_KEY = match_key;
            CONSTRUCT_KIND = entry_kind;
            ALLOC_BEFORE_CONSTRUCT = alloc_log();
            set_alloc_ret(BODY_STORAGE);
            block
        }
    }

    unsafe extern "C" fn recording_ensure_ready(result: *mut u8, mode: u32) {
        unsafe {
            READY_CALLS += 1;
            READY_RESULT = result;
            READY_MODE = mode;
        }
    }

    fn install_mocks() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            ENTRY_MATCH_NEXT = recording_match_next;
            ENTRY_RESULT_CONSTRUCT = recording_result_construct;
            ENTRY_RESULT_ENSURE_READY = recording_ensure_ready;
            MATCH_RESULTS = [ptr::null_mut(); 3];
            MATCH_CALLS = 0;
            MATCH_PREVIOUS = [ptr::null_mut(); 3];
            MATCH_ENTRIES = ptr::null_mut();
            MATCH_KEY = 0;
            CONSTRUCT_BLOCK = ptr::null_mut();
            CONSTRUCT_ENTRY = ptr::null_mut();
            CONSTRUCT_KEY = 0;
            CONSTRUCT_KIND = 0;
            ALLOC_BEFORE_CONSTRUCT = (0, 0, 0);
            BODY_STORAGE = ptr::null_mut();
            READY_CALLS = 0;
            READY_RESULT = ptr::null_mut();
            READY_MODE = 0;
        }
        (ops_guard, heap_guard)
    }

    fn restore_mocks(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe {
            ENTRY_MATCH_NEXT = missing_entry_match_next;
            ENTRY_RESULT_CONSTRUCT = missing_entry_result_construct;
            ENTRY_RESULT_ENSURE_READY = missing_entry_result_ensure_ready;
        }
        drop(guards);
    }

    #[test]
    fn selects_nth_match_wraps_it_and_optionally_makes_it_ready() {
        let guards = install_mocks();
        let mut result_storage = [0usize; 4];
        let mut body_storage = RefcountedBody {
            opaque0: 0,
            refcount: 0,
            mutex: ptr::null_mut(),
        };
        let first = 0x1111_0000usize as *mut u8;
        let second = 0x2222_0000usize as *mut u8;
        let entries = 0x3333_0000usize as *mut u8;
        let source = EntryMatchSource { header: 0, entries, entry_kind: 0xa7 };
        let mut out = ptr::null_mut();
        unsafe {
            MATCH_RESULTS = [first, second, ptr::null_mut()];
            BODY_STORAGE = (&mut body_storage as *mut RefcountedBody).cast();
            set_alloc_ret(result_storage.as_mut_ptr().cast());

            matched_entry_select_nth(&mut out, &source, 0x4a21_0003, 1, 1);

            assert_eq!(MATCH_CALLS, 2, "one initial and one successor match lookup");
            assert_eq!(MATCH_ENTRIES, entries);
            assert_eq!(MATCH_KEY, 0x4a21_0003);
            assert!(MATCH_PREVIOUS[0].is_null(), "the first lookup starts at NULL");
            assert_eq!(MATCH_PREVIOUS[1], first, "the successor receives the prior match");
            assert_eq!(ALLOC_BEFORE_CONSTRUCT, (1, 28, 2), "the result block is tag-2 new(28)");
            assert_eq!(CONSTRUCT_BLOCK, result_storage.as_mut_ptr().cast());
            assert_eq!(CONSTRUCT_ENTRY, second);
            assert_eq!(CONSTRUCT_KEY, 0x4a21_0003);
            assert_eq!(CONSTRUCT_KIND, 0xa7);
            assert_eq!(READY_CALLS, 1);
            assert_eq!(READY_RESULT, result_storage.as_mut_ptr().cast());
            assert_eq!(READY_MODE, 0, "the readiness mode is forced to zero");
            assert_eq!(out, &mut body_storage as *mut RefcountedBody);
            assert_eq!(body_storage.opaque0, result_storage.as_mut_ptr() as usize);
            assert_eq!(body_storage.refcount, 1, "temporary release leaves the published handle owning one reference");
            assert_eq!(alloc_log(), (2, 12, 2), "the handle body is the second tag-2 allocation");
        }
        restore_mocks(guards);
    }

    #[test]
    fn negative_occurrence_skips_matcher_and_clears_output() {
        let guards = install_mocks();
        let source = EntryMatchSource {
            header: 0,
            entries: 0x3333_0000usize as *mut u8,
            entry_kind: 0,
        };
        let mut out = 0x1111_0000usize as *mut RefcountedBody;
        unsafe {
            matched_entry_select_nth(&mut out, &source, 7, 1, -1);
            assert_eq!(MATCH_CALLS, 0, "signed negative occurrence bypasses the loop");
            assert!(out.is_null(), "the NULL handle constructor clears output");
            assert_eq!(READY_CALLS, 0);
        }
        restore_mocks(guards);
    }

    #[test]
    fn exhausted_sequence_clears_output_without_constructing() {
        let guards = install_mocks();
        let source = EntryMatchSource {
            header: 0,
            entries: 0x3333_0000usize as *mut u8,
            entry_kind: 0x3c,
        };
        let first = 0x1111_0000usize as *mut u8;
        let mut out = 0x2222_0000usize as *mut RefcountedBody;
        unsafe {
            MATCH_RESULTS = [first, ptr::null_mut(), ptr::null_mut()];
            matched_entry_select_nth(&mut out, &source, 9, 0, 1);
            assert_eq!(MATCH_CALLS, 2, "the missing second match terminates selection");
            assert_eq!(MATCH_PREVIOUS[1], first);
            assert!(out.is_null());
            assert!(CONSTRUCT_BLOCK.is_null(), "no result allocation or construction on exhaustion");
            assert_eq!(READY_CALLS, 0);
        }
        restore_mocks(guards);
    }

    #[test]
    fn absent_entry_collection_clears_output_without_dispatch() {
        let guards = install_mocks();
        let source = EntryMatchSource {
            header: 0,
            entries: ptr::null_mut(),
            entry_kind: 0,
        };
        let mut out = 0x1111_0000usize as *mut RefcountedBody;
        unsafe {
            matched_entry_select_nth(&mut out, &source, 0, 1, 0);
            assert_eq!(MATCH_CALLS, 0);
            assert!(out.is_null());
            assert_eq!(READY_CALLS, 0);
        }
        restore_mocks(guards);
    }
}
