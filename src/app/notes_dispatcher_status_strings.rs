//! `notes_dispatcher_status_strings` — original: `FUN_0828a978` @
//! `0x0828a978` (72 bytes of code, `0x0828a978..0x0828a9c0`; the adjacent
//! literal pool is `0x0828a9c0..0x0828a9d4`, and the next function begins at
//! `0x0828a9d4`).
//!
//! Raw ARM loads the notes dispatcher's mode word at `+0x4e8`, then invokes
//! virtual slot `+0x58` with the dispatcher, `StSt`, and `0x4190` for mode
//! zero or `0x4195` otherwise. It tail-dispatches the same slot with `Str `
//! and `0x41a1`. The string resource IDs are retained as words because their
//! display text is not established.
//!
//! **No plain direct `bl` calls or predicated `bl` calls.** The body has one
//! unconditional indirect `blx` and one `bx` tail dispatch through vtable
//! slot `+0x58`; the five Ghidra call sites are callers, not calls made here.
//!
//! Deliberate deviation: on 64-bit hosts the vtable uses pointer-width slots,
//! while target builds retain the retailOS `+0x58` slot. The context's mode is
//! a named field on hosts but remains word `+0x4e8` on the target.

#[cfg(test)]
extern crate std;

const STATUS_STRING: u32 = 0x5374_5374; // `StSt`
const SECONDARY_STRING: u32 = 0x5374_7220; // `Str `
const MODE_ZERO_ARGUMENT: u32 = 0x0000_4190;
const MODE_NONZERO_ARGUMENT: u32 = 0x0000_4195;
const SECONDARY_ARGUMENT: u32 = 0x0000_41a1;
const MODE_WORD_INDEX: usize = 0x4e8 / 4;

/// Vtable portion used by the notes dispatcher.
///
/// `display_status_string` is the retailOS slot `+0x58` on 32-bit ARM.
#[repr(C)]
pub struct NotesDispatcherVtable {
    _unused_slots: [usize; 22],
    pub display_status_string: unsafe extern "C" fn(*mut u8, u32, u32),
}

/// Recovered fields of the notes dispatcher relevant to status-string output.
#[repr(C)]
pub struct NotesDispatcher {
    pub vtable: *const NotesDispatcherVtable,
    _before_mode: [u32; MODE_WORD_INDEX - 1],
    pub mode: u32,
}

/// Dispatches the notes controller's primary and secondary status strings.
///
/// # Safety
///
/// `dispatcher` must point to a retailOS notes dispatcher with a readable
/// vtable and callable slot `+0x58`; stock code makes no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn notes_dispatcher_status_strings(dispatcher: *mut NotesDispatcher) {
    let mode = if cfg!(target_os = "none") {
        dispatcher.cast::<u32>().add(MODE_WORD_INDEX).read()
    } else {
        (*dispatcher).mode
    };
    let dispatch = (*(*dispatcher).vtable).display_status_string;
    dispatch(
        dispatcher.cast(),
        STATUS_STRING,
        if mode == 0 { MODE_ZERO_ARGUMENT } else { MODE_NONZERO_ARGUMENT },
    );
    dispatch(dispatcher.cast(), SECONDARY_STRING, SECONDARY_ARGUMENT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(usize, u32, u32); 2] = [(0, 0, 0); 2];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_dispatch(dispatcher: *mut u8, string: u32, argument: u32) {
        CALLS[CALL_COUNT] = (dispatcher as usize, string, argument);
        CALL_COUNT += 1;
    }

    fn assert_mode(mode: u32, primary_argument: u32) {
        let vtable = NotesDispatcherVtable {
            _unused_slots: [0; 22],
            display_status_string: record_dispatch,
        };
        let mut dispatcher = NotesDispatcher {
            vtable: &vtable,
            _before_mode: [0; MODE_WORD_INDEX - 1],
            mode,
        };
        unsafe {
            CALL_COUNT = 0;
            notes_dispatcher_status_strings(&mut dispatcher);
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS[0], (&mut dispatcher as *mut NotesDispatcher as usize, STATUS_STRING, primary_argument));
            assert_eq!(CALLS[1], (&mut dispatcher as *mut NotesDispatcher as usize, SECONDARY_STRING, SECONDARY_ARGUMENT));
        }
    }

    #[test]
    fn dispatches_mode_zero_primary_then_secondary_string() {
        let _guard = TEST_LOCK.lock();
        assert_mode(0, MODE_ZERO_ARGUMENT);
    }

    #[test]
    fn dispatches_any_nonzero_mode_with_alternate_primary_argument() {
        let _guard = TEST_LOCK.lock();
        assert_mode(u32::MAX, MODE_NONZERO_ARGUMENT);
    }
}
