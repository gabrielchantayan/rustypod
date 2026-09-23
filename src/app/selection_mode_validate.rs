//! `selection_mode_validate` — original: `FUN_081e4374` @ `0x081e4374`.
//!
//! Raw A32 establishes the exact 88-byte body `0x081e4374..0x081e43cb`;
//! `push {r3,r4,r5,r6,r7,lr}` at `0x081e43cc` starts the next function.
//! It has one unconditional direct `bl` (to `FUN_081e5100`), no predicated
//! direct `bl`, and one unconditional virtual `blx` through reader-vtable
//! slot +0x08. Three inbound direct calls are all unconditional `bl`.
//!
//! The reader writes a status byte: zero selects mode zero and one selects
//! mode one; every other value returns error 3. The selected mode is then
//! located by `FUN_081e5100`, which writes its index at state +0x1078; a
//! nonzero lookup result also maps to error 3.
//!
//! Deliberate deviations: the stock lookup remains called at its verified
//! address on-device. Host builds use a replaceable seam because firmware
//! addresses are not callable on the host.

/// Reader vtable, decoded only through slot +0x08.
#[repr(C)]
pub struct ModeSelectionReaderVTable {
    /// Slots +0x00 and +0x04.
    pub slots_before_read: [Option<unsafe extern "C" fn()>; 2],
    /// Slot +0x08: writes the selected mode byte.
    pub read_mode: unsafe extern "C" fn(*mut ModeSelectionReader, *mut u8),
}

/// Reader object, decoded only through its vtable word.
#[repr(C)]
pub struct ModeSelectionReader {
    pub vtable: *const ModeSelectionReaderVTable,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(ModeSelectionReaderVTable, read_mode)];

type FindSelectionMode = unsafe extern "C" fn(*mut u8, u32, *mut u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn find_selection_mode(state: *mut u8, mode: u32, index: *mut u32) -> u32 {
    let find: FindSelectionMode = unsafe { core::mem::transmute(0x081e_5100usize) };
    unsafe { find(state, mode, index) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_find_selection_mode(_: *mut u8, _: u32, _: *mut u32) -> u32 {
    panic!("selection_mode_validate requires FUN_081e5100")
}

#[cfg(not(target_os = "none"))]
pub static mut SELECTION_MODE_FIND: FindSelectionMode = missing_find_selection_mode;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn find_selection_mode(state: *mut u8, mode: u32, index: *mut u32) -> u32 {
    let find = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SELECTION_MODE_FIND)) };
    unsafe { find(state, mode, index) }
}

/// selection_mode_validate — original: `FUN_081e4374` @ `0x081e4374` (88 bytes).
///
/// Reads a mode byte through `reader`'s vtable. Modes 0 and 1 are forwarded to
/// the stock first-match lookup; its successful index is stored at state +0x1078.
/// Returns zero on success and 3 for an invalid mode or lookup failure.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selection_mode_validate(
    state: *mut u8,
    reader: *mut ModeSelectionReader,
) -> u32 {
    let mut mode = 0u8;
    let read_mode = unsafe { (*(*reader).vtable).read_mode };
    unsafe { read_mode(reader, &mut mode) };

    let mode = match mode {
        0 => 0,
        1 => 1,
        _ => return 3,
    };
    let result = unsafe { find_selection_mode(state, mode, state.add(0x1078).cast()) };
    if result == 0 { 0 } else { 3 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

    static MODE: AtomicU8 = AtomicU8::new(0);
    static FIND_RESULT: AtomicU32 = AtomicU32::new(0);
    static FIND_CALLS: AtomicU32 = AtomicU32::new(0);
    static SEEN_MODE: AtomicU32 = AtomicU32::new(u32::MAX);

    unsafe extern "C" fn read_mode(_: *mut ModeSelectionReader, out: *mut u8) {
        unsafe { out.write(MODE.load(Ordering::Relaxed)) };
    }

    unsafe extern "C" fn find_mode(_: *mut u8, mode: u32, index: *mut u32) -> u32 {
        FIND_CALLS.fetch_add(1, Ordering::Relaxed);
        SEEN_MODE.store(mode, Ordering::Relaxed);
        unsafe { index.write(37) };
        FIND_RESULT.load(Ordering::Relaxed)
    }

    #[test]
    fn accepts_only_binary_modes_and_preserves_lookup_result() {
        let vtable = ModeSelectionReaderVTable {
            slots_before_read: [None, None],
            read_mode,
        };
        let mut reader = ModeSelectionReader { vtable: &vtable };
        let mut state = [0u32; 0x500];
        unsafe { SELECTION_MODE_FIND = find_mode };

        for (mode, lookup_result, expected) in [(0, 0, 0), (1, 0, 0), (1, 9, 3), (2, 0, 3)] {
            MODE.store(mode, Ordering::Relaxed);
            FIND_RESULT.store(lookup_result, Ordering::Relaxed);
            FIND_CALLS.store(0, Ordering::Relaxed);
            let result = unsafe { selection_mode_validate(state.as_mut_ptr().cast(), &mut reader) };
            assert_eq!(result, expected);
            assert_eq!(FIND_CALLS.load(Ordering::Relaxed), u32::from(mode < 2));
            if mode < 2 {
                assert_eq!(SEEN_MODE.load(Ordering::Relaxed), u32::from(mode));
                assert_eq!(state[0x1078 / 4], 37);
            }
        }
    }
}
