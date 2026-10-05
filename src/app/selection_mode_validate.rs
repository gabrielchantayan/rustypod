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
//! Deliberate deviations: the verified first-match lookup is now implemented
//! in Rust on both firmware and host builds; no behavioral deviation.

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


/// selection_mode_validate — original: `FUN_081e4374` @ `0x081e4374` (88 bytes).
///
/// Reads a mode byte through `reader`'s vtable. Modes 0 and 1 are forwarded to
/// first-match lookup; its successful index is stored at state +0x1078.
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
    let result = unsafe { super::find_selection_mode::find_selection_mode(state, mode, state.add(0x1078).cast()) };
    if result == 0 { 0 } else { 3 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicU8, Ordering};

    static MODE: AtomicU8 = AtomicU8::new(0);

    unsafe extern "C" fn read_mode(_: *mut ModeSelectionReader, out: *mut u8) {
        unsafe { out.write(MODE.load(Ordering::Relaxed)) };
    }


    #[test]
    fn accepts_binary_modes_and_preserves_index_on_failure() {
        let vtable = ModeSelectionReaderVTable {
            slots_before_read: [None, None],
            read_mode,
        };
        let mut reader = ModeSelectionReader { vtable: &vtable };
        let mut state = [0u32; 0x500];
        let bytes = state.as_mut_ptr().cast::<u8>();
        unsafe {
            bytes.add(0x128e).write(1);
            bytes.add(0x128e + 0x50).write(0);
        }
        for (mode, count, expected, index) in [
            (0, 2, 0, 1), (1, 2, 0, 0), (1, 0, 3, 99), (2, 2, 3, 99),
        ] {
            MODE.store(mode, Ordering::Relaxed);
            state[0x1080 / 4] = count;
            state[0x1078 / 4] = 99;
            let result = unsafe { selection_mode_validate(bytes, &mut reader) };
            assert_eq!(result, expected);
            assert_eq!(state[0x1078 / 4], index);
        }
    }
}
