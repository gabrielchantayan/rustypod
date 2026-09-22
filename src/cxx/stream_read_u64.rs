//! `stream_read_u64` — original: `FUN_08268680` @ `0x08268680` (76 bytes;
//! three direct call sites reported by Ghidra).
//!
//! Raw ARM establishes the true 76-byte A32 extent: `push {r2,r3,r4,lr}` at
//! `0x08268680` through `pop {r2,r3,r4,pc}` at `0x082686c8`; the next real
//! function begins at `0x082686cc`. The body has no direct `bl` instructions
//! and one indirect `blx ip` through vtable slot `+0x20`. It reads two
//! little-endian words from `*cursor + offset`, advances the cursor by eight,
//! then lets the reader's byte callback transform the private eight-byte
//! scratch value before returning it.
//!
//! Deliberate deviation: the ARM stack scratch is represented by two `u32`
//! words. This preserves its target layout on hosts where `u64` alignment and
//! pointer width differ from ARM's.

/// Target vtable word index for the reader's byte callback at `+0x20`.
const BYTE_CALLBACK_VTABLE_INDEX: usize = 0x20 / 4;

/// ABI of the unrecovered byte transformation callback.
type ByteCallback = unsafe extern "C" fn(*mut u8, *mut u32, u32, u32);

/// Target-layout prefix of the reader passed to the scalar cursor wrappers.
#[repr(C)]
pub struct StreamReader {
    pub vtable: *const ByteCallback,
    pub callback_context: *mut u8,
}

/// Reads a callback-transformed 64-bit value and advances `cursor` by eight.
///
/// `reader`, `cursor`, and the selected vtable slot are deliberately unchecked,
/// matching the original. `*cursor + offset` must be aligned for a 32-bit read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_read_u64(
    reader: *mut StreamReader,
    offset: u32,
    cursor: *mut *const u8,
) -> u64 {
    let source = unsafe { (*cursor).add(offset as usize).cast::<u32>() };
    let mut words = [unsafe { source.read() }, unsafe { source.add(1).read() }];

    unsafe { *cursor = (*cursor).add(8) };

    let callback = unsafe { *(*reader).vtable.add(BYTE_CALLBACK_VTABLE_INDEX) };
    unsafe { callback((*reader).callback_context, words.as_mut_ptr(), 8, 1) };

    (words[0] as u64) | ((words[1] as u64) << 32)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLBACK_CONTEXT: *mut u8 = ptr::null_mut();
    static mut CALLBACK_WORDS: [u32; 2] = [0; 2];
    static mut CALLBACK_LENGTH: u32 = 0;
    static mut CALLBACK_MODE: u32 = 0;
    static mut WRONG_SLOT_CALLS: usize = 0;

    unsafe extern "C" fn wrong_slot(_context: *mut u8, _words: *mut u32, _length: u32, _mode: u32) {
        unsafe { WRONG_SLOT_CALLS += 1 };
    }

    unsafe extern "C" fn transform_words(context: *mut u8, words: *mut u32, length: u32, mode: u32) {
        unsafe {
            CALLBACK_CONTEXT = context;
            CALLBACK_WORDS = [words.read(), words.add(1).read()];
            CALLBACK_LENGTH = length;
            CALLBACK_MODE = mode;
            words.write(0xdead_beef);
            words.add(1).write(0xcafe_babe);
        }
    }

    #[test]
    fn reads_at_offset_advances_cursor_and_returns_callback_mutation() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            CALLBACK_CONTEXT = ptr::null_mut();
            CALLBACK_WORDS = [0; 2];
            CALLBACK_LENGTH = 0;
            CALLBACK_MODE = 0;
            WRONG_SLOT_CALLS = 0;
        }

        let mut vtable = [wrong_slot as ByteCallback; BYTE_CALLBACK_VTABLE_INDEX + 1];
        vtable[BYTE_CALLBACK_VTABLE_INDEX] = transform_words;
        let mut context = 0u8;
        let mut reader = StreamReader { vtable: vtable.as_ptr(), callback_context: &mut context };
        let source = [0x1111_2222u32, 0x3333_4444, 0x5555_6666, 0x7777_8888];
        let mut cursor = source.as_ptr().cast::<u8>();

        let value = unsafe { stream_read_u64(&mut reader, 4, &mut cursor) };

        assert_eq!(value, 0xcafe_babe_dead_beef);
        assert_eq!(cursor, unsafe { source.as_ptr().cast::<u8>().add(8) });
        unsafe {
            assert_eq!(CALLBACK_CONTEXT, core::ptr::addr_of_mut!(context));
            assert_eq!(CALLBACK_WORDS, [0x3333_4444, 0x5555_6666]);
            assert_eq!(CALLBACK_LENGTH, 8);
            assert_eq!(CALLBACK_MODE, 1);
            assert_eq!(WRONG_SLOT_CALLS, 0);
        }
    }
}
