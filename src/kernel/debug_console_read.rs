//! Angel debug-console line reader — `FUN_082d670c` @ `0x082d670c`.
//!
//! Raw `osos.dec` has 128 bytes of instructions (`0x082d670c..0x082d678c`),
//! then the 8-byte literal pool at `0x082d678c..0x082d6794`; the separately
//! linked next function starts at `0x082d6794`. Decoding every ARM B/BL word
//! finds exactly 6 direct call sites, all plain unconditional `bl` (none
//! predicated): `0x082bf18c`, `0x082bfaa4`, `0x082d0b98`, `0x08393d2c`,
//! `0x08393ee4`, and `0x083940c0`. No image data word holds the entry, so it
//! is not indirectly dispatched.
//!
//! # Algorithm
//!
//! Lazily opens the Angel `:tt` debug console through SYS_OPEN with the raw
//! four-byte filename extent, caching the returned handle at `0x089ca3c8`.
//! Every call issues SYS_READ for `capacity - 1` bytes with mode zero, then
//! writes NUL at `buffer + capacity - unread - 2`, where `unread` is the
//! SYS_READ result. This intentionally retains the firmware's unguarded
//! wrapping arithmetic and caches failed opens too.
//!
//! Deliberate deviation: the target reads and writes the original cache word
//! through volatile pointers; host builds model that word with a private
//! static so the cache and the exact semihost parameter blocks are testable.

use core::ptr;

use crate::stdio::semihost::{semihost_swi, SYS_OPEN, SYS_READ};

const DEBUG_CONSOLE_HANDLE_ADDR: *mut i32 = 0x089c_a3c8 as *mut i32;
const TTY_NAME: &[u8; 4] = b":tt\0";

#[cfg(not(target_os = "none"))]
static mut HOST_DEBUG_CONSOLE_HANDLE: i32 = 0;

#[inline(always)]
fn debug_console_handle_ptr() -> *mut i32 {
    #[cfg(target_os = "none")]
    {
        DEBUG_CONSOLE_HANDLE_ADDR
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(HOST_DEBUG_CONSOLE_HANDLE)
    }
}

/// debug_console_read_line — original `FUN_082d670c` @ `0x082d670c` (128 bytes).
///
/// Opens and caches the Angel `:tt` console handle, reads `capacity - 1` bytes
/// into `buffer`, then inserts the original's trailing NUL byte. The arguments
/// are intentionally unvalidated: all six original callers pass a writable
/// buffer and a capacity large enough for its unchecked result arithmetic.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn debug_console_read_line(buffer: *mut u8, capacity: u32) {
    let handle_ptr = debug_console_handle_ptr();
    let mut handle = unsafe { ptr::read_volatile(handle_ptr) };
    if handle == 0 {
        let open_block = [TTY_NAME.as_ptr() as usize, 0, TTY_NAME.len()];
        handle = unsafe { semihost_swi()(SYS_OPEN, open_block.as_ptr()) };
        unsafe { ptr::write_volatile(handle_ptr, handle) };
    }

    let read_block = [
        handle as usize,
        buffer as usize,
        capacity.wrapping_sub(1) as usize,
        0,
    ];
    let unread = unsafe { semihost_swi()(SYS_READ, read_block.as_ptr()) } as u32;
    let nul_offset = capacity.wrapping_sub(unread).wrapping_sub(2) as usize;
    unsafe { ptr::write(buffer.wrapping_add(nul_offset), 0) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::stdio::semihost::tests::{mock_swi, restore_swi, SWI_LOG};

    unsafe fn reset_handle() {
        ptr::write(debug_console_handle_ptr(), 0);
    }

    #[test]
    fn opens_tty_reads_capacity_minus_one_and_terminates() {
        let _guard = mock_swi(&[5, 0]);
        unsafe { reset_handle() };
        let mut buffer = *b"abcdefgh";

        unsafe { debug_console_read_line(buffer.as_mut_ptr(), buffer.len() as u32) };

        let log = unsafe { &*ptr::addr_of!(SWI_LOG) };
        assert_eq!(
            log,
            &std::vec![
                (SYS_OPEN, std::vec![TTY_NAME.as_ptr() as usize, 0, 4]),
                (SYS_READ, std::vec![5, buffer.as_mut_ptr() as usize, 7, 0]),
            ]
        );
        assert_eq!(buffer, *b"abcdef\0h");
        unsafe { reset_handle() };
        restore_swi();
    }

    #[test]
    fn caches_handle_and_uses_unread_count_for_nul_position() {
        let _guard = mock_swi(&[9, 1, 2]);
        unsafe { reset_handle() };
        let mut first = *b"abcdefgh";
        let mut second = *b"ABCDEFGH";

        unsafe {
            debug_console_read_line(first.as_mut_ptr(), first.len() as u32);
            debug_console_read_line(second.as_mut_ptr(), second.len() as u32);
        }

        let log = unsafe { &*ptr::addr_of!(SWI_LOG) };
        assert_eq!(log.len(), 3, "the cached handle suppresses a second SYS_OPEN");
        assert_eq!(log[0], (SYS_OPEN, std::vec![TTY_NAME.as_ptr() as usize, 0, 4]));
        assert_eq!(log[1], (SYS_READ, std::vec![9, first.as_mut_ptr() as usize, 7, 0]));
        assert_eq!(log[2], (SYS_READ, std::vec![9, second.as_mut_ptr() as usize, 7, 0]));
        assert_eq!(first, *b"abcde\0gh");
        assert_eq!(second, *b"ABCD\0FGH");
        unsafe { reset_handle() };
        restore_swi();
    }
}
