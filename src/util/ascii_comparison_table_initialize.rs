//! Initialize the ASCII fast-comparison eligibility table.
//!
//! Original: `FUN_080d5090` @ 0x080d5090. True extent is 124 bytes through
//! 0x080d510c: 116 instruction bytes and two 4-byte address literals. Raw
//! A32 decoding verifies zero incoming plain BLs, two incoming BLEQs
//! (0x08045340 and 0x08059ca8), and zero outgoing BLs of either kind.
//! Clear all 128 entries at 0x08a777a8, mark space, exclamation, period,
//! digits and ASCII letters, then set the byte at 0x089cb1a8 to one.
//! Callers use this table to select their ASCII string-comparison fast path.
//! Deliberate deviations: host builds substitute native byte storage for
//! firmware globals. Volatile byte writes preserve ordering and avoid LLVM
//! replacing the clearing loop with a libc call. No initialization guard is
//! added: repeated calls rebuild the table exactly as the original does.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_TABLE: [u8; 128] = [0; 128];
#[cfg(not(target_os = "none"))]
static mut HOST_INITIALIZED: u8 = 0;

#[inline(always)]
unsafe fn table() -> *mut u8 {
    #[cfg(target_os = "none")]
    { 0x08a7_77a8 as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_TABLE).cast::<u8>() }
}

#[inline(always)]
unsafe fn initialized() -> *mut u8 {
    #[cfg(target_os = "none")]
    { 0x089c_b1a8 as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_INITIALIZED) }
}

/// Rebuild the shared table and publish its initialized byte last.
///
/// # Safety
/// The firmware globals must be writable; callers must serialize access to
/// the table and flag, including reads by comparison routines.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ascii_comparison_table_initialize() {
    let entries = table();
    for index in 0..128 {
        ptr::write_volatile(entries.add(index), 0);
    }
    ptr::write_volatile(entries.add(0x20), 1);
    ptr::write_volatile(entries.add(0x21), 1);
    ptr::write_volatile(entries.add(0x2e), 1);
    for index in 0x30..0x3a {
        ptr::write_volatile(entries.add(index), 1);
    }
    for index in 0x41..0x5b {
        ptr::write_volatile(entries.add(index), 1);
    }
    for index in 0x61..0x7b {
        ptr::write_volatile(entries.add(index), 1);
    }
    ptr::write_volatile(initialized(), 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn rebuilds_every_entry_even_when_already_initialized() {
        let _lock = LOCK.lock();
        unsafe {
            for flag in [0, 1, 0xff] {
                for index in 0..128 {
                    ptr::write(table().add(index), 0xa5);
                }
                ptr::write(initialized(), flag);
                ascii_comparison_table_initialize();
                for byte in 0u8..128 {
                    let expected = u8::from(byte.is_ascii_alphanumeric()
                        || b" !.".contains(&byte));
                    assert_eq!(ptr::read(table().add(byte as usize)), expected,
                        "ASCII byte {byte:#04x}, initial flag {flag:#04x}");
                }
                assert_eq!(ptr::read(initialized()), 1);
            }
        }
    }
}
