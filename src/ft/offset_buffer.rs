//! Compaction of the FreeType-area reverse offset buffer at `0x08048ab0`.
//!
//! The backing record's exact upstream type is unclassified. Its observed
//! representation has a u16 active-table end at `cursor + 0x1c`, a u16 entry
//! count at `buffer + 0x0a`, and signed, buffer-relative offsets in the reverse
//! table immediately before its active end.

use crate::libc::memmove::memmove;
use crate::libc::memzero::memzero;

type OffsetBufferDropEntry = unsafe extern "C" fn(*mut u8, *mut u8, u32);

/// Firmware address of the unported reverse-offset-table maintenance helper
/// `FUN_08048994`, called after this function moves the payload.
const OFFSET_BUFFER_DROP_ENTRY_ADDRESS: usize = 0x0804_8994;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_offset_buffer_drop_entry(
    cursor: *mut u8,
    buffer: *mut u8,
    entry_count: u32,
) {
    let drop_entry: OffsetBufferDropEntry =
        core::mem::transmute(OFFSET_BUFFER_DROP_ENTRY_ADDRESS);
    drop_entry(cursor, buffer, entry_count);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_offset_buffer_drop_entry(
    _cursor: *mut u8,
    _buffer: *mut u8,
    _entry_count: u32,
) {
    panic!("ft_compact_offset_buffer_range requires FUN_08048994 0x08048994");
}

/// Direct-call boundary for `FUN_08048994`. On target this preserves the
/// original `bl`; host tests replace it with a source-equivalent helper.
#[cfg(target_os = "none")]
static mut OFFSET_BUFFER_DROP_ENTRY: OffsetBufferDropEntry = firmware_offset_buffer_drop_entry;
#[cfg(not(target_os = "none"))]
static mut OFFSET_BUFFER_DROP_ENTRY: OffsetBufferDropEntry = missing_offset_buffer_drop_entry;

#[inline(always)]
unsafe fn read_u16(ptr: *const u8) -> u16 {
    (ptr as *const u16).read()
}

#[inline(always)]
unsafe fn read_i16(ptr: *const u8) -> i16 {
    (ptr as *const i16).read()
}

#[inline(always)]
fn signed_offset_len(value: i16) -> usize {
    value as i32 as u32 as usize
}

/// ft_compact_offset_buffer_range — original: `FUN_08048ab0` @ `0x08048ab0`
/// (132 bytes, `0x08048ab0..0x08048b34`; 6 direct `bl` call sites, all
/// unconditional).
///
/// Removes the range bracketed by the two selected signed offsets in a
/// reverse offset table. It moves trailing payload bytes into the gap when the
/// range is not at the end, delegates reverse-table count/offset adjustment to
/// `FUN_08048994`, then clears the released byte range. The direct calls are
/// `blne 0x08037e00` (the ROM memmove mirror) and `bl 0x08048994`; the final
/// memzero is a tail branch through `0x08044e24` / `0x08037dc8`.
///
/// Decoding every ARM B/BL immediate in `osos.dec` finds inbound plain `bl`
/// calls at `0x08041ca8`, `0x08048ba4`, `0x08048d90`, `0x08058fd8`,
/// `0x08064eb4`, and `0x0806b824`; none is predicated.
///
/// Deliberate deviation: the two ROM veneers call the existing Rust
/// [`memmove`] and [`memzero`] ports through volatile function-pointer loads.
/// The loads prevent LLVM from replacing these direct firmware boundaries with
/// AEABI memory builtins. `FUN_08048994` is unported, so its direct
/// target-address boundary remains a seam rather than assigning an unverified
/// identity to that callee.
///
/// # Safety
/// `cursor` and `buffer` must be valid, aligned firmware records. Their
/// reverse offset table and payload ranges must satisfy the signed offsets;
/// in particular, the two selected offsets must delimit a nonnegative range.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_compact_offset_buffer_range(
    cursor: *mut u8,
    buffer: *mut u8,
    entry_count: u32,
) {
    let entry_end = buffer.add(read_u16(cursor.add(0x1c)) as usize);
    let entry_start = entry_end.sub(entry_count.wrapping_shl(1) as usize);
    let removed_end = read_i16(entry_start.sub(2));
    let removed_start = read_i16(entry_start.sub(4));
    let trailing_end = read_u16(
        entry_end.sub(read_u16(buffer.add(0x0a)) as usize * 2 + 2),
    );
    let moved_len = trailing_end.wrapping_sub(removed_start as u16) as i16;

    if moved_len != 0 {
        let move_payload = core::ptr::read_volatile(
            &(memmove as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8),
        );
        move_payload(
            buffer.offset(removed_end as isize),
            buffer.offset(removed_start as isize),
            signed_offset_len(moved_len),
        );
    }

    let drop_entry = core::ptr::addr_of!(OFFSET_BUFFER_DROP_ENTRY).read_volatile();
    drop_entry(cursor, buffer, entry_count);

    let released_at = read_i16(
        entry_end.sub(read_u16(buffer.add(0x0a)) as usize * 2 + 2),
    );
    let clear_released = core::ptr::read_volatile(
        &(memzero as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
    );
    clear_released(
        buffer.offset(released_at as isize),
        signed_offset_len(removed_start.wrapping_sub(removed_end)),
    );
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    static OFFSET_BUFFER_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DROP_ENTRY_CALLS: u32 = 0;

    struct DropEntrySeam {
        _lock: MutexGuard<'static, ()>,
        original: OffsetBufferDropEntry,
    }

    impl Drop for DropEntrySeam {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(OFFSET_BUFFER_DROP_ENTRY).write(self.original);
            }
        }
    }

    #[repr(align(2))]
    struct AlignedBytes<const N: usize>([u8; N]);

    unsafe fn write_u16(ptr: *mut u8, value: u16) {
        (ptr as *mut u16).write(value);
    }

    /// Independent transcription of `FUN_08048994`, used only to make the
    /// target function's unported direct-call boundary observable on host.
    unsafe extern "C" fn drop_entry_reference(
        cursor: *mut u8,
        buffer: *mut u8,
        entry_count: u32,
    ) {
        DROP_ENTRY_CALLS += 1;
        let entry_end = buffer.add(read_u16(cursor.add(0x1c)) as usize);
        let selected = entry_end.sub(entry_count.wrapping_shl(1) as usize);
        let removed_start = read_i16(selected.sub(4));
        let removed_end = read_i16(selected.sub(2));
        let mut source = selected.sub(4) as *mut i16;
        let mut destination = selected.sub(2) as *mut i16;
        let new_count = read_u16(buffer.add(0x0a)).wrapping_sub(1);
        let mut remaining = new_count.wrapping_sub(entry_count as u16);
        write_u16(buffer.add(0x0a), new_count);
        while remaining != 0 {
            source = source.sub(1);
            destination = destination.sub(1);
            destination.write(source.read().wrapping_sub(removed_start.wrapping_sub(removed_end)));
            remaining = remaining.wrapping_sub(1);
        }
    }

    unsafe fn install_drop_entry_reference() -> DropEntrySeam {
        let lock = OFFSET_BUFFER_TEST_LOCK.lock();
        let original = core::ptr::addr_of!(OFFSET_BUFFER_DROP_ENTRY).read_volatile();
        core::ptr::addr_of_mut!(OFFSET_BUFFER_DROP_ENTRY).write(drop_entry_reference);
        DROP_ENTRY_CALLS = 0;
        DropEntrySeam { _lock: lock, original }
    }

    fn write_offset(buffer: &mut [u8], entry_end: usize, before_end: usize, value: i16) {
        unsafe { write_u16(buffer.as_mut_ptr().add(entry_end - before_end), value as u16) };
    }

    #[test]
    fn compacts_trailing_payload_adjusts_offsets_and_clears_reclaimed_bytes() {
        unsafe {
            let _seam = install_drop_entry_reference();
            let mut cursor = AlignedBytes([0u8; 32]);
            let mut buffer = AlignedBytes([0xa5u8; 64]);
            let entry_end = 60;
            write_u16(cursor.0.as_mut_ptr().add(0x1c), entry_end as u16);
            write_u16(buffer.0.as_mut_ptr().add(0x0a), 4);
            write_offset(&mut buffer.0, entry_end, 2, 0);
            write_offset(&mut buffer.0, entry_end, 4, 12);
            write_offset(&mut buffer.0, entry_end, 6, 20);
            write_offset(&mut buffer.0, entry_end, 8, 30);
            write_offset(&mut buffer.0, entry_end, 10, 40);
            for (index, byte) in buffer.0[20..40].iter_mut().enumerate() {
                *byte = 0x40 + index as u8;
            }

            ft_compact_offset_buffer_range(cursor.0.as_mut_ptr(), buffer.0.as_mut_ptr(), 1);

            assert_eq!(DROP_ENTRY_CALLS, 1);
            assert_eq!(&buffer.0[12..32], &(0x40..0x54).collect::<std::vec::Vec<u8>>()[..]);
            assert!(buffer.0[32..40].iter().all(|&byte| byte == 0));
            assert_eq!(read_u16(buffer.0.as_ptr().add(0x0a)), 3);
            assert_eq!(read_i16(buffer.0.as_ptr().add(54)), 22);
            assert_eq!(read_i16(buffer.0.as_ptr().add(52)), 32);
        }
    }

    #[test]
    fn clears_a_terminal_range_without_moving_payload() {
        unsafe {
            let _seam = install_drop_entry_reference();
            let mut cursor = AlignedBytes([0u8; 32]);
            let mut buffer = AlignedBytes([0xa5u8; 48]);
            let entry_end = 32;
            write_u16(cursor.0.as_mut_ptr().add(0x1c), entry_end as u16);
            write_u16(buffer.0.as_mut_ptr().add(0x0a), 2);
            write_offset(&mut buffer.0, entry_end, 2, 0);
            write_offset(&mut buffer.0, entry_end, 4, 12);
            write_offset(&mut buffer.0, entry_end, 6, 20);
            buffer.0[12..20].fill(0x5c);

            ft_compact_offset_buffer_range(cursor.0.as_mut_ptr(), buffer.0.as_mut_ptr(), 1);

            assert_eq!(DROP_ENTRY_CALLS, 1);
            assert!(buffer.0[12..20].iter().all(|&byte| byte == 0));
            assert_eq!(read_u16(buffer.0.as_ptr().add(0x0a)), 1);
        }
    }
}
