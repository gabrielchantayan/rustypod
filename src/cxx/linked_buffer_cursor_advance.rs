//! Advance a cursor over linked buffer descriptors.

/// `linked_buffer_cursor_advance` — `FUN_08297588` @ `0x08297588`.
///
/// True size: 40 bytes, ending at the next function at `0x082975b0`.
/// Whole-image raw A32 decoding verifies one plain BL caller (0x083d37e8)
/// and one predicated BLNE caller (0x08297528); no outgoing calls.
/// Read the current descriptor from cursor word three. If its word-one
/// successor is nonzero, add its word-two length to cursor word two modulo
/// 2^32, then reload the successor and store it as the current descriptor.
/// A terminal descriptor leaves the cursor unchanged. Deliberate deviations:
/// none. Target pointers remain four-byte words on hosts; raw pointer reads
/// preserve the stock reload when the cursor overlaps the descriptor.
///
/// # Safety
/// `cursor` must point to four aligned, writable u32 words. Its word three
/// must address a descriptor readable through word one, and through word two
/// when a successor exists. No concurrent mutation is permitted.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_buffer_cursor_advance(cursor: *mut u32) {
    let current = cursor.add(3).read() as usize as *const u32;
    if current.add(1).read() != 0 {
        let length = current.add(2).read();
        let offset = cursor.add(2).read();
        cursor.add(2).write(length.wrapping_add(offset));
        cursor.add(3).write(current.add(1).read());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::linked_buffer_cursor_advance;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LINKED_BUFFER_CURSOR_ADVANCE, 0x1000)
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn follows_one_link_wraps_offsets_and_stops_at_terminal() {
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = *FIXTURE else {
            note_missing_u32_fixture("cxx::linked_buffer_cursor_advance");
            return;
        };
        let first = base as *mut u32;
        let second = unsafe { first.add(4) };
        let terminal = unsafe { first.add(8) };
        unsafe {
            first.write(0xaaaa);
            first.add(1).write(second as usize as u32);
            first.add(2).write(5);
            second.write(0xbbbb);
            second.add(1).write(terminal as usize as u32);
            second.add(2).write(0);
            terminal.write(0xcccc);
            terminal.add(1).write(0);
            terminal.add(2).write(u32::MAX);
        }
        let mut cursor = [0x1234, 0x5678, u32::MAX - 2, first as usize as u32];
        unsafe { linked_buffer_cursor_advance(cursor.as_mut_ptr()) };
        assert_eq!(cursor, [0x1234, 0x5678, 2, second as usize as u32]);
        unsafe { linked_buffer_cursor_advance(cursor.as_mut_ptr()) };
        assert_eq!(cursor, [0x1234, 0x5678, 2, terminal as usize as u32]);
        unsafe { linked_buffer_cursor_advance(cursor.as_mut_ptr()) };
        assert_eq!(cursor, [0x1234, 0x5678, 2, terminal as usize as u32]);
    }

    #[test]
    fn reloads_successor_after_overlapping_offset_write() {
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = *FIXTURE else {
            note_missing_u32_fixture("cxx::linked_buffer_cursor_advance");
            return;
        };
        let cursor = base as *mut u32;
        let current = unsafe { cursor.add(1) };
        let address = current as usize as u32;
        unsafe {
            cursor.write(0x1234);
            cursor.add(1).write(0x5678);
            cursor.add(2).write(7);
            cursor.add(3).write(address);
            linked_buffer_cursor_advance(cursor);
            assert_eq!(cursor.read(), 0x1234);
            assert_eq!(cursor.add(1).read(), 0x5678);
            assert_eq!(cursor.add(2).read(), address.wrapping_add(7));
            assert_eq!(cursor.add(3).read(), address.wrapping_add(7));
        }
    }
}
