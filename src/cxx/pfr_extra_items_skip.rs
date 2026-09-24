/// pfr_extra_items_skip — original: `FUN_080b79dc` @ `0x080b79dc`.
///
/// True size: 12 bytes (`mov r3,#0; mov r2,#0; b 0x080c07c0`), followed by
/// the separate `FUN_080b79e8` entry. Verified call count: 3 plain `bl`
/// call sites and 0 predicated `bl` call sites. The shared target is
/// FreeType's `pfr_extra_items_parse`; zeroing its handler and handler-data
/// arguments selects its skip-only mode. This port consumes the count-prefixed
/// sequence of `(size, kind, payload)` extra items, advances `cursor` past all
/// items, and returns 8 if either an item header or payload crosses `limit`.
///
/// Deliberate deviation: the shared retail parser emits its invalid-extra-item
/// trace through `FUN_0804d17c` before returning 8. The diagnostic has no
/// named Rust seam, so this wrapper preserves its parser state and status
/// result but omits that trace side effect.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pfr_extra_items_skip(cursor: *mut *mut u8, limit: *const u8) -> u32 {
    let mut current = cursor.read_volatile();
    let limit = limit as usize;

    if limit < current.wrapping_add(1) as usize {
        cursor.write_volatile(current);
        return 8;
    }

    let count = current.read_volatile();
    let mut next = current.wrapping_add(1);
    current = next;
    for _ in 0..count {
        if limit < next.wrapping_add(2) as usize {
            cursor.write_volatile(current);
            return 8;
        }

        let size = next.read_volatile() as usize;
        current = next.wrapping_add(2);
        next = current.wrapping_add(size);
        if limit < next as usize {
            cursor.write_volatile(current);
            return 8;
        }
        current = next;
    }

    cursor.write_volatile(current);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invoke(bytes: &mut [u8], offset: usize, limit: usize) -> (u32, usize) {
        let mut cursor = unsafe { bytes.as_mut_ptr().add(offset) };
        let status = unsafe { pfr_extra_items_skip(&mut cursor, bytes.as_ptr().add(limit)) };
        (status, cursor as usize - bytes.as_ptr() as usize)
    }

    #[test]
    fn skips_empty_and_multiple_extra_item_lists() {
        let mut empty = [0, 0xaa];
        assert_eq!(invoke(&mut empty, 0, 1), (0, 1));

        let mut items = [2, 2, 3, 0x10, 0x11, 4, 9, 0x20, 0x21, 0x22, 0x23, 0];
        assert_eq!(invoke(&mut items, 0, 11), (0, 11));
    }

    #[test]
    fn rejects_missing_count_header_and_payload_without_advancing_past_failure() {
        let mut missing_count = [0; 1];
        assert_eq!(invoke(&mut missing_count, 0, 0), (8, 0));

        let mut missing_header = [1, 4];
        assert_eq!(invoke(&mut missing_header, 0, 1), (8, 1));
        let mut missing_payload = [1, 2, 7, 0];
        assert_eq!(invoke(&mut missing_payload, 0, 3), (8, 3));
    }
}
