//! Byte-ring empty predicate — retailOS `FUN_0816598c` @ 0x0816598c.
//!
//! True extent: 24 bytes, 0x0816598c..0x081659a4; the next word is
//! an independent PUSH prologue. Raw words: e5901000 e5900004 e1510000
//! 13a00000 03a00001 e12fff1e. Whole-image A32 decoding finds two plain
//! incoming BLs (0x080cc2f0, 0x080cc4e8), zero predicated incoming BLs,
//! and zero outgoing BLs. Compare write/read cursor words at +0/+4 and
//! return exactly 1 for equality, otherwise 0; do not inspect payload.
//! Caller 0x080cc298 drains this ring; dequeue 0x08165938 advances the
//! read cursor at +4 and wraps at 1024. No deliberate deviations.

/// Return whether the byte ring's write and read cursors are equal.
///
/// # Safety
/// `cursors` must point to two readable, aligned u32 words. No cursor
/// range validation is performed, matching the firmware.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_ring_is_empty(cursors: *const u32) -> u32 {
    (*cursors == *cursors.add(1)) as u32
}

#[cfg(test)]
mod tests {
    use super::byte_ring_is_empty;

    #[test]
    fn equality_uses_full_cursor_words_without_normalizing() {
        for write in [0, 1, 1023, 1024, 0x8000_0000, u32::MAX] {
            for read in [0, 1, 1023, 1024, 0x8000_0000, u32::MAX] {
                let cursors = [write, read];
                let expected = if write == read { 1 } else { 0 };
                assert_eq!(unsafe { byte_ring_is_empty(cursors.as_ptr()) }, expected);
                assert_eq!(cursors, [write, read]);
            }
        }
    }

    #[test]
    fn draining_and_wrapping_change_empty_state() {
        let mut ring = [0u32, 1023, 0xdead_beef];
        unsafe {
            assert_eq!(byte_ring_is_empty(ring.as_ptr()), 0);
            ring[1] = 0;
            assert_eq!(byte_ring_is_empty(ring.as_ptr()), 1);
            ring[0] = 1;
            assert_eq!(byte_ring_is_empty(ring.as_ptr()), 0);
            ring[1] = 1;
            assert_eq!(byte_ring_is_empty(ring.as_ptr()), 1);
        }
        assert_eq!(ring[2], 0xdead_beef);
    }
}
