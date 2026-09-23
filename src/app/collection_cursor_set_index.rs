/// Sets an opaque collection cursor's current item index — original:
/// `FUN_0816f650` @ `0x0816f650` (8 bytes; 3 plain `bl`, 0 predicated
/// `bl` call sites).
///
/// Raw ARM is `str r1,[r0,#0x18]; bx lr`: store `index` in the opaque
/// cursor's target-width word at +0x18. The next real function starts at
/// `0x0816f658`; this leaf has no outgoing calls. Deliberate deviations:
/// none.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_cursor_set_index(cursor: *mut u32, index: u32) {
    unsafe { cursor.add(0x18 / core::mem::size_of::<u32>()).write(index) };
}

#[cfg(test)]
mod tests {
    use super::collection_cursor_set_index;

    #[repr(C)]
    struct CollectionCursor {
        words_before_index: [u32; 6],
        current_index: u32,
        word_after_index: u32,
    }

    #[test]
    fn replaces_only_the_current_index_word() {
        let mut cursor = CollectionCursor {
            words_before_index: [0xaaaa_aaaa; 6],
            current_index: 0x1111_1111,
            word_after_index: 0xbbbb_bbbb,
        };

        unsafe { collection_cursor_set_index((&mut cursor as *mut CollectionCursor).cast(), u32::MAX) };

        assert_eq!(cursor.current_index, u32::MAX);
        assert_eq!(cursor.words_before_index, [0xaaaa_aaaa; 6]);
        assert_eq!(cursor.word_after_index, 0xbbbb_bbbb);
    }

    #[test]
    fn accepts_zero_as_an_index() {
        let mut cursor = CollectionCursor {
            words_before_index: [0; 6],
            current_index: 7,
            word_after_index: 0,
        };

        unsafe { collection_cursor_set_index((&mut cursor as *mut CollectionCursor).cast(), 0) };

        assert_eq!(cursor.current_index, 0);
    }
}
