use crate::heap::block_deque::BlockDeque;

// Preserve the target's three aligned words, including the opaque first word.
#[repr(C)]
pub struct FrontWordObject {
    pub preceding_words: [u32; 2],
    pub value: u32,
}

#[inline(always)]
unsafe fn front_object(deque: *const BlockDeque) -> *const FrontWordObject {
    #[cfg(target_os = "none")]
    {
        // The existing deque_iterator_current_or_zero port omits the stock
        // cursor dereference; use the verified stock ABI, not that Rust body.
        let lookup: unsafe extern "C" fn(*const BlockDeque) -> *const FrontWordObject =
            core::mem::transmute(0x0821_56b8usize);
        lookup(deque)
    }
    #[cfg(not(target_os = "none"))]
    {
        if (*deque).count == 0 {
            core::ptr::null()
        } else {
            (*deque).begin.cur.cast::<*const FrontWordObject>().read()
        }
    }
}

/// container_front_word_or_minus_one — original FUN_08215820 @ 0x08215820.
/// True size: 28 bytes; next independent push prologue is at 0x0821583c.
/// Two inbound plain BL sites (0x082334ec, 0x08235a14), zero predicated BL.
/// Body: one plain BL at 0x08215828 to 0x082156b8, zero predicated BL or BLX.
/// Looks up the deque's front object, returning its aligned u32 at +8 when
/// non-NULL, or UINT32_MAX otherwise. All field bits, including the sentinel,
/// pass through unchanged. Deliberate deviations: retain the stock lookup on
/// target because its existing Rust port lacks the cursor dereference; use
/// the verified lookup algorithm with native cursor pointers on hosts.
///
/// # Safety
/// `deque` must be readable. When nonempty, its begin cursor must address a
/// readable object pointer; a non-NULL object must contain three aligned u32
/// words. No vtable or interpretation of the first two words is required.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn container_front_word_or_minus_one(deque: *const BlockDeque) -> u32 {
    let object = front_object(deque);
    if object.is_null() {
        u32::MAX
    } else {
        (*object).value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::block_deque::DequeIter;

    fn deque(cursor: *mut u8, count: u32) -> BlockDeque {
        BlockDeque {
            begin: DequeIter { cur: cursor, ..DequeIter::NULL },
            end: DequeIter::NULL,
            count,
            map: core::ptr::null_mut(),
            map_cap: 0,
        }
    }

    #[test]
    fn empty_deque_does_not_dereference_invalid_cursor() {
        let container = deque(core::ptr::null_mut(), 0);
        assert_eq!(unsafe { container_front_word_or_minus_one(&container) }, u32::MAX);
    }

    #[test]
    fn nonempty_null_front_returns_sentinel() {
        let mut slot: *const FrontWordObject = core::ptr::null();
        let container = deque(core::ptr::addr_of_mut!(slot).cast(), 1);
        assert_eq!(unsafe { container_front_word_or_minus_one(&container) }, u32::MAX);
    }

    #[test]
    fn reads_third_word_through_cursor_and_tracks_empty_transition() {
        let mut object = FrontWordObject { preceding_words: [0x1234_5678, 0x8765_4321], value: 0 };
        let mut slot = core::ptr::addr_of!(object);
        let mut container = deque(core::ptr::addr_of_mut!(slot).cast(), 1);
        for count in [1, 2, u32::MAX] {
            container.count = count;
            for value in [0, 1, 0x8000_0000, 0xffff_fffe, u32::MAX] {
                object.value = value;
                assert_eq!(unsafe { container_front_word_or_minus_one(&container) }, value);
                assert_eq!(object.preceding_words, [0x1234_5678, 0x8765_4321]);
                assert_eq!(container.count, count);
            }
        }
        object.value = 7;
        container.count = 0;
        assert_eq!(unsafe { container_front_word_or_minus_one(&container) }, u32::MAX);
        container.count = 1;
        assert_eq!(unsafe { container_front_word_or_minus_one(&container) }, 7);
    }
}
