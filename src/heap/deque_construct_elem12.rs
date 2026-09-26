//! Default construction for the 12-byte-element deque instantiation.

use super::block_deque::{deque_construct_elem12, BlockDeque, DequeHead};

/// `block_deque_construct_elem12` — original: `FUN_083de190` @ **0x083de190**
/// (32 bytes exactly, `0x083de190..0x083de1b0`; the next separately linked
/// function begins at `0x083de1b0`). Raw A32 decoding finds **2 inbound plain
/// `bl` call sites** at `0x081ef8bc` and `0x081ef968`, both unconditional,
/// and zero predicated inbound `bl` forms.
///
/// Clears the full 0x2c-byte deque object: its trailing `map_cap` word first,
/// then the 0x28-byte deque head through [`deque_construct_elem12`] at
/// `0x083ddffc`. Returns the input object pointer.
///
/// # Safety
///
/// `deque` must point to a writable [`BlockDeque`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.block_deque_construct_elem12")]
#[inline(never)]
pub unsafe extern "C" fn block_deque_construct_elem12(
    deque: *mut BlockDeque,
) -> *mut BlockDeque {
    (*deque).map_cap = 0;
    deque_construct_elem12(deque.cast::<DequeHead>());
    deque
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;

    #[test]
    fn clears_every_target_word_and_returns_the_deque() {
        let mut deque: BlockDeque = unsafe { core::mem::zeroed() };
        unsafe { core::ptr::write_bytes(addr_of_mut!(deque).cast::<u8>(), u8::MAX, core::mem::size_of::<BlockDeque>()) };

        let returned = unsafe { block_deque_construct_elem12(addr_of_mut!(deque)) };

        assert_eq!(returned, addr_of_mut!(deque));
        assert!(deque.begin.cur.is_null());
        assert!(deque.begin.seg_base.is_null());
        assert!(deque.begin.seg_end.is_null());
        assert!(deque.begin.seg_slot.is_null());
        assert!(deque.end.cur.is_null());
        assert!(deque.end.seg_base.is_null());
        assert!(deque.end.seg_end.is_null());
        assert!(deque.end.seg_slot.is_null());
        assert_eq!(deque.count, 0);
        assert!(deque.map.is_null());
        assert_eq!(deque.map_cap, 0);
    }
}
