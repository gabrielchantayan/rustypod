//! `handler_list_construct` — original: `FUN_0816cbfc` @ 0x0816cbfc (32 bytes).
//!
//! Raw ARM extent is eight instruction words, 0x0816cbfc..0x0816cc1c: it calls
//! [`three_word_clear_third`] @ 0x083e143c, then writes its remaining fields;
//! the independent vector destructor begins with `push {r4, r5, r6, lr}` at
//! 0x0816cc20. Decoding every ARM B/BL word in `osos.dec` finds exactly 15
//! direct call sites, all unconditional plain `bl`; there are no predicated
//! forms or plain-B tail calls. Callers build `{command_id, handler_name,
//! flag}` records through `vector_push_back_elem12` before passing this list
//! to the firmware handler consumer at 0x08134720.
//!
//! # Algorithm
//!
//! Clear the three-word handler vector head at offsets +0, +4, and +8; store
//! the low byte of `mode` at +12; clear the state word at +16 and the state
//! flag at +20; return `this` unchanged in r0. It has no NULL or alignment
//! guard. There are no device-code deviations: the target calls the already
//! ported `three_word_clear_third` directly rather than using a dispatch seam.
//! Host builds clear the three typed pointer fields separately, avoiding a
//! 32-bit word helper over the host's 64-bit pointer representation.

use crate::cxx::templates::VectorStorage;
#[cfg(target_pointer_width = "32")]
use crate::cxx::three_word_clear_third::three_word_clear_third;

/// The 24-byte handler-list record constructed by [`handler_list_construct`].
///
/// `handlers` is the standard `{begin, end, end_of_storage}` vector head.
/// The remaining words are initialized here but their later semantics have
/// not been identified.
#[repr(C)]
pub struct HandlerList {
    pub handlers: VectorStorage,
    pub mode: u8,
    pub state: u32,
    pub state_flag: u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(HandlerList, mode)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(HandlerList, state)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(HandlerList, state_flag)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::size_of::<HandlerList>()];

/// Initializes a handler list and returns `this` unchanged.
///
/// # Safety
///
/// `list` must be non-NULL, 4-byte aligned, and writable through target
/// offset +20. The firmware clears all three vector-head words and the two
/// state fields without inspecting any pre-existing values; it preserves the
/// three padding bytes after `mode` and after `state_flag`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.handler_list_construct")]
#[inline(never)]
pub unsafe extern "C" fn handler_list_construct(list: *mut HandlerList, mode: u32) -> *mut HandlerList {
    unsafe {
        #[cfg(target_pointer_width = "32")]
        three_word_clear_third(core::ptr::addr_of_mut!((*list).handlers).cast::<u32>());
        #[cfg(not(target_pointer_width = "32"))]
        {
            (*list).handlers.begin = core::ptr::null_mut();
            (*list).handlers.end = core::ptr::null_mut();
            (*list).handlers.end_of_storage = core::ptr::null_mut();
        }
        (*list).mode = mode as u8;
        (*list).state = 0;
        (*list).state_flag = 0;
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_every_observed_field_and_returns_this() {
        let mut list = HandlerList {
            handlers: VectorStorage {
                begin: 0x1111_2222usize as *mut u8,
                end: 0x3333_4444usize as *mut u8,
                end_of_storage: 0x5555_6666usize as *mut u8,
            },
            mode: 0xaa,
            state: 0x7788_99aa,
            state_flag: 0xbb,
        };

        let returned = unsafe { handler_list_construct(&mut list, 0x7e91_c2ff) };

        assert_eq!(returned, core::ptr::addr_of_mut!(list));
        assert!(list.handlers.begin.is_null());
        assert!(list.handlers.end.is_null());
        assert!(list.handlers.end_of_storage.is_null());
        assert_eq!(list.mode, 0xff);
        assert_eq!(list.state, 0);
        assert_eq!(list.state_flag, 0);
    }

    #[test]
    fn zero_mode_is_stored_without_a_guard() {
        let mut list = HandlerList {
            handlers: VectorStorage {
                begin: core::ptr::dangling_mut(),
                end: core::ptr::dangling_mut(),
                end_of_storage: core::ptr::dangling_mut(),
            },
            mode: 1,
            state: u32::MAX,
            state_flag: 1,
        };

        unsafe { handler_list_construct(&mut list, 0) };

        assert_eq!(list.mode, 0);
        assert_eq!(list.state, 0);
        assert_eq!(list.state_flag, 0);
    }
}
