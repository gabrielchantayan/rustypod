//! `list_node_pool_list_init` — original: `FUN_083dd6c8` @ `0x083dd6c8`
//! (72 bytes; 18 A32 words through `pop {r4,pc}` at `0x083dd70c`; the next
//! function begins at `0x083dd710`). Raw decoding finds one plain outgoing
//! `bl` to `FUN_083dd4cc`, no predicated `bl`, and two inbound plain `bl`
//! calls at `0x082acbb0` and `0x082acbc8`.
//!
//! Clears the 24-byte list owner, acquires one 12-byte node from its embedded
//! pool with `single = 1`, and makes that node the empty intrusive-ring
//! sentinel. Deliberate deviations: none.

use super::list_node_pool_acquire_083dd4cc::list_node_pool_acquire_083dd4cc;
use core::ptr::addr_of_mut;

/// Target-width intrusive list node. Its value word remains uninitialized by
/// the constructor, exactly as the retail pool acquire call leaves it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListNode {
    pub next: u32,
    pub previous: u32,
    pub value: u32,
}

/// The complete 24-byte owner: 16-byte node pool followed by its sentinel and
/// an untouched trailing state word.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListNodePoolList {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
    pub sentinel: u32,
    pub state: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(ListNodePoolList, sentinel)];
const _: [u8; 0x18] = [0; core::mem::size_of::<ListNodePoolList>()];


/// Initializes and returns `list` as an empty node-pool-backed intrusive list.
///
/// # Safety
///
/// `list` must identify 24 writable bytes. The installed pool-acquisition
/// helper must return a writable 12-byte node.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_list_init(
    list: *mut ListNodePoolList,
) -> *mut ListNodePoolList {
    unsafe {
        addr_of_mut!((*list).chunks).write(0);
        addr_of_mut!((*list).free).write(0);
        addr_of_mut!((*list).next).write(0);
        addr_of_mut!((*list).end).write(0);
        addr_of_mut!((*list).sentinel).write(0);
        addr_of_mut!((*list).state).write(0);

        let sentinel = list_node_pool_acquire_083dd4cc(list, 1);
        let sentinel_word = sentinel as usize as u32;
        addr_of_mut!((*list).sentinel).write(sentinel_word);
        addr_of_mut!((*sentinel).next).write(sentinel_word);
        addr_of_mut!((*sentinel).previous).write(sentinel_word);
        list
    }
}

