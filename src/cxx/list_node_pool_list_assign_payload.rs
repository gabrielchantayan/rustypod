//! `list_node_pool_list_assign_payload` — `FUN_083dc714` @ `0x083dc714`.
//! True size: 208 bytes, ending at pop @ 0x083dc7e0; next function @
//! 0x083dc7e4. Raw A32 decoding: two outbound plain BLs (range erase @
//! 0x083dc484 and range insert @ 0x083dc544), one inbound plain BL @
//! 0x081f0bb0, no predicated BLs in either direction.
//!
//! Self-assignment returns immediately. Copy payload words 1 and 2 over the
//! common prefix, preserving links and payload tags. Erase the destination
//! suffix if source ends first, otherwise insert tagged copies before the
//! destination sentinel. Return destination. Deliberate deviations: stack
//! iterators become Rust locals; reuse the existing insertion port. Unported
//! range erase retains its verified retail ABI/address via a host seam.

use super::list_node_pool_acquire::ListNode;
use super::list_node_pool_list_construct::ListNodePoolList;
use super::list_node_pool_list_insert_payload_range::list_node_pool_list_insert_payload_range;

pub type PayloadRangeErase = unsafe extern "C" fn(*mut u32, *mut ListNodePoolList, *mut u32, *const u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_erase(_: *mut u32, _: *mut ListNodePoolList, _: *mut u32, _: *const u32) {
    panic!("list assignment requires retail range erase 0x083dc484 or host operations")
}

#[cfg(not(target_os = "none"))]
pub static mut PAYLOAD_LIST_RANGE_ERASE: PayloadRangeErase = unavailable_erase;

/// # Safety
/// Both arguments must be live target-layout lists with valid node rings.
/// Destination must support recycling/allocation and payload destruction.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_list_assign_payload(
    destination: *mut ListNodePoolList,
    source: *const ListNodePoolList,
) -> *mut ListNodePoolList {
    if core::ptr::eq(destination, source) { return destination; }
    let end = (*destination).sentinel;
    let source_end = (*source).sentinel as usize as *const ListNode;
    let mut cursor = (*(end as usize as *const ListNode)).next;
    let mut input = (*source_end).next as usize as *const ListNode;
    while cursor != end && input != source_end {
        let node = cursor as usize as *mut ListNode;
        (*node).payload[1] = (*input).payload[1];
        (*node).payload[2] = (*input).payload[2];
        cursor = (*node).next;
        input = (*input).next as usize as *const ListNode;
    }
    if input == source_end {
        let mut result = 0;
        #[cfg(target_os = "none")]
        let erase: PayloadRangeErase = core::mem::transmute(0x083d_c484usize);
        #[cfg(not(target_os = "none"))]
        let erase = PAYLOAD_LIST_RANGE_ERASE;
        erase(&mut result, destination, &mut cursor, &end);
    } else {
        list_node_pool_list_insert_payload_range(destination, &end, input, source_end);
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;

    // Behavioral retail-erase model: unlink and recycle, with trivial payload
    // destruction. Assignment tests check resulting rings, not seam echoes.
    unsafe extern "C" fn erase(out: *mut u32, list: *mut ListNodePoolList, first: *mut u32, last: *const u32) {
        while *first != *last {
            let node = *first as usize as *mut ListNode;
            let next = (*node).next;
            (*((*node).prev as usize as *mut ListNode)).next = next;
            (*(next as usize as *mut ListNode)).prev = (*node).prev;
            (*list).count -= 1;
            (*node).next = (*list).pool.free;
            (*list).pool.free = node as usize as u32;
            *first = next;
        }
        *out = *first;
    }

    unsafe fn ring(list: *mut ListNodePoolList, head: *mut ListNode, count: usize, seed: u32) {
        ptr::write(list, ListNodePoolList::default());
        (*list).sentinel = head as usize as u32;
        (*list).count = count as u32;
        for i in 0..=count {
            let node = head.add(i);
            ptr::write(node, ListNode {
                next: head.add(if i == count { 0 } else { i + 1 }) as usize as u32,
                prev: head.add(if i == 0 { count } else { i - 1 }) as usize as u32,
                payload: [seed, seed + i as u32, !seed ^ i as u32],
            });
        }
    }

    #[test]
    fn assigns_empty_equal_shorter_longer_and_self_without_changing_source() {
        let slab = try_map_u32_slab(hints::PAYLOAD_LIST_ASSIGN, 0x1000).expect("low fixture");
        unsafe {
            let saved = PAYLOAD_LIST_RANGE_ERASE;
            PAYLOAD_LIST_RANGE_ERASE = erase;
            let dst = slab.cast::<ListNodePoolList>();
            let src = slab.add(0x40).cast::<ListNodePoolList>();
            let dh = slab.add(0x100).cast::<ListNode>();
            let sh = slab.add(0x300).cast::<ListNode>();
            for d in 0..=3 {
                for s in 0..=3 {
                    ring(dst, dh, d, 0x10);
                    ring(src, sh, s, 0x80);
                    let fresh = slab.add(0x500).cast::<ListNode>();
                    for i in 0..3 {
                        ptr::write(fresh.add(i), ListNode { next: if i == 2 { 0 } else { fresh.add(i + 1) as usize as u32 }, prev: 0, payload: [0; 3] });
                    }
                    (*dst).pool.free = fresh as usize as u32;
                    assert_eq!(list_node_pool_list_assign_payload(dst, src), dst);
                    assert_eq!((*dst).count, s as u32);
                    let mut node = (*dh).next as usize as *mut ListNode;
                    let mut previous = dh;
                    for i in 1..=s {
                        assert_eq!((*node).prev, previous as usize as u32);
                        assert_eq!([(*node).payload[1], (*node).payload[2]], [0x80 + i as u32, !0x80u32 ^ i as u32]);
                        assert_eq!((*node).payload[0], if i <= d { 0x10 } else { 0x0898_ce24 });
                        if i <= d { assert_eq!(node, dh.add(i)); }
                        previous = node;
                        node = (*node).next as usize as *mut ListNode;
                    }
                    assert_eq!(node, dh);
                    assert_eq!((*dh).prev, previous as usize as u32);
                    assert_eq!((*src).count, s as u32);
                    for i in 0..=s {
                        assert_eq!((*sh.add(i)).payload, [0x80, 0x80 + i as u32, !0x80u32 ^ i as u32]);
                    }
                    if d > s {
                        assert_eq!((*dst).pool.free, dh.add(d) as usize as u32);
                        let mut recycled = (*dst).pool.free;
                        for i in (s + 1..=d).rev() {
                            assert_eq!(recycled, dh.add(i) as usize as u32);
                            recycled = (*(recycled as usize as *mut ListNode)).next;
                        }
                        assert_eq!(recycled, fresh as usize as u32);
                    }
                    let before = core::slice::from_raw_parts(dh.cast::<u32>(), (d + 1) * 5).to_vec();
                    assert_eq!(list_node_pool_list_assign_payload(dst, dst), dst);
                    assert_eq!(core::slice::from_raw_parts(dh.cast::<u32>(), (d + 1) * 5), before);
                }
            }
            // The self path must not dereference even an uninitialized header.
            (*dst).sentinel = 0;
            assert_eq!(list_node_pool_list_assign_payload(dst, dst), dst);
            PAYLOAD_LIST_RANGE_ERASE = saved;
        }
    }
}
