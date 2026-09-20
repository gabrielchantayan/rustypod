//! Prepends a red-black-tree node to a cleanup chain and optionally destroys
//! its payload — original: `FUN_083cccc4` at load address `0x083cccc4`.
//!
//! Raw `osos.dec` establishes the exact 40-byte extent: ten ARM words from
//! `push {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}`; the next separately linked
//! function starts at `0x083cccec`. Full-image A32 decoding finds three direct
//! inbound plain `bl` calls at `0x081f16b0`, `0x083cd174`, and `0x083cd494`, and
//! no predicated inbound calls. The body has no plain internal calls and one
//! predicated `blne` to [`crate::app::opaque_tree_vector_destruct`].
//!
//! The node's right-link word becomes the old cleanup-chain head, then an
//! optional opaque payload at node+0x14 is destroyed; finally the node becomes
//! the new head. Deliberate deviations: none. All links remain target-width
//! `u32` words, preserving target offsets in host fixtures.

const HEAD: usize = 1;
const RIGHT_LINK: usize = 3;
const PAYLOAD: usize = 0x14;

type DestroyPayload = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// Prepends `node` to `chain` and optionally destroys its payload.
///
/// Original: `FUN_083cccc4` at load address `0x083cccc4` (40 bytes; three
/// inbound plain `bl` calls and no predicated inbound calls).
///
/// # Safety
///
/// `chain` must have a writable target-width head word at +0x04. `node` must
/// have writable words at +0x0c and a valid opaque payload at +0x14 when
/// `destroy_payload` is nonzero. The retail function has no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_node_prepend_and_destroy_payload")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_node_prepend_and_destroy_payload(
    chain: *mut u32,
    node: *mut u32,
    destroy_payload: u32,
) {
    unsafe {
        red_black_tree_node_prepend_and_destroy_payload_with(
            chain,
            node,
            destroy_payload,
            crate::app::opaque_tree_vector_destruct::opaque_tree_vector_destruct,
        );
    }
}

unsafe fn red_black_tree_node_prepend_and_destroy_payload_with(
    chain: *mut u32,
    node: *mut u32,
    destroy_payload: u32,
    destroy: DestroyPayload,
) {
    unsafe {
        node.add(RIGHT_LINK).write(chain.add(HEAD).read());
        if destroy_payload != 0 {
            destroy(node.cast::<u8>().add(PAYLOAD));
        }
        chain.add(HEAD).write(node as usize as u32);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CHAIN: AtomicUsize = AtomicUsize::new(0);
    static DESTROYED: AtomicUsize = AtomicUsize::new(0);
    static HEAD_DURING_DESTROY: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_destroy(payload: *mut u8) -> *mut u8 {
        let chain = CHAIN.load(Ordering::Relaxed) as *const u32;
        HEAD_DURING_DESTROY.store(unsafe { chain.add(HEAD).read() } as usize, Ordering::Relaxed);
        DESTROYED.store(payload as usize, Ordering::Relaxed);
        payload
    }


    #[test]
    fn prepends_node_without_destroying_payload_when_flag_is_zero() {
        let mut chain = [0u32; 2];
        let mut node = [0u32; 16];
        chain[HEAD] = 0x1234_5678;
        DESTROYED.store(usize::MAX, Ordering::Relaxed);

        unsafe {
            red_black_tree_node_prepend_and_destroy_payload_with(
                chain.as_mut_ptr(), node.as_mut_ptr(), 0, record_destroy,
            );
        }

        assert_eq!(node[RIGHT_LINK], 0x1234_5678);
        assert_eq!(chain[HEAD], node.as_mut_ptr() as usize as u32);
        assert_eq!(DESTROYED.load(Ordering::Relaxed), usize::MAX);
    }

    #[test]
    fn destroys_payload_after_linking_node_and_before_publishing_head() {
        let mut chain = [0u32; 2];
        let mut node = [0u32; 16];
        let old_head = 0x7654_3210;
        CHAIN.store(chain.as_ptr() as usize, Ordering::Relaxed);
        chain[HEAD] = old_head;
        DESTROYED.store(0, Ordering::Relaxed);
        HEAD_DURING_DESTROY.store(chain[HEAD] as usize, Ordering::Relaxed);

        unsafe {
            red_black_tree_node_prepend_and_destroy_payload_with(
                chain.as_mut_ptr(), node.as_mut_ptr(), 1, record_destroy,
            );
        }

        assert_eq!(node[RIGHT_LINK], old_head);
        assert_eq!(DESTROYED.load(Ordering::Relaxed), unsafe { node.as_mut_ptr().cast::<u8>().add(PAYLOAD) } as usize);
        assert_eq!(HEAD_DURING_DESTROY.load(Ordering::Relaxed), old_head as usize);
        assert_eq!(chain[HEAD], node.as_mut_ptr() as usize as u32);
    }
}
