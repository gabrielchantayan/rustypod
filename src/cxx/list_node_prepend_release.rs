//! `list_node_prepend_release` — retailOS `FUN_083cadd0` @ `0x083cadd0`.
//!
//! Raw ARM is exactly 40 bytes from `stmdb sp!,{r4,r5,r6,lr}` at `0x083cadd0`
//! through `ldmia sp!,{r4,r5,r6,pc}` at `0x083cadf4`; `0x083cadf8` begins the
//! next separately linked function. Whole-image A32 decoding finds two plain
//! inbound `bl` calls (`0x083cb280`, `0x083cb5a0`) and no predicated inbound
//! calls, despite Ghidra reporting three references. Its body has no plain
//! `bl` and one predicated `blne` to `list_release_chain_destroy`.
//!
//! Prepends `node` to the list head stored at word one: it first stores the old
//! head in node word three, optionally releases the node's embedded chain at
//! word five, then publishes the node as the new head. Deliberate deviations:
//! Rust expresses the predicated call as a conditional and returns the callee's
//! value when release is requested, preserving the ARM `r0` result.
use crate::cxx::list_release_chain_destroy::list_release_chain_destroy;

const LIST_HEAD_WORD: usize = 1;
const NODE_PREVIOUS_WORD: usize = 3;
const NODE_RELEASE_CHAIN_WORD: usize = 5;

#[inline(always)]
unsafe fn read_word(base: *mut u8, word: usize) -> u32 {
    unsafe { base.cast::<u32>().add(word).read() }
}

#[inline(always)]
unsafe fn write_word(base: *mut u8, word: usize, value: u32) {
    unsafe { base.cast::<u32>().add(word).write(value) }
}

/// Prepends `node` and optionally releases its embedded chain.
///
/// # Safety
/// `list` must provide word one and `node` must provide words three through
/// five. A nonzero `release_node_chain` requires the embedded chain to satisfy
/// [`crate::list_release_chain_destroy`]'s safety contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_node_prepend_release")]
#[inline(never)]
pub unsafe extern "C" fn list_node_prepend_release(
    list: *mut u8,
    node: *mut u8,
    release_node_chain: u32,
) -> *mut u8 {
    let old_head = unsafe { read_word(list, LIST_HEAD_WORD) };
    unsafe { write_word(node, NODE_PREVIOUS_WORD, old_head) };

    let result = if release_node_chain != 0 {
        unsafe { list_release_chain_destroy(node.add(NODE_RELEASE_CHAIN_WORD * 4)) }
    } else {
        old_head as usize as *mut u8
    };

    unsafe { write_word(list, LIST_HEAD_WORD, node as usize as u32) };
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn prepends_without_releasing_and_returns_the_old_head() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_PREPEND_RELEASE, 0x100) else {
            return;
        };
        let list = slab;
        let node = unsafe { slab.add(0x40) };
        unsafe {
            write_word(list, LIST_HEAD_WORD, 0x1234_5678);
            assert_eq!(list_node_prepend_release(list, node, 0), 0x1234_5678usize as *mut u8);
            assert_eq!(read_word(node, NODE_PREVIOUS_WORD), 0x1234_5678);
            assert_eq!(read_word(list, LIST_HEAD_WORD), node as usize as u32);
        }
    }

    #[test]
    fn release_uses_embedded_chain_and_returns_its_address() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_PREPEND_RELEASE_RELEASE, 0x100) else {
            return;
        };
        let list = slab;
        let node = unsafe { slab.add(0x40) };
        let release_chain = unsafe { node.add(NODE_RELEASE_CHAIN_WORD * 4) };
        unsafe {
            write_word(list, LIST_HEAD_WORD, 0xfeed_beef);
            write_word(release_chain, 4, 0);
            assert_eq!(list_node_prepend_release(list, node, 1), release_chain);
            assert_eq!(read_word(node, NODE_PREVIOUS_WORD), 0xfeed_beef);
            assert_eq!(read_word(list, LIST_HEAD_WORD), node as usize as u32);
        }
    }
}
