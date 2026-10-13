//! `thunk_FUN_082c5b18` @ 0x080034c8: 8 bytes through 0x080034d0.
//! Verified inbound calls: 2 plain BL (0x08000c78, 0x08000cbc), 0
//! predicated BL; the veneer and resolved body have no outgoing BL.
//! Startup 0x080046e0 relocates the main image down by 0xaed8, so the
//! literal 0x082c5b18 resolves to raw 0x082d09f0, not Ghidra's body.
//! The 36-byte body (including its literal) ends at 0x082d0a14: read the
//! head at KCB 0x22008a50 + 0x14, replace it with node[0] if non-null,
//! clear node[5], and return the removed node; an empty list stays empty.
//! Deliberate deviations: replace the literal veneer with its reached
//! algorithm; host builds substitute only the firmware head storage.
//! Word indices preserve the target's four-byte fields on 64-bit hosts.

#[cfg(not(target_arch = "arm"))]
static mut HOST_HEAD: u32 = 0;

#[inline]
fn head_word() -> *mut u32 {
    #[cfg(target_arch = "arm")]
    { 0x2200_8a64 as *mut u32 }
    #[cfg(not(target_arch = "arm"))]
    { core::ptr::addr_of_mut!(HOST_HEAD) }
}

/// Pop a kernel pool node, clearing its association word at +0x14.
///
/// # Safety
/// The firmware head must contain zero or an aligned, writable node with
/// at least six u32 words. The caller must serialize access to the pool.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn kernel_pool_node_take() -> *mut u32 {
    let head = head_word();
    let node = head.read_volatile() as usize as *mut u32;
    if !node.is_null() {
        head.write_volatile(node.read_volatile());
        node.add(5).write_volatile(0);
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_singleton_and_chain_preserve_unrelated_words() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::KERNEL_POOL_NODE_TAKE, 4096,
        ) else {
            crate::testing::note_missing_u32_fixture("kernel::kernel_pool_node_take");
            return;
        };
        unsafe {
            let first = slab.cast::<u32>();
            let second = first.add(8);
            head_word().write(0);
            assert!(kernel_pool_node_take().is_null());
            assert_eq!(head_word().read(), 0);
            for node in [first, second] {
                for i in 0..8 { node.add(i).write(0xabc0 + i as u32); }
            }
            first.write(second as usize as u32);
            second.write(0);
            head_word().write(first as usize as u32);
            assert_eq!(kernel_pool_node_take(), first);
            assert_eq!(head_word().read(), second as usize as u32);
            assert_eq!(first.read(), second as usize as u32);
            assert_eq!(first.add(5).read(), 0);
            assert_eq!(second.add(5).read(), 0xabc5);
            assert_eq!(kernel_pool_node_take(), second);
            assert_eq!(head_word().read(), 0);
            assert_eq!(second.add(5).read(), 0);
            assert!(kernel_pool_node_take().is_null());
            for node in [first, second] {
                for i in [1, 2, 3, 4, 6, 7] {
                    assert_eq!(node.add(i).read(), 0xabc0 + i as u32);
                }
            }
        }
    }
}
