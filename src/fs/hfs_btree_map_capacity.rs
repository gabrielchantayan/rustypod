//! HFS B-tree allocation-map capacity threshold.
//!
//! retailOS `FUN_08044224` @ **0x08044224**, 40 bytes through `bx lr`
//! at 0x08044248; the next real prologue starts at 0x0804424c. Raw A32
//! words verify two incoming plain BL calls (0x08041300, 0x08041c7c),
//! zero predicated incoming BLs, and zero outgoing BLs of either kind.
//!
//! Read the node size halfword at control+0x1c and node count word at
//! control+0x20. Start capacity at (node_size-256)*8, then add
//! node_size*8-160 until capacity is unsigned-greater-or-equal to count.
//! Record-insertion callers compare the returned threshold with their
//! proposed node count to reserve an additional allocation-map node.
//!
//! Deliberate deviations: none in arithmetic or memory effects. The Rust
//! return type exposes r0, which Ghidra's void declaration loses. No input
//! validation or closed-form division replaces the original wrapping loop.

/// Return the current allocation-map capacity rounded up to cover node count.
///
/// # Safety
/// `control` must be four-byte aligned and readable through byte 0x23.
/// Inputs must permit the wrapping loop to terminate; the firmware does not
/// validate node size or count. The control block is never modified.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hfs_btree_map_capacity(control: *const u8) -> u32 {
    let node_size = control.add(0x1c).cast::<u16>().read() as u32;
    let node_count = control.add(0x20).cast::<u32>().read();
    let mut capacity = node_size.wrapping_sub(256).wrapping_mul(8);
    while capacity < node_count {
        capacity = capacity.wrapping_add(node_size * 8).wrapping_sub(160);
    }
    capacity
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(node_size: u16, count: u32) -> u32 {
        let mut control = [0xa5a5_a5a5u32; 10];
        control[7] = 0xbeef_0000 | node_size as u32;
        control[8] = count;
        let before = control;
        let result = unsafe { hfs_btree_map_capacity(control.as_ptr().cast()) };
        assert_eq!(control, before);
        result
    }

    #[test]
    fn first_and_subsequent_map_boundaries() {
        for size in [256u16, 512, 1024, 4096, 32768, 65535] {
            let first = (size as u32 - 256) * 8;
            let step = size as u32 * 8 - 160;
            assert_eq!(evaluate(size, 0), first);
            for maps in 0..=4 {
                let boundary = first + maps * step;
                assert_eq!(evaluate(size, boundary), boundary);
                if boundary != 0 {
                    assert_eq!(evaluate(size, boundary - 1), boundary);
                }
                assert_eq!(evaluate(size, boundary + 1), boundary + step);
            }
        }
    }

    #[test]
    fn undersized_nodes_preserve_unsigned_initial_wrap() {
        for size in [0u16, 1, 20, 255] {
            let expected = (size as u32).wrapping_sub(256).wrapping_mul(8);
            assert_eq!(evaluate(size, 0), expected);
            assert_eq!(evaluate(size, expected), expected);
        }
    }
}
