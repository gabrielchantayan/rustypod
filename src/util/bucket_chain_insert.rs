//! `bucket_chain_insert` — retailOS `FUN_083d35e4` at load address
//! `0x083d35e4`.
//!
//! Load address: `0x083d35e4`; true size: 40 bytes (`0x28`), from the first
//! `ldr` through `bx lr` at `0x083d3608`; `push {r4-r8,lr}` at `0x083d360c`
//! begins the next real function. Raw ARM decoding verifies two inbound plain
//! `bl` instructions (at `0x083d2dc4` and `0x083d3000`) and zero predicated
//! `bl` instructions.
//!
//! Inserts `node` at the head of the word-0 intrusive chain rooted at
//! `chain_head`, increments the owner's word +0x10 node count with ARM u32
//! wraparound, and lowers its word +0x0c bucket cursor when this head address
//! precedes it. There are no deliberate deviations: owner fields and links
//! remain target-width u32 words, so host pointer width cannot alter the
//! firmware layout.

/// Inserts an intrusive node into one target-width bucket chain.
///
/// # Safety
///
/// `owner` must provide writable words through +0x10. `node` and `chain_head`
/// must be writable target-width pointer words; their values must identify
/// valid target-addressable nodes when nonzero.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.bucket_chain_insert")]
#[inline(never)]
pub unsafe extern "C" fn bucket_chain_insert(
    owner: *mut u8,
    node: *mut u32,
    chain_head: *mut u32,
) {
    unsafe {
        node.write(chain_head.read());
        chain_head.write(node as usize as u32);
        let count = owner.add(0x10).cast::<u32>();
        count.write_volatile(count.read_volatile().wrapping_add(1));

        let cursor = owner.add(0x0c).cast::<u32>();
        if (chain_head as usize) < cursor.read_volatile() as usize {
            cursor.write_volatile(chain_head as usize as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::testing::{hints, try_map_u32_slab};

    use super::bucket_chain_insert;

    #[test]
    fn prepends_chain_updates_count_and_only_lowers_cursor() {
        let Some(slab) = try_map_u32_slab(hints::BUCKET_CHAIN_INSERT, 0x1000) else {
            return;
        };
        let owner = slab;
        let head = unsafe { slab.add(0x40).cast::<u32>() };
        let first = unsafe { slab.add(0x80).cast::<u32>() };
        let second = unsafe { slab.add(0x90).cast::<u32>() };

        unsafe {
            owner.add(0x0c).cast::<u32>().write((head as usize + 4) as u32);
            owner.add(0x10).cast::<u32>().write(u32::MAX);
            first.write(0x1234_5678);
            head.write(first as usize as u32);

            bucket_chain_insert(owner, second, head);

            assert_eq!(second.read(), first as usize as u32);
            assert_eq!(head.read(), second as usize as u32);
            assert_eq!(owner.add(0x10).cast::<u32>().read(), 0);
            assert_eq!(owner.add(0x0c).cast::<u32>().read(), head as usize as u32);

            bucket_chain_insert(owner, first, head);

            assert_eq!(first.read(), second as usize as u32);
            assert_eq!(head.read(), first as usize as u32);
            assert_eq!(owner.add(0x10).cast::<u32>().read(), 1);
            assert_eq!(owner.add(0x0c).cast::<u32>().read(), head as usize as u32);
        }
    }
}
