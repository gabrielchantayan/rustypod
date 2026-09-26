//! First node from an opaque nested C++ container header.
//!
//! `cxx_container_first_node_083dbdd4` — retailOS `FUN_083dbdd4` @
//! **0x083dbdd4**, **20 bytes** (`0x083dbdd4..0x083dbde7`; the following
//! identical accessor at `0x083dbde8` is a separately linked function). Raw
//! A32 decoding finds zero plain or predicated body `bl` instructions.
//! Full-image A32 decoding finds two inbound unconditional plain `bl` sites
//! (0x081099c0, 0x081099cc), and no predicated inbound `bl` sites.
//!
//! # Algorithm
//!
//! Load the nested container pointer at `header + 0x10`, then return its word
//! at `+0x08`. The callers use the result as the first node in an intrusive
//! traversal terminated by the owner word at `+0x10`.
//!
//! # Deliberate deviation
//!
//! This body is byte-identical to the separately linked
//! `FUN_083dbde8`/`cxx_container_first_node_083dbde8`,
//! `FUN_083dbeb4`/`cxx_container_first_node_083dbeb4`, and
//! `FUN_083dbec8`/`cxx_container_first_node`. Its `push {r3,lr}; str r0,[sp];
//! pop {r3,pc}` only preserves a stack home for `r0`; this direct Rust
//! expression retains the two ordered target-width loads and returned `r0`
//! value without that dead stack traffic. Its dedicated text section prevents
//! LLVM from folding this separately linked BL target into either twin.

const NESTED_CONTAINER_OFFSET: usize = 0x10;
const FIRST_NODE_OFFSET: usize = 0x08;

/// Returns the first node word from an opaque nested container header.
///
/// # Safety
///
/// `header` must be readable through +0x10, and its target-width pointer at
/// that offset must name storage readable through +0x08. RetailOS performs no
/// null checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.cxx_container_first_node_083dbdd4"))]
pub unsafe extern "C" fn cxx_container_first_node_083dbdd4(header: *const u8) -> *mut u8 {
    let nested = header.add(NESTED_CONTAINER_OFFSET).cast::<u32>().read() as usize as *const u8;
    nested.add(FIRST_NODE_OFFSET).cast::<u32>().read() as usize as *mut u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    unsafe fn write_target_word(base: *mut u8, offset: usize, value: *mut u8) {
        base.add(offset).cast::<u32>().write(value as usize as u32);
    }

    #[test]
    fn returns_each_headers_nested_containers_first_node_word() {
        let Some(slab) = try_map_u32_slab(hints::CXX_CONTAINER_FIRST_NODE_083DBDD4, 0x1000) else {
            return;
        };
        unsafe {
            let first_header = slab.add(0x100);
            let second_header = slab.add(0x200);
            let first_nested = slab.add(0x300);
            let second_nested = slab.add(0x400);
            let first_node = slab.add(0x500);
            let second_node = slab.add(0x600);
            let decoy_node = slab.add(0x700);
            write_target_word(first_header, NESTED_CONTAINER_OFFSET, first_nested);
            write_target_word(second_header, NESTED_CONTAINER_OFFSET, second_nested);
            write_target_word(first_nested, FIRST_NODE_OFFSET, first_node);
            write_target_word(first_nested, 0x0c, decoy_node);
            write_target_word(second_nested, FIRST_NODE_OFFSET, second_node);
            assert_eq!(cxx_container_first_node_083dbdd4(first_header), first_node);
            assert_eq!(cxx_container_first_node_083dbdd4(second_header), second_node);
        }
    }
}
