//! `mov_atom_node_new` — original: `FUN_080b3d40` @ 0x080b3d40
//! (**28 bytes**, 0x080b3d40..0x080b3d5c, 7 instructions, no literal
//! pool; Ghidra's 28 is exact — the next function opens at 0x080b3d5c
//! with its own `push {r4, lr}`. Byte-decoded from osos.dec; Ghidra
//! emits no C file for this one at all). **22 `bl` call sites, 0
//! predicated, 0 tail branches**, verified by decoding every B/BL word
//! in osos.dec; no DATA word anywhere references the address, so it is
//! only ever direct-called, never dispatched virtually.
//!
//! # What it is
//!
//! The MOV/MP4 demuxer's **atom node factory**: allocate one 0x28-byte
//! atom table node and initialize it with the fourcc key it will be
//! filed under. 19 of the 22 call sites load a fourcc literal into r0
//! immediately before the `bl` — `tkhd`, `edts`, `elst`, `mdia`,
//! `mdhd`, `minf`, `stbl`, `stsd`, `stco`, `co64`, `stsc`, `stsz`,
//! `stts`, `stss` (all @ 0x081c1d2c..0x081c1dbc), `moov`, `mvhd`,
//! `trak`, `hdlr`, `mdat` (@ 0x081c7d6c..0x081c7da8), each the file's
//! ASCII bytes read as a little-endian u32 (`'tkhd'` = 0x64686b74).
//! The remaining three pass a computed key; one of them (@ 0x080a3f00)
//! sits inside the fourcc-keyed table search `FUN_080a3ea0` itself,
//! which grows the tree with a fresh placeholder node on a populate
//! miss.
//!
//! # Algorithm
//!
//! ```text
//! 080b3d40  e92d4010  push {r4, lr}
//! 080b3d44  e1a04000  mov  r4, r0            @ r4 = fourcc
//! 080b3d48  e3a00028  mov  r0, #0x28         @ sizeof(node) = 40
//! 080b3d4c  eb07dc20  bl   0x082aadd4        @ operator_new(0x28), tag 2
//! 080b3d50  e1a01004  mov  r1, r4            @ r1 = fourcc
//! 080b3d54  e8bd4010  pop  {r4, lr}
//! 080b3d58  ea026554  b    0x0814d2b0        @ tail: node_init(node, fourcc)
//! ```
//!
//! The tail callee @ 0x0814d2b0 (unported; 48 bytes,
//! 0x0814d2b0..0x0814d2e0, 12 instructions, no literal pool — the next
//! function opens at 0x0814d2e0 with `mov r1, #0`) is the node
//! initializer, stores only, in this exact register order:
//!
//! ```text
//! 0814d2b0  mov  r2, #0
//! 0814d2b4  str  r2, [r0, #8]      @ dup_chain = NULL
//! 0814d2b8  str  r2, [r0]          @ child_a  = NULL
//! 0814d2bc  str  r2, [r0, #4]      @ child_b  = NULL
//! 0814d2c0  strb r2, [r0, #33]     @ kind = 0            (+0x21)
//! 0814d2c4  mvn  r2, #0            @ r2 = -1
//! 0814d2c8  str  r2, [r0, #16]     @ offset_lo = -1      (+0x10)
//! 0814d2cc  str  r2, [r0, #20]     @ offset_hi = -1      (+0x14)
//! 0814d2d0  str  r2, [r0, #24]     @ size_lo = -1        (+0x18)
//! 0814d2d4  str  r1, [r0, #36]     @ fourcc = key        (+0x24)
//! 0814d2d8  str  r2, [r0, #28]     @ size_hi = -1        (+0x1c)
//! 0814d2dc  bx   lr                @ returns r0 = node unchanged
//! ```
//!
//! Two bytes/words are deliberately NOT written: `+0x0c` and the flag
//! byte `+0x20` are born as whatever the heap block already held.
//!
//! # The node (0x28 = 40 bytes)
//!
//! Cross-checked three ways: the initializer above, the getters/
//! setters @ 0x0814d230/0x0814d1ac/0x0814d270 (see
//! `mov/atom_info.rs`), and the table search `FUN_080a3ea0`, which
//! reads `+0x24` as the key (`puVar2[9]`), treats `+0x10/+0x14 == -1`
//! as the placeholder test, and walks `+0x00`/`+0x04` (children) and
//! `+0x08` (duplicate-fourcc chain):
//!
//! ```text
//! +0x00  ptr  child link A (tree walk)
//! +0x04  ptr  child link B (tree walk)
//! +0x08  ptr  duplicate-fourcc chain
//! +0x0c  ---  untouched by the initializer
//! +0x10  u64  atom payload offset   (born -1 = placeholder)
//! +0x18  u64  atom total size       (born -1)
//! +0x20  u8   flag byte             (born UNINITIALIZED)
//! +0x21  u8   kind byte 0..=5       (born 0)
//! +0x24  u32  fourcc key, file byte order as a little-endian u32
//! ```
//!
//! # Deviations
//!
//! - The original tail-branches to the initializer (`b 0x0814d2b0`);
//!   the port calls [`atom_node_init`] and returns its result. The
//!   initializer returns its node argument unchanged (`bx lr` with r0
//!   untouched), so the ABI-visible result is identical.
//! - The initializer @ 0x0814d2b0 is not ported as its own symbol; its
//!   whole decoded body is reproduced as the private [`atom_node_init`]
//!   (12 instructions, stores only, no external dependencies — no
//!   dispatch seam is needed).
//! - No NULL guard between `operator_new` and the initializer, exactly
//!   like the original: on allocation failure the first field store
//!   faults. (The one caller that checks the result against NULL —
//!   `FUN_080a3ea0` — can therefore never observe NULL on the stock
//!   build.)

/// Allocation size of one atom node — the `mov r0, #0x28` feeding
/// `operator_new` in [`mov_atom_node_new`].
pub const MOV_ATOM_NODE_SIZE: usize = 0x28;

/// The fourcc-keyed atom table node the factory builds. All pointer
/// fields are kept as raw `u32` words so the layout is byte-identical
/// on the 32-bit target and 64-bit hosts.
#[repr(C)]
pub struct MovAtomNode {
    /// `+0x00`: child link A walked by the table search.
    pub child_a: u32,
    /// `+0x04`: child link B walked by the table search.
    pub child_b: u32,
    /// `+0x08`: duplicate-fourcc chain link.
    pub dup_chain: u32,
    /// `+0x0c`: not written by the initializer (born uninitialized).
    pub unused_0c: u32,
    /// `+0x10`: low half of the u64 payload offset (-1 = placeholder).
    pub offset_lo: u32,
    /// `+0x14`: high half of the u64 payload offset.
    pub offset_hi: u32,
    /// `+0x18`: low half of the u64 atom total size.
    pub size_lo: u32,
    /// `+0x1c`: high half of the u64 atom total size.
    pub size_hi: u32,
    /// `+0x20`: flag byte — NOT written by the initializer.
    pub flag: u8,
    /// `+0x21`: kind byte 0..=5.
    pub kind: u8,
    /// `+0x22..+0x24`: alignment padding.
    pub pad_22: [u8; 2],
    /// `+0x24`: fourcc key, the file's ASCII bytes as a little-endian
    /// u32 (`'tkhd'` = 0x64686b74).
    pub fourcc: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(MovAtomNode, child_a)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(MovAtomNode, child_b)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(MovAtomNode, dup_chain)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(MovAtomNode, offset_lo)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(MovAtomNode, size_lo)];
const _: [u8; 0x20] = [0; core::mem::offset_of!(MovAtomNode, flag)];
const _: [u8; 0x21] = [0; core::mem::offset_of!(MovAtomNode, kind)];
const _: [u8; 0x24] = [0; core::mem::offset_of!(MovAtomNode, fourcc)];
const _: [u8; 0x28] = [0; core::mem::size_of::<MovAtomNode>()];

/// The node initializer @ 0x0814d2b0, reproduced store-for-store in
/// the original's register order (see the module header). Returns
/// `node` unchanged, like the original's `bx lr` with r0 untouched.
///
/// `+0x0c` and the `+0x20` flag byte are deliberately not written;
/// the `-1` words are written individually (`mvn r2, #0` per half),
/// never as a u64 store.
///
/// # Safety
///
/// `node` must point to at least 0x28 writable bytes. No NULL guard,
/// exactly like the original.
unsafe fn atom_node_init(node: *mut MovAtomNode, fourcc: u32) -> *mut MovAtomNode {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).dup_chain), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).child_a), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).child_b), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).kind), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).offset_lo), 0xffff_ffff);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).offset_hi), 0xffff_ffff);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).size_lo), 0xffff_ffff);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).fourcc), fourcc);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).size_hi), 0xffff_ffff);
    }
    node
}

/// mov_atom_node_new — original: `FUN_080b3d40` @ 0x080b3d40 (28 bytes;
/// 22 `bl` call sites, binary-verified).
///
/// Allocates one 0x28-byte MOV atom table node with tag-2
/// `operator_new` and initializes it as a placeholder filed under
/// `fourcc`: all links NULL, kind 0, offset and size -1. The `+0x0c`
/// word and the `+0x20` flag byte keep whatever the heap block held.
/// Returns the new node. See the module header for the algorithm, the
/// node layout, and the deviations.
///
/// No NULL guard on the allocation result, exactly like the original —
/// on failure the initializer's first store faults, so this never
/// returns NULL on the stock build.
///
/// # Safety
///
/// None beyond the allocator's own contract; the returned node is
/// owned by the caller and released with tag-2 `operator_delete`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_atom_node_new(fourcc: u32) -> *mut MovAtomNode {
    let block = unsafe { crate::heap::veneers::operator_new(MOV_ATOM_NODE_SIZE) };
    unsafe { atom_node_init(block.cast(), fourcc) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};

    /// 0x28 bytes of heap-block stand-in, word-aligned, poisoned so the
    /// fields the initializer must NOT touch (+0x0c, +0x20) are
    /// observable. Serialized by the heap ops lock via `mock_heap()`.
    static mut NODE_BUF: [u32; 10] = [0; 10];

    const POISON: u32 = 0xaaaa_aaaa;

    fn poisoned_block() -> *mut u8 {
        unsafe {
            NODE_BUF = [POISON; 10];
            let block = NODE_BUF.as_mut_ptr().cast::<u8>();
            set_alloc_ret(block);
            block
        }
    }

    #[test]
    fn initializes_placeholder_node() {
        let _heap = mock_heap();
        let block = poisoned_block();
        let fourcc = u32::from_le_bytes(*b"tkhd");

        let node = unsafe { mov_atom_node_new(fourcc) };

        assert_eq!(node, block.cast::<MovAtomNode>(), "returns the fresh block");
        assert_eq!(alloc_log(), (1, MOV_ATOM_NODE_SIZE, 2), "one tag-2 operator_new(0x28)");
        unsafe {
            assert_eq!((*node).child_a, 0);
            assert_eq!((*node).child_b, 0);
            assert_eq!((*node).dup_chain, 0);
            assert_eq!((*node).offset_lo, 0xffff_ffff);
            assert_eq!((*node).offset_hi, 0xffff_ffff);
            assert_eq!((*node).size_lo, 0xffff_ffff);
            assert_eq!((*node).size_hi, 0xffff_ffff);
            assert_eq!((*node).kind, 0);
            assert_eq!((*node).fourcc, fourcc);
        }
    }

    #[test]
    fn leaves_untouched_fields_alone() {
        let _heap = mock_heap();
        let block = poisoned_block();

        let node = unsafe { mov_atom_node_new(u32::from_le_bytes(*b"moov")) };

        unsafe {
            assert_eq!((*node).unused_0c, POISON, "+0x0c is not written by the init");
            assert_eq!((*node).flag, 0xaa, "+0x20 flag byte is born uninitialized");
            assert_eq!((*node).pad_22, [0xaa, 0xaa], "+0x22 padding is not written");
            let _ = block;
        }
    }

    #[test]
    fn stores_fourcc_raw() {
        let _heap = mock_heap();
        for fourcc in [0u32, 0xffff_ffff, u32::from_le_bytes(*b"stsd")] {
            let block = poisoned_block();
            let node = unsafe { mov_atom_node_new(fourcc) };
            unsafe {
                assert_eq!((*node).fourcc, fourcc, "key stored byte-for-byte");
                assert_eq!(node, block.cast::<MovAtomNode>());
            }
        }
    }
}
