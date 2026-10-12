//! Clear a buffer using the context's unsigned 16-bit byte count.
//!
//! Original FUN_08044e28 @ 0x08044e28; true extent [0x08044e28,0x08044e38),
//! 16 bytes, followed by an independent PUSH. Whole-image aligned A32 decoding
//! verifies two incoming plain BLs (0x08044f74, 0x08048ca4), zero predicated
//! BLs. The body has no BLs: mov r2,r0; mov r0,r1; ldrh r1,[r2,#0x1c];
//! b 0x08044e24. Clear exactly that many bytes and return the original buffer.
//! The branch reaches memzero_branch_veneer, then the IRAM memzero veneer
//! @ 0x08037dc8 -> 0x220002d4, the copy of osos memzero @ 0x080002d4.
//!
//! Deviations: express the register shuffle as a typed call to the existing
//! Rust veneer. Its volatile dispatch retains the callee boundary; LLVM may
//! use a call/return rather than the original tail branch. No new callee seam.

use crate::libc::iram_veneers::memzero_branch_veneer;

#[repr(C)]
pub struct BufferClearContext {
    pub prefix: [u32; 7],
    pub byte_count: u16,
}

/// # Safety
/// `context` must be aligned and readable through its `byte_count` field.
/// `buffer` must be writable for `byte_count` bytes, with any alignment.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_sized_buffer_clear(
    context: *const BufferClearContext,
    buffer: *mut u8,
) -> *mut u8 {
    memzero_branch_veneer(buffer, (*context).byte_count as usize)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn unsigned_lengths_alignments_and_surrounding_bytes() {
        assert_eq!(core::mem::offset_of!(BufferClearContext, byte_count), 0x1c);
        for len in [0u16, 1, 3, 4, 7, 31, 32, 33, 255, 256, 0x8000, 0xffff] {
            for alignment in 0..4 {
                let context = BufferClearContext {
                    prefix: [0xdeadbeef; 7],
                    byte_count: len,
                };
                let mut bytes = std::vec![0xa5u8; len as usize + 12];
                let start = 4 + alignment;
                let buffer = unsafe { bytes.as_mut_ptr().add(start) };
                assert_eq!(unsafe { context_sized_buffer_clear(&context, buffer) }, buffer);
                for (index, &byte) in bytes.iter().enumerate() {
                    let expected = if (start..start + len as usize).contains(&index) { 0 } else { 0xa5 };
                    assert_eq!(byte, expected, "len={len}, alignment={alignment}, index={index}");
                }
                assert_eq!(context.prefix, [0xdeadbeef; 7]);
                assert_eq!(context.byte_count, len);
            }
        }
    }

    #[test]
    fn length_is_loaded_before_overlapping_context_is_cleared() {
        let mut context = BufferClearContext { prefix: [u32::MAX; 7], byte_count: 30 };
        let buffer = core::ptr::addr_of_mut!(context).cast::<u8>();
        assert_eq!(unsafe { context_sized_buffer_clear(&context, buffer) }, buffer);
        assert_eq!(context.prefix, [0; 7]);
        assert_eq!(context.byte_count, 0);
    }
}
