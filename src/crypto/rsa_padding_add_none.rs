//! OpenSSL RSA no-padding encoding from retailOS.

use crate::kernel::diag_ring_record::diag_ring_record;
use crate::libc::iram_veneers::iram_memzero_veneer;
use crate::libc::rt_memcpy::__rt_memcpy;

/// RSA_padding_add_none — original: `FUN_08062da4` @ 0x08062da4.
/// True extent: 100 bytes, ending at the next function at 0x08062e08.
/// Raw A32 scan: two inbound plain BL callers, zero predicated BL callers;
/// three outbound plain BL instructions, zero predicated BL instructions.
///
/// If `src_len > dst_len` (signed comparison), record RSA diagnostic
/// `(4, 0x6f, 0x6d, 0, 0)` and return -1 without accessing either buffer.
/// Otherwise zero the leading `dst_len - src_len` bytes, copy the input to
/// the right-hand end, and return `dst_len`. There is no delimiter or length
/// validation beyond the signed comparison.
///
/// Deliberate deviations: native host pointers; the IRAM memcpy veneer
/// (0x08037db0 -> 0x22000020) is replaced with its existing Rust body,
/// loaded through a volatile function pointer to avoid builtin substitution.
/// Ghidra's extra fifth argument at callers is unused by the raw body.
///
/// # Safety
/// On the success path lengths must describe valid readable/writable regions
/// (normally nonnegative), including the wrapping u32 prefix length. The
/// source must remain readable after prefix clearing; copy overlap inherits
/// the existing forward-copy helper's requirements. No NULL guard is added.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rsa_padding_add_none(
    dst: *mut u8,
    dst_len: i32,
    src: *const u8,
    src_len: i32,
) -> i32 {
    if src_len > dst_len {
        diag_ring_record(4, 0x6f, 0x6d, 0, 0);
        return -1;
    }
    let prefix_len = dst_len.wrapping_sub(src_len) as u32 as usize;
    iram_memzero_veneer(dst, prefix_len);
    let copy = core::ptr::read_volatile(
        &(__rt_memcpy as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8),
    );
    copy(dst.wrapping_add(prefix_len), src, src_len as u32 as usize);
    dst_len
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::diag_ring_record::{DiagEventRing, DIAG_RING_BLOCK_GETTER};
    use crate::testing::DIAG_RING_TEST_LOCK;
    use core::cell::Cell;

    std::thread_local! {
        static RING: Cell<*mut DiagEventRing> = const { Cell::new(core::ptr::null_mut()) };
    }

    unsafe extern "C" fn ring_getter() -> *mut DiagEventRing {
        RING.with(|ring| ring.get())
    }

    #[test]
    fn right_alignment_matches_reference_with_all_byte_alignments() {
        for dst_offset in 0..4 {
            for src_offset in 0..4 {
                for dst_len in 0..=64usize {
                    for src_len in 0..=dst_len {
                        let mut dst = [0xa5; 80];
                        let mut expected = dst;
                        let mut src = [0u8; 80];
                        for (index, byte) in src.iter_mut().enumerate() {
                            *byte = (index as u8).wrapping_mul(37).wrapping_add(1);
                        }
                        let original_src = src;
                        expected[dst_offset..dst_offset + dst_len - src_len].fill(0);
                        expected[dst_offset + dst_len - src_len..dst_offset + dst_len]
                            .copy_from_slice(&src[src_offset..src_offset + src_len]);
                        let result = unsafe {
                            rsa_padding_add_none(dst.as_mut_ptr().add(dst_offset), dst_len as i32,
                                src.as_ptr().add(src_offset), src_len as i32)
                        };
                        assert_eq!(result, dst_len as i32);
                        assert_eq!(dst, expected);
                        assert_eq!(src, original_src);
                    }
                }
            }
        }
    }

    #[test]
    fn rejection_preserves_buffers_and_records_signed_length_error() {
        let _lock = DIAG_RING_TEST_LOCK.lock().unwrap();
        let mut ring: DiagEventRing = unsafe { core::mem::zeroed() };
        RING.with(|slot| slot.set(&mut ring));
        let saved = unsafe { DIAG_RING_BLOCK_GETTER };
        unsafe { DIAG_RING_BLOCK_GETTER = Some(ring_getter); }
        let mut dst = [0xa5; 8];
        let src = [0x5a; 8];
        for (dst_len, src_len) in [(3, 4), (0, 1), (-1, 0), (i32::MIN, i32::MAX)] {
            let result = unsafe {
                rsa_padding_add_none(dst.as_mut_ptr(), dst_len, src.as_ptr(), src_len)
            };
            assert_eq!(result, -1);
            assert_eq!(dst, [0xa5; 8]);
            assert_eq!(src, [0x5a; 8]);
            assert_eq!(ring.tags[ring.head as usize], 0x0406_f06d);
            assert_eq!(ring.data0[ring.head as usize], 0);
            assert_eq!(ring.data1[ring.head as usize], 0);
        }
        unsafe { DIAG_RING_BLOCK_GETTER = saved; }
        RING.with(|slot| slot.set(core::ptr::null_mut()));
    }
}
