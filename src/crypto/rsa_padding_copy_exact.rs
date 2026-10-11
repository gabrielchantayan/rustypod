//! RSA exact-length no-padding encoding from retailOS.

use crate::kernel::diag_ring_record::diag_ring_record;
use crate::libc::rt_memcpy::__rt_memcpy;

/// Original: `FUN_080628f0` @ 0x080628f0, 84 bytes, ending at the
/// next function's push at 0x08062944; no literal pool. Raw A32 words
/// contain two unconditional BL instructions and zero predicated BLs.
///
/// Compare signed source and destination lengths. A longer source records
/// `(4, 0x6b, 0x6e, 0, 0)`; a shorter source records `(4, 0x6b, 0x7a, 0, 0)`.
/// Both return zero without buffer access. Equal lengths copy exactly that
/// many bytes and return one, including the zero-length case.
///
/// Deliberate deviations: native host pointers; call the existing memcpy
/// body through a volatile function pointer instead of the verified veneer
/// at 0x08037db0 (0x22000020, the IRAM mirror of 0x08000020). This prevents
/// LLVM builtin substitution. No sign, NULL, or overlap guards are added.
///
/// # Safety
/// On equality, buffers must satisfy the forward-copy helper's requirements
/// for `src_len as u32` bytes. Negative equal lengths retain the firmware's
/// large unsigned copy count, rather than being rejected.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rsa_padding_copy_exact(
    dst: *mut u8,
    dst_len: i32,
    src: *const u8,
    src_len: i32,
) -> i32 {
    if src_len != dst_len {
        let reason = if src_len > dst_len { 0x6e } else { 0x7a };
        diag_ring_record(4, 0x6b, reason, 0, 0);
        return 0;
    }
    let copy = core::ptr::read_volatile(
        &(__rt_memcpy as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8),
    );
    copy(dst, src, src_len as u32 as usize);
    1
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
    fn exact_copy_matches_reference_for_all_alignments_and_lengths() {
        for dst_offset in 0..4 {
            for src_offset in 0..4 {
                for len in 0..=64usize {
                    let mut dst = [0xa5; 80];
                    let mut expected = dst;
                    let mut src = [0u8; 80];
                    for (index, byte) in src.iter_mut().enumerate() {
                        *byte = (index as u8).wrapping_mul(37).wrapping_add(1);
                    }
                    let original_src = src;
                    expected[dst_offset..dst_offset + len]
                        .copy_from_slice(&src[src_offset..src_offset + len]);
                    let result = unsafe {
                        rsa_padding_copy_exact(dst.as_mut_ptr().add(dst_offset), len as i32,
                            src.as_ptr().add(src_offset), len as i32)
                    };
                    assert_eq!(result, 1);
                    assert_eq!(dst, expected);
                    assert_eq!(src, original_src);
                }
            }
        }
    }

    #[test]
    fn signed_mismatches_record_errors_without_accessing_buffers() {
        let _lock = DIAG_RING_TEST_LOCK.lock().unwrap();
        let mut ring: DiagEventRing = unsafe { core::mem::zeroed() };
        RING.with(|slot| slot.set(&mut ring));
        let saved = unsafe { DIAG_RING_BLOCK_GETTER };
        unsafe { DIAG_RING_BLOCK_GETTER = Some(ring_getter); }
        for (dst_len, src_len, reason) in [
            (3, 4, 0x6e), (4, 3, 0x7a), (0, 1, 0x6e), (1, 0, 0x7a),
            (-1, 0, 0x6e), (0, -1, 0x7a),
            (i32::MIN, i32::MAX, 0x6e), (i32::MAX, i32::MIN, 0x7a),
            (-2, -1, 0x6e), (-1, -2, 0x7a),
        ] {
            let result = unsafe {
                rsa_padding_copy_exact(core::ptr::null_mut(), dst_len,
                    core::ptr::null(), src_len)
            };
            assert_eq!(result, 0);
            assert_eq!(ring.tags[ring.head as usize], 0x0406_b000 | reason);
            assert_eq!(ring.data0[ring.head as usize], 0);
            assert_eq!(ring.data1[ring.head as usize], 0);
        }
        let head = ring.head;
        assert_eq!(unsafe {
            rsa_padding_copy_exact(core::ptr::null_mut(), 0, core::ptr::null(), 0)
        }, 1);
        assert_eq!(ring.head, head);
        unsafe { DIAG_RING_BLOCK_GETTER = saved; }
        RING.with(|slot| slot.set(core::ptr::null_mut()));
    }
}
