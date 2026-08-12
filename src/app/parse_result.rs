//! `parse_result_init` — the 4-byte result-record constructor of the
//! fault-tolerant record-resource parsers (the 0x080f8xxx–0x080fexxx
//! cluster, ui/block_map's "record-resource parsers").
//!
//! # The record
//!
//! The cluster's parsers return a small C++ value type by hidden
//! out-pointer (sret). Its full method family sits in one translation
//! unit at 0x08283120–0x08283178:
//!
//! ```text
//! 0x08283120  ldrb r0, [r0, #0]; bx lr                 status()
//! 0x08283124  ldrh r0, [r0, #2]; bx lr                 detail()
//! 0x0828312c  ldrb r0, [r0, #1]; bx lr                 code()
//! 0x08283134  strb/strb/strh; bx lr                    init (identical
//!                                                      twin of ours)
//! 0x08283144  rsbs r0, r0, #1; movcc r0, #0; bx lr     is_ok()
//! 0x08283154  zero all four bytes; bx lr               clear()
//! 0x08283168  strb/strb/strh; bx lr                    init — THIS PORT
//! 0x08283178  bx lr                                    ~result() (trivial,
//!                                                      the context_scope_drop
//!                                                      phenomenon)
//! ```
//!
//! so the layout is proven on both sides by the readers, not just by the
//! writer:
//!
//! ```text
//! +0x00  status  u8       0 = cleared, 1 = ok (is_ok() tests == 1),
//!                         2 = error
//! +0x01  code    u8       5 on every error path observed
//! +0x02  detail  u16 LE   e.g. 0x2000 (FUN_080fc74c writes {2, 5,
//!                         0x2000}); a pool constant elsewhere
//! ```
//!
//! # How the call sites use it
//!
//! 53 `bl` sites (binary-scanned), 52 of them inside the parser cluster
//! plus one outlier @ 0x081d5e48. The canonical shape: the parser
//! zero-initializes a record on its frame (`mov r1, #0; mov r2, #0;
//! mov r3, #0; add r0, sp, #N; bl 0x08283168`, e.g. 0x080f8ef4 /
//! 0x080f8f08 building two records back to back), parses, rewrites the
//! record through the twin @ 0x08283134 with {2, 5, detail} on failure
//! (e.g. 0x080f8bd0), and finally gates the consumer on `is_ok()`
//! (`bl 0x08283144; cmp r0, #0; beq <bail>`, e.g. 0x080f8d74). r0 is
//! consumed after the call (`mov r7, r0` &c.), so the original returns
//! the out pointer — free in the original since r0 is never written.
//!
//! The adjacency to context_scope (0x08283f3c+) is ADS translation-unit
//! packaging only: no context_scope function references this record.
//!
//! Deviation: none of substance. The three stores are volatile so LLVM
//! cannot merge them into one 32-bit `str` — the original emits three
//! distinct stores, and a merged word store would fault where the
//! original's byte/half stores do not if `out` were ever unaligned.

/// parse_result_init — original: `FUN_08283168` @ 0x08283168 (16 bytes;
/// 53 `bl` call sites).
///
/// Writes the 4-byte parser result record: `status` at +0x00 (`strb`),
/// `code` at +0x01 (`strb`), `detail` as a little-endian u16 at +0x02
/// (`strh`), and returns `out` (the original simply never clobbers r0,
/// and its callers rely on that). No NULL check, exactly like the
/// original.
///
/// # Safety
///
/// `out` must point into a writable allocation covering `out..out+4`.
/// Byte and half stores, so `out` needs only 2-byte alignment, as in
/// the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parse_result_init(
    out: *mut u8,
    status: u8,
    code: u8,
    detail: u16,
) -> *mut u8 {
    out.write_volatile(status);
    out.add(1).write_volatile(code);
    (out.add(2) as *mut u16).write_volatile(detail);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2-aligned record buffer — the original's `strh` carries the
    /// same halfword-alignment contract on ARMv5.
    #[repr(align(2))]
    struct Record([u8; 5]);

    #[test]
    fn fields_land_at_byte_byte_le_u16_offsets() {
        let mut record = Record([0xa5u8; 5]);
        let out = record.0.as_mut_ptr();
        let returned = unsafe { parse_result_init(out, 1, 2, 0x3456) };
        assert_eq!(returned, out, "returns the out pointer, as the original's r0");
        assert_eq!(&record.0[..4], &[1, 2, 0x56, 0x34], "status, code, detail LE");
        assert_eq!(record.0[4], 0xa5, "not one byte past the record");
    }

    #[test]
    fn all_zero_clears_the_record() {
        // The canonical call-site shape: r1 = r2 = r3 = 0.
        let mut record = Record([0xffu8; 5]);
        unsafe { parse_result_init(record.0.as_mut_ptr(), 0, 0, 0) };
        assert_eq!(&record.0[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn all_ones_values_write_all_ones() {
        let mut record = Record([0u8; 5]);
        unsafe { parse_result_init(record.0.as_mut_ptr(), 0xff, 0xff, 0xffff) };
        assert_eq!(&record.0[..4], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn the_error_shape_the_parsers_write() {
        // FUN_080fc74c's {2, 5, 0x2000}: status 2, code 5, detail 0x2000.
        let mut record = Record([0u8; 5]);
        unsafe { parse_result_init(record.0.as_mut_ptr(), 2, 5, 0x2000) };
        assert_eq!(&record.0[..4], &[2, 5, 0x00, 0x20]);
    }
}
