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
//! 0x08283134  strb/strb/strh; bx lr                    init —
//!                                                      [`parse_result_init_alias_3134`],
//!                                                      the byte-identical twin
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

/// parse_result_init_alias_3134 — original: `FUN_08283134` @
/// 0x08283134 (16 bytes; 42 call sites binary-scanned: 37 `bl` — 7 of
/// them conditional — plus 5 `b`).
///
/// Byte-identical twin of [`parse_result_init`] @ 0x08283168: the same
/// `strb r1,[r0]; strb r2,[r0,#1]; strh r3,[r0,#2]; bx lr` body
/// writing the same 4-byte parser result record (status +0x00, code
/// +0x01, detail LE u16 +0x02) and returning `out` in the preserved
/// r0. ADS emitted the constructor twice in the class's translation
/// unit (0x08283120–0x08283178); the call-site evidence shows no
/// semantic split — the same record-resource parser cluster calls this
/// symbol where its siblings call 0x08283168, including the signature
/// error-path rewrites (`moveq r1,#2; moveq r2,#2; moveq r3,#0x3a00;
/// beq 0x08283134` @ 0x080f8830 and `movne r1,#2; movne r2,#5; bne
/// 0x08283134` @ 0x080f8be0) and the cluster's zero-initializations;
/// the one out-of-cluster site @ 0x080a8a74 tail-writes an error
/// record {2, 3, detail} from a flags decode, the same record
/// record semantics. An independent body, not a delegation to
/// [`parse_result_init`], exactly as the original is a second emitted
/// copy rather than a branch to the first. (At release opt LLVM's
/// MergeFunctions folds the two byte-identical bodies into the shared
/// `.text.parse_result_init` section; this symbol remains in the
/// archive's symbol table at the merged address, so hooks resolve it
/// normally.)
///
/// # Safety
///
/// Same contract as [`parse_result_init`]: `out` must cover
/// `out..out+4` writable, halfword-aligned for the `strh`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parse_result_init_alias_3134(
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

    #[test]
    fn the_twin_writes_the_same_layout() {
        let mut record = Record([0xa5u8; 5]);
        let out = record.0.as_mut_ptr();
        let returned = unsafe { parse_result_init_alias_3134(out, 1, 2, 0x3456) };
        assert_eq!(returned, out, "the twin also returns its out pointer");
        assert_eq!(&record.0[..4], &[1, 2, 0x56, 0x34], "status, code, detail LE");
        assert_eq!(record.0[4], 0xa5, "not one byte past the record");
    }

    #[test]
    fn the_twin_covers_the_extreme_values() {
        let mut record = Record([0xffu8; 5]);
        unsafe { parse_result_init_alias_3134(record.0.as_mut_ptr(), 0, 0, 0) };
        assert_eq!(&record.0[..4], &[0, 0, 0, 0], "the cluster's zero-init shape");
        unsafe { parse_result_init_alias_3134(record.0.as_mut_ptr(), 0xff, 0xff, 0xffff) };
        assert_eq!(&record.0[..4], &[0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn the_twin_writes_the_clusters_error_shape() {
        // The conditional-tail-call error rewrite @ 0x080f8be0:
        // status 2, code 5, detail from a pool constant.
        let mut record = Record([0u8; 5]);
        unsafe { parse_result_init_alias_3134(record.0.as_mut_ptr(), 2, 5, 0x3a00) };
        assert_eq!(&record.0[..4], &[2, 5, 0x00, 0x3a]);
    }
}
