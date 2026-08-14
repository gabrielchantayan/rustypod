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
//! 0x08283178  bx lr                                    ~result() — ALSO
//!                                                      PORTED HERE, as
//!                                                      [`parse_result_destroy`]
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

/// parse_result_destroy — original: `FUN_08283178` @ 0x08283178
/// (4 bytes; **46 `bl` call sites, all unconditional, 0 `b`**,
/// binary-scanned by decoding every B/BL word in osos.dec).
///
/// The record's **trivial destructor**: the whole function is one
/// instruction, `bx lr`. The record holds two `u8`s and a `u16` and
/// owns nothing, so scope exit has nothing to release — but ADS still
/// emits and calls the destructor, so it is a real `bl` target with 46
/// callers.
///
/// # It is a destructor, not a veneer or a stub
///
/// Decoded from the raw word: 0x08283178 is `0xe12fff1e`, a lone
/// `bx lr`. Not a veneer — a veneer is `ldr pc, [pc, #-4]` plus a
/// target word, or a plain `b <target>`, and neither is present. The
/// 4-byte extent is exact on both sides: 0x08283174 is the closing
/// `bx lr` of [`parse_result_init`] and 0x0828317c is the
/// `push {r4, r5, r6, r7, r8, lr}` of the next function. No literal
/// pool.
///
/// **No DATA word in the image holds 0x08283178**, so it is never
/// reached through a vtable — every caller binds it statically, which
/// is what a compiler does for a known-type destructor. 44 of the 46
/// sites sit inside the record-resource parser cluster
/// (0x080f8xxx–0x080fdxxx) in the canonical scope-exit shape
/// `add r0, sp, #N; bl 0x08283178`, destroying a record the parser
/// built on its own frame; the other two are 0x08160a58 (the same
/// stack shape) and 0x081d5e5c.
///
/// # r0 passes through, and one caller depends on it
///
/// `bx lr` leaves r0 untouched, so the function returns its argument.
/// The outer destructor @ 0x081d5e54 proves that is load-bearing
/// rather than cosmetic — it destroys an embedded record at member
/// offset +0x34 and then rebases r0 to return its own `this`:
///
/// ```text
/// 081d5e54  push {r4, lr}
/// 081d5e58  add  r0, r0, #0x34      @ &this->result
/// 081d5e5c  bl   0x08283178         @ r0 must survive
/// 081d5e60  sub  r0, r0, #0x34      @ back to this
/// 081d5e64  pop  {r4, pc}           @ return this
/// ```
///
/// A `void` port would compile to the same `bx lr` today but document
/// the wrong contract, so the signature returns `record` — the same
/// reading `cxx::trivial_destructor` records for 0x082646ac.
///
/// # Deviations
///
/// None behaviorally: the port is the identity function. It reads and
/// writes nothing, so `record` may be NULL, unaligned or dangling.
///
/// Codegen note: this body is byte-identical to the image's other empty
/// destructors, so at release opt LLVM's MergeFunctions folds it onto
/// one shared section with `cxx::trivial_destructor` &c. The symbol
/// stays in the archive's symbol table at the merged address, so hooks
/// resolve it normally — the `parse_result_init_alias_3134` situation,
/// one floor down.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parse_result_destroy(record: *mut u8) -> *mut u8 {
    record
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

    #[test]
    fn destroy_leaves_the_record_and_its_neighbours_untouched() {
        // The canonical scope-exit shape destroys a record the parser
        // built on its own frame; a destructor that wrote anything
        // would corrupt the frame it is walking off.
        let mut record = Record([0xa5u8; 5]);
        unsafe { parse_result_init(record.0.as_mut_ptr(), 2, 5, 0x2000) };
        let before = record.0;

        unsafe { parse_result_destroy(record.0.as_mut_ptr()) };

        assert_eq!(record.0, before, "the destructor reads and writes nothing");
    }

    #[test]
    fn destroy_returns_its_argument_so_a_caller_can_rebase_it() {
        // 0x081d5e54 destroys an embedded record at member offset +0x34
        // and then does `sub r0, r0, #0x34; pop {r4, pc}` to return its
        // own `this` — which only works because r0 survives the call.
        const EMBEDDED_RECORD_OFFSET: usize = 0x34;
        let mut owner = [0u8; EMBEDDED_RECORD_OFFSET + 4];
        let this = owner.as_mut_ptr();

        let returned = unsafe { parse_result_destroy(this.add(EMBEDDED_RECORD_OFFSET)) };

        assert_eq!(returned, unsafe { this.add(EMBEDDED_RECORD_OFFSET) });
        assert_eq!(unsafe { returned.sub(EMBEDDED_RECORD_OFFSET) }, this, "rebases to this");
    }

    #[test]
    fn destroy_accepts_a_null_or_unaligned_record() {
        // It dereferences nothing, so the original's missing NULL guard
        // is not a latent fault.
        assert!(unsafe { parse_result_destroy(core::ptr::null_mut()) }.is_null());
        let mut record = Record([0u8; 5]);
        let odd = unsafe { record.0.as_mut_ptr().add(1) };
        assert_eq!(unsafe { parse_result_destroy(odd) }, odd);
    }
}
