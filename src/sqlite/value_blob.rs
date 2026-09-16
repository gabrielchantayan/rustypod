//! The blob extractor — how the engine hands a `Mem`/`sqlite3_value`
//! out as a raw byte buffer.
//!
//! - `sqlite3_value_blob` — original: `FUN_08391714` @ 0x08391714
//!   (60 bytes, 0x08391714..0x08391750; 4 `bl` call sites, all
//!   unconditional, binary-scanned: 0x082d2b0c, 0x082e8af4,
//!   0x0838f9bc, 0x083926d4). Upstream SQLite 3.5.9's public API
//!   `sqlite3_value_blob` (`const void *sqlite3_value_blob(
//!   sqlite3_value *pVal)` in vdbemem.c), verified line-for-line
//!   against the public 3.5.9 source. The extent is confirmed by the
//!   closing `ldmia sp!,{r4,pc}` at 0x0839174c and the distinct entry
//!   of `sqlite3_value_bytes` @ 0x08391750 (ported,
//!   `sqlite/value_bytes.rs`) — no literal pool.
//!
//! Raw listing (arm-none-eabi-objdump, ARM state):
//!
//! ```text
//! 08391714  push {r4, lr}
//! 08391718  ldrh r1, [r0, #28]      @ flags = Mem.flags (+0x1c)
//! 0839171c  mov  r4, r0
//! 08391720  tst  r1, #18            @ MEM_Str|MEM_Blob (0x12)
//! 08391724  popeq {r4, lr}
//! 08391728  moveq r1, #1            @ enc = SQLITE_UTF8
//! 0839172c  beq  0x08386718         @ tail: sqlite3ValueText
//! 08391730  mov  r0, r4
//! 08391734  bl   0x0838bbb4         @ sqlite3VdbeMemExpandBlob
//! 08391738  ldrh r0, [r4, #28]      @ reload flags (ExpandBlob rewrites)
//! 0839173c  bic  r0, r0, #2         @ clear MEM_Str
//! 08391740  orr  r0, r0, #16        @ set MEM_Blob
//! 08391744  strh r0, [r4, #28]
//! 08391748  ldr  r0, [r4, #20]      @ return Mem.z (+0x14)
//! 0839174c  pop  {r4, pc}
//! ```
//!
//! Algorithm: a value already flagged string or blob is blob-ified in
//! place — any `MEM_Zero` tail is materialized through the
//! already-ported
//! [`vdbe_mem_expand_blob`](super::vdbe_mem_expand_blob::vdbe_mem_expand_blob)
//! (its return code is discarded, exactly as upstream discards it),
//! the flags are RE-READ from memory after the call (the original's
//! second `ldrh`, because ExpandBlob clears `MEM_Zero|MEM_Term`),
//! `MEM_Str` clears and `MEM_Blob` sets, and the `z` pointer is
//! returned. Any other type (integer, real, null) falls through to a
//! tail call of [`sqlite_value_text`](super::value_text::
//! sqlite_value_text) with `enc = SQLITE_UTF8` — the text rendering
//! doubles as the blob bytes, and the NULL guard for a NULL/`MEM_Null`
//! value lives there (this wrapper has none: its opening `ldrh`
//! already dereferences the value).
//!
//! Callee map (both callees are ported):
//!
//! - 0x0838bbb4 — `sqlite3VdbeMemExpandBlob`: materialize a zero-tail
//!   blob, `SQLITE_OK`/`SQLITE_NOMEM` (discarded).
//! - 0x08386718 — `sqlite3ValueText`: render the value as UTF-8 text
//!   and return its `z`, NULL on a NULL/NULL-flagged value or a failed
//!   coercion.
//!
//! Deliberate deviations: the expand-blob call dispatches through the
//! existing [`SQLITE_VDBE_MEM_EXPAND_BLOB`](super::value_text::
//! SQLITE_VDBE_MEM_EXPAND_BLOB) slot (whose shipped default IS the
//! port) so host tests can record the call — this lowers to `blx`
//! through the slot instead of the original's direct `bl`. On target
//! `z` is read as one aligned word at +0x14 (`ldr r0,[r4,#0x14]`),
//! with a full-width unaligned pointer read on 64-bit hosts; the
//! crate-wide frame-pointer prologue and the commutative
//! `orr`/`bic` order are the remaining codegen deltas (match.py:
//! same branch structure, flag reload, and tail call).

use super::error::SQLITE_UTF8;
use super::value_new::MEM_FLAGS_OFFSET;
use super::value_text::{expand_blob_op, sqlite_value_text, MEM_BLOB, MEM_STR, MEM_Z_OFFSET};

/// sqlite3_value_blob — original: `FUN_08391714` @ 0x08391714 (60
/// bytes).
///
/// Upstream SQLite 3.5.9's `sqlite3_value_blob`: return `value`'s
/// bytes as a blob pointer. A `MEM_Str`/`MEM_Blob` value is converted
/// to a pure blob in place (`MEM_Str` cleared, `MEM_Blob` set, after
/// materializing any `MEM_Zero` tail) and its `z` is returned; any
/// other type is coerced through the UTF-8 text extractor and that
/// text pointer is returned instead.
///
/// Register usage: r0 = value (saved in r4), r1 = scratch flags then
/// `enc = SQLITE_UTF8` on the text tail, r0 = `z` or the text
/// extractor's result on return.
///
/// # Safety
/// Like the original's opening `ldrh`, there is no NULL guard:
/// `value` must name a live 0x28-byte `Mem` whose flags at +0x1c may
/// be rewritten (by this function and by the dispatched callees) and
/// whose `z` at +0x14 is a readable pointer field.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_value_blob(value: *mut u8) -> *mut u8 {
    let flags_ptr = value.add(MEM_FLAGS_OFFSET) as *mut u16;
    if flags_ptr.read() & (MEM_STR | MEM_BLOB) == 0 {
        return sqlite_value_text(value, SQLITE_UTF8);
    }
    (expand_blob_op())(value);
    // Reload: ExpandBlob clears MEM_Zero|MEM_Term in the cell.
    let flags = flags_ptr.read();
    flags_ptr.write((flags & !MEM_STR) | MEM_BLOB);
    // On target `z` is a 4-aligned word field (Mem buffers are 8-byte
    // aligned), matching the original's single `ldr r0,[r4,#0x14]`;
    // on 64-bit hosts the fixture stores a full-width pointer.
    #[cfg(target_pointer_width = "32")]
    {
        (value.add(MEM_Z_OFFSET) as *const u32).read() as *mut u8
    }
    #[cfg(not(target_pointer_width = "32"))]
    {
        (value.add(MEM_Z_OFFSET) as *const *mut u8).read_unaligned()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::value_new::MEM_SIZE;
    use super::super::value_text::{
        SQLITE_VDBE_MEM_EXPAND_BLOB, SQLITE_VDBE_MEM_STRINGIFY,
    };
    use super::*;
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;

    /// Serializes the dispatch-slot swaps (the `sqlite/value_text.rs`
    /// convention).
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    /// The `MEM_Null` flag, only needed to build fixtures.
    const MEM_NULL: u16 = 0x1;
    /// The `MEM_Int` flag, only needed to build fixtures.
    const MEM_INT: u16 = 0x4;
    /// The `MEM_Term` flag, only needed to build fixtures.
    const MEM_TERM: u16 = 0x20;
    /// The `MEM_Zero` flag, only needed to build fixtures.
    const MEM_ZERO: u16 = 0x800;

    /// Whether the expand-blob recorder ran.
    static mut EXPAND_CALLS: u32 = 0;

    /// Success-shaped recording `sqlite3VdbeMemExpandBlob`: the zero
    /// tail is materialized, so `MEM_Zero|MEM_Term` clear (`& 0xf7df`
    /// in the original's port).
    unsafe extern "C" fn recording_expand_blob(mem: *mut u8) -> i32 {
        *core::ptr::addr_of_mut!(EXPAND_CALLS) += 1;
        let flags_ptr = mem.add(MEM_FLAGS_OFFSET) as *mut u16;
        // The original early-returns when MEM_Zero is clear.
        if flags_ptr.read() & MEM_ZERO != 0 {
            flags_ptr.write(flags_ptr.read() & !(MEM_ZERO | MEM_TERM));
        }
        0
    }

    /// Recording `sqlite3VdbeMemStringify` that stamps the
    /// rendered-string shape (`MEM_Str|MEM_Term`, `Mem.enc = enc`)
    /// like the original's success path, so the text extractor returns
    /// the cell's `z`.
    unsafe extern "C" fn landing_stringify(mem: *mut u8, enc: u8) -> i32 {
        (*core::ptr::addr_of_mut!(STRINGIFY_ENCS)).push(enc);
        let flags_ptr = mem.add(MEM_FLAGS_OFFSET) as *mut u16;
        flags_ptr.write(flags_ptr.read() | MEM_STR | MEM_TERM);
        (mem.add(super::super::value_text::MEM_ENC_OFFSET) as *mut u8).write(enc);
        0
    }

    /// Encodings the stringify recorder saw, in call order.
    static mut STRINGIFY_ENCS: Vec<u8> = Vec::new();

    /// A stand-in 0x28-byte `Mem` plus the byte buffer its `z` names.
    struct TestMem {
        block: [u8; MEM_SIZE as usize],
        bytes: [u8; 8],
    }

    impl TestMem {
        fn new(flags: u16, enc: u8) -> TestMem {
            let mut mem = TestMem { block: [0xa5; MEM_SIZE as usize], bytes: *b"media\0\0\0" };
            (mem.block[MEM_FLAGS_OFFSET..MEM_FLAGS_OFFSET + 2])
                .copy_from_slice(&flags.to_ne_bytes());
            mem.block[super::super::value_text::MEM_ENC_OFFSET] = enc;
            mem
        }

        /// Write the current address of `bytes` into the `z` field
        /// (must run after any move of the fixture).
        fn fix_z(&mut self) {
            let z_bytes = (self.bytes.as_mut_ptr() as usize).to_ne_bytes();
            self.block[MEM_Z_OFFSET..MEM_Z_OFFSET + z_bytes.len()]
                .copy_from_slice(&z_bytes);
        }

        fn ptr(&mut self) -> *mut u8 {
            self.block.as_mut_ptr()
        }

        fn flags(&self) -> u16 {
            u16::from_ne_bytes(
                self.block[MEM_FLAGS_OFFSET..MEM_FLAGS_OFFSET + 2].try_into().unwrap(),
            )
        }

        fn z(&self) -> *mut u8 {
            self.bytes.as_ptr() as *mut u8
        }
    }

    /// Install the expand-blob/stringify recorders, run `body`, then
    /// restore the shipped defaults.
    unsafe fn with_recorders(body: impl FnOnce()) {
        *core::ptr::addr_of_mut!(EXPAND_CALLS) = 0;
        (*core::ptr::addr_of_mut!(STRINGIFY_ENCS)).clear();
        let saved_expand = core::ptr::read_volatile(
            core::ptr::addr_of!(SQLITE_VDBE_MEM_EXPAND_BLOB),
        );
        let saved_stringify = core::ptr::read_volatile(
            core::ptr::addr_of!(SQLITE_VDBE_MEM_STRINGIFY),
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_EXPAND_BLOB),
            recording_expand_blob,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_STRINGIFY),
            landing_stringify,
        );
        body();
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_EXPAND_BLOB),
            saved_expand,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_STRINGIFY),
            saved_stringify,
        );
    }

    #[test]
    fn blob_returns_z_and_sets_pure_blob_flags() {
        let _guard = SLOT_LOCK.lock().unwrap();
        let mut mem = TestMem::new(MEM_BLOB | MEM_TERM, SQLITE_UTF8);
        unsafe {
            mem.fix_z();
            with_recorders(|| {
                let out = sqlite3_value_blob(mem.ptr());
                assert_eq!(out, mem.z());
                // MEM_Str was already clear; MEM_Blob stays; MEM_Term
                // survives (the recorder is never the path here).
                assert_eq!(mem.flags(), MEM_BLOB | MEM_TERM);
                assert_eq!(*core::ptr::addr_of!(EXPAND_CALLS), 1);
                assert!((*core::ptr::addr_of!(STRINGIFY_ENCS)).is_empty());
            });
        }
    }

    #[test]
    fn string_is_demoted_to_blob() {
        let _guard = SLOT_LOCK.lock().unwrap();
        let mut mem = TestMem::new(MEM_STR | MEM_TERM, SQLITE_UTF8);
        unsafe {
            mem.fix_z();
            with_recorders(|| {
                let out = sqlite3_value_blob(mem.ptr());
                assert_eq!(out, mem.z());
                // `bic r0,r0,#2; orr r0,r0,#16`: MEM_Str clears,
                // MEM_Blob sets, MEM_Term survives the reload.
                assert_eq!(mem.flags(), MEM_BLOB | MEM_TERM);
                assert_eq!(*core::ptr::addr_of!(EXPAND_CALLS), 1);
            });
        }
    }

    #[test]
    fn zero_tail_blob_rereads_flags_after_expand() {
        let _guard = SLOT_LOCK.lock().unwrap();
        let mut mem = TestMem::new(MEM_BLOB | MEM_TERM | MEM_ZERO, SQLITE_UTF8);
        unsafe {
            mem.fix_z();
            with_recorders(|| {
                let out = sqlite3_value_blob(mem.ptr());
                assert_eq!(out, mem.z());
                // The recorder clears MEM_Zero|MEM_Term; only the
                // re-read flags get the bic/orr, so both stay clear.
                assert_eq!(mem.flags(), MEM_BLOB);
                assert_eq!(*core::ptr::addr_of!(EXPAND_CALLS), 1);
            });
        }
    }

    #[test]
    fn integer_falls_through_to_utf8_text() {
        let _guard = SLOT_LOCK.lock().unwrap();
        let mut mem = TestMem::new(MEM_INT, 0);
        unsafe {
            mem.fix_z();
            with_recorders(|| {
                let out = sqlite3_value_blob(mem.ptr());
                // The landing stringify stamps MEM_Str|MEM_Term and
                // enc = requested, so the extractor returns z.
                assert_eq!(out, mem.z());
                assert_eq!(*core::ptr::addr_of!(EXPAND_CALLS), 0);
                assert_eq!(
                    *core::ptr::addr_of!(STRINGIFY_ENCS),
                    vec![SQLITE_UTF8]
                );
            });
        }
    }

    #[test]
    fn null_value_returns_null_via_text_extractor() {
        let _guard = SLOT_LOCK.lock().unwrap();
        let mut mem = TestMem::new(MEM_NULL, 0);
        unsafe {
            mem.fix_z();
            with_recorders(|| {
                let out = sqlite3_value_blob(mem.ptr());
                assert!(out.is_null());
                assert_eq!(*core::ptr::addr_of!(EXPAND_CALLS), 0);
                assert!((*core::ptr::addr_of!(STRINGIFY_ENCS)).is_empty());
                // The text extractor leaves a MEM_Null cell untouched.
                assert_eq!(mem.flags(), MEM_NULL);
            });
        }
    }

    #[test]
    fn missing_stringify_yields_null_like_the_original_oom() {
        let _guard = SLOT_LOCK.lock().unwrap();
        let mut mem = TestMem::new(MEM_INT, 0);
        // Shipped defaults: the missing-stringify seam claims
        // SQLITE_NOMEM and leaves enc stale, so the extractor's final
        // encoding check fails to NULL.
        mem.fix_z();
        let out = unsafe { sqlite3_value_blob(mem.ptr()) };
        assert!(out.is_null());
    }
}
