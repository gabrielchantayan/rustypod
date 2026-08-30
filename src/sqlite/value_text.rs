//! The text extractor — how the engine renders a `Mem`/`sqlite3_value`
//! as a NUL-terminated string in a requested encoding.
//!
//! - `sqlite_value_text` — original: `FUN_08386718` @ 0x08386718
//!   (160 bytes, 0x08386718..0x083867b8; 8 `bl` call sites,
//!   binary-scanned). Upstream SQLite 3.5.9's `sqlite3ValueText`
//!   (`const void *sqlite3ValueText(sqlite3_value *pVal, u8 enc)` in
//!   vdbemem.c), verified line-for-line against the public 3.5.9
//!   source — including the final `pVal->enc == (enc &
//!   ~SQLITE_UTF16_ALIGNED)` guard, which IS upstream (the firmware
//!   only has the asserts compiled out).
//!
//! - `sqlite3_value_text` — original: `FUN_0839179c` @ 0x0839179c
//!   (8 bytes, 0x0839179c..0x083917a4; 32 `bl` call sites, all
//!   unconditional, binary-scanned). Upstream SQLite 3.5.9's public
//!   API wrapper `sqlite3_value_text`: `mov r1,#1; b 0x08386718` —
//!   a pure tail branch into the extractor with `enc = SQLITE_UTF8`.
//!   Its three unported siblings confirm the family: 0x083917c8
//!   (`sqlite3_value_text16le`, `mov r1,#2`), 0x083917c0
//!   (`sqlite3_value_text16be`, `mov r1,#3`), 0x083917a4
//!   (`sqlite3_value_text16`, r1 = 2 or 3 by the byte-order flag byte
//!   at 0x088fa948).
//!
//! Algorithm: a NULL value or one flagged `MEM_Null` (0x1) yields NULL
//! without touching anything else. Otherwise the value is coerced
//! toward a string: `(MEM_Blob >> 3) == MEM_Str`, so a blob's flag bit
//! is shifted into `MEM_Str` (0x2) and stored back to +0x1c — blobs
//! take the recode path, not the stringify path. A `MEM_Zero`
//! (0x800, zero-tail blob) is materialized first through the inlined
//! `expandBlob(P)` macro guard (`sqlite3VdbeMemExpandBlob` @
//! 0x0838bbb4, only when 0x800 is set). Then, with `MEM_Str` set
//! (re-read from memory after the expansion), the string is recoded to
//! `enc & ~SQLITE_UTF16_ALIGNED` (8) by `sqlite3VdbeChangeEncoding` @
//! 0x083869f4; if the caller asked for `SQLITE_UTF16_ALIGNED` and the
//! buffer pointer `z` at +0x14 is odd,
//! `sqlite3VdbeMemMakeWriteable` @ 0x0838bb30 must make it writable
//! (returning `SQLITE_OK` = 0) or the whole call fails to NULL; then
//! `sqlite3VdbeMemNulTerminate` @ 0x0838bfb0 guarantees the double
//! NUL. Without `MEM_Str` (an integer or real), the value is rendered
//! by `sqlite3VdbeMemStringify` @ 0x0838c32c with the FULL `enc`
//! (the aligned bit is not masked on that path — `mov r1,r5`).
//! Finally the text is returned only when the value's encoding byte at
//! +0x1f now equals `enc & ~SQLITE_UTF16_ALIGNED`; a recode that could
//! not land (OOM inside a callee) leaves the byte stale and the
//! function returns NULL instead of a mis-encoded buffer.
//!
//! Callee map (all unported, seam-modeled below; identities verified
//! against the 3.5.9 source and their Ghidra decompiles):
//!
//! - 0x0838bbb4 — `sqlite3VdbeMemExpandBlob`: `n += i`, grows via
//!   0x0838bdb0, zero-fills the tail, clears `MEM_Zero|MEM_Term`
//!   (`& 0xf7df`).
//! - 0x083869f4 — `sqlite3VdbeChangeEncoding`: no-op when not
//!   `MEM_Str` or `Mem.enc == desiredEnc`; otherwise translates
//!   through UTF-8/UTF-16 with BOM handling.
//! - 0x0838bb30 — `sqlite3VdbeMemMakeWriteable`: expands a zero-blob,
//!   then if `MEM_Str|MEM_Blob` (0x12) and `z != zMalloc` (+0x24)
//!   copies into owned space and sets `MEM_Term` (0x20).
//! - 0x0838bfb0 — `sqlite3VdbeMemNulTerminate`: when `MEM_Str` without
//!   `MEM_Term`, grows `n+2` and appends the double NUL.
//! - 0x0838c32c — `sqlite3VdbeMemStringify`: grows 0x20 bytes, prints
//!   the number, sets `n`, `enc = SQLITE_UTF8` (1), `MEM_Str|MEM_Term`
//!   (0x22), then recodes through 0x083869f4.
//!
//! Call sites (binary-scanned):
//!
//! - 0x082bea9c — FUN_082be9e8 (the user-function result bridge):
//!   converts the fresh value filled by
//!   [`sqlite_value_set_str`](super::value_set_str::sqlite_value_set_str)
//!   before handing the text to the callback.
//! - 0x0837d5e4, 0x0837d5fc, 0x0837d630, 0x0837d63c — sqlite3MemCompare
//!   @ 0x0837d47c: both operands recoded to the collating sequence's
//!   encoding (`ldrb` of `pColl->enc` at +0x04) and back.
//! - 0x083864d4 — sqlite3ValueBytes @ 0x083864c0: forces the string
//!   representation so `n` measures text.
//! - 0x0838a718 — sqlite3VdbeExec @ 0x08386ecc: `enc = SQLITE_UTF8`
//!   (1).
//! - 0x0838fed4 — FUN_0838fe88.
//!
//! `Mem` fields used (layout per `sqlite/mem_release.rs` and
//! `sqlite/value_new.rs`):
//!
//! ```text
//! +0x14 z       *mut u8   text/blob buffer (read_unaligned: +0x14 is
//!                         4-aligned only, an 8-byte host read would
//!                         be misaligned)
//! +0x1c flags   u16       MEM_Null 0x1, MEM_Str 0x2, MEM_Blob 0x10,
//!                         MEM_Term 0x20, MEM_Zero 0x800
//! +0x1f enc     u8        SQLITE_UTF8 1 / UTF16LE 2 / UTF16BE 3
//! ```
//!
//! Deviations:
//! - All five callees are unported: each call goes through a dispatch
//!   static whose default slot is a documented stub reproducing the
//!   original's failure/no-op end state (the house seam pattern,
//!   `sqlite/value_set_str.rs`). The real ports should replace the
//!   defaults when they land.
//! - `enc` is typed `u8` like upstream (the firmware's full-width
//!   `bic`/`cmp` on r1 are identical for the zero-extended arguments
//!   every observed call site passes — `mov r1,#1`, `ldrb` of
//!   `pColl->enc`).

use super::error::SQLITE_UTF8;
use super::value_new::{MEM_FLAGS_OFFSET, MEM_NULL};
use super::value_set_str::SQLITE_NOMEM;

/// The original's `SQLITE_OK` return (`mov r0,#0x0` in the callees'
/// success paths).
pub const SQLITE_OK: i32 = 0;

/// Byte offset of `Mem.z` (original: `ldrne r0,[r4,#0x14]`).
pub const MEM_Z_OFFSET: usize = 0x14;

/// Byte offset of `Mem.enc` (original: `ldrb r0,[r4,#0x1f]`).
pub const MEM_ENC_OFFSET: usize = 0x1f;

/// The `MEM_Str` flag (original: `tst r0,#0x2`).
pub const MEM_STR: u16 = 0x2;

/// The `MEM_Blob` flag (original: `and r1,r0,#0x10`);
/// `(MEM_Blob >> 3) == MEM_Str` is the blob-to-string promotion.
pub const MEM_BLOB: u16 = 0x10;

/// The `MEM_Zero` flag (original: `tst r0,#0x800`) — a blob with a
/// zero-filled tail counted in `Mem.i`, materialized by the inlined
/// `expandBlob(P)` macro guard.
pub const MEM_ZERO: u16 = 0x800;

/// `SQLITE_UTF16_ALIGNED` (original: `bic r1,r5,#0x8` / `tst r5,#0x8`)
/// — OR'd into `enc` to ask for a 2-byte-aligned UTF-16 buffer.
pub const SQLITE_UTF16_ALIGNED: u8 = 0x8;

/// `sqlite3VdbeMemExpandBlob(mem)` @ 0x0838bbb4: materialize a
/// zero-tail blob, `SQLITE_OK`/`SQLITE_NOMEM` (the caller's
/// `expandBlob(P)` macro discards the code).
pub type VdbeMemExpandBlobFn = unsafe extern "C" fn(mem: *mut u8) -> i32;

/// `sqlite3VdbeChangeEncoding(mem, desired_enc)` @ 0x083869f4: recode
/// the string representation to `desired_enc` (never sees the
/// `SQLITE_UTF16_ALIGNED` bit), `SQLITE_OK`/`SQLITE_NOMEM` (discarded
/// here; the end state is observed through `Mem.enc`).
pub type VdbeChangeEncodingFn = unsafe extern "C" fn(mem: *mut u8, desired_enc: u8) -> i32;

/// `sqlite3VdbeMemMakeWriteable(mem)` @ 0x0838bb30: copy an
/// ephemeral/static string into owned, growable space;
/// `SQLITE_OK`/`SQLITE_NOMEM` — the only callee whose return code this
/// function checks.
pub type VdbeMemMakeWriteableFn = unsafe extern "C" fn(mem: *mut u8) -> i32;

/// `sqlite3VdbeMemNulTerminate(mem)` @ 0x0838bfb0: append the double
/// NUL and set `MEM_Term`, `SQLITE_OK`/`SQLITE_NOMEM` (discarded).
pub type VdbeMemNulTerminateFn = unsafe extern "C" fn(mem: *mut u8) -> i32;

/// `sqlite3VdbeMemStringify(mem, enc)` @ 0x0838c32c: render an
/// integer/real as text in `enc` (the FULL `enc`, aligned bit and
/// all), `SQLITE_OK`/`SQLITE_NOMEM` (discarded).
pub type VdbeMemStringifyFn = unsafe extern "C" fn(mem: *mut u8, enc: u8) -> i32;

/// The default for an unported `sqlite3VdbeMemExpandBlob`. The
/// `expandBlob(P)` macro discards the return code and the original
/// leaves the `Mem` untouched when its grow fails — so a no-op
/// claiming success reproduces both the original's OOM end state and
/// its behavior on any value that needs no expansion.
pub(crate) unsafe extern "C" fn missing_vdbe_mem_expand_blob(_mem: *mut u8) -> i32 {
    SQLITE_OK
}

/// The default for an unported `sqlite3VdbeChangeEncoding`: no-op
/// shaped like the original's recode-OOM end state — `Mem.enc` stays
/// stale, this wrapper's final encoding check fails, and the caller
/// gets NULL. (When no recode was needed the no-op IS the original,
/// which returns early without touching the `Mem`.)
pub(crate) unsafe extern "C" fn missing_vdbe_change_encoding(
    _mem: *mut u8,
    _desired_enc: u8,
) -> i32 {
    SQLITE_NOMEM
}

/// The default for an unported `sqlite3VdbeMemMakeWriteable`:
/// `SQLITE_NOMEM` — this wrapper returns NULL on the odd-aligned path,
/// exactly the original's OOM end state.
pub(crate) unsafe extern "C" fn missing_vdbe_mem_make_writeable(_mem: *mut u8) -> i32 {
    SQLITE_NOMEM
}

/// The default for an unported `sqlite3VdbeMemNulTerminate`. The
/// wrapper discards the code, and the original is itself a no-op when
/// `MEM_Term` is already set — a no-op claiming success.
pub(crate) unsafe extern "C" fn missing_vdbe_mem_nul_terminate(_mem: *mut u8) -> i32 {
    SQLITE_OK
}

/// The default for an unported `sqlite3VdbeMemStringify`: no-op shaped
/// like the original's stringify-OOM end state — flags/`Mem.enc`
/// untouched, the final encoding check fails, NULL out.
pub(crate) unsafe extern "C" fn missing_vdbe_mem_stringify(_mem: *mut u8, _enc: u8) -> i32 {
    SQLITE_NOMEM
}

/// Active `sqlite3VdbeMemExpandBlob` dispatch slot. Host tests install
/// a recording replacement; the real port should replace this default
/// when it lands.
pub static mut SQLITE_VDBE_MEM_EXPAND_BLOB: VdbeMemExpandBlobFn =
    missing_vdbe_mem_expand_blob;

/// Active `sqlite3VdbeChangeEncoding` dispatch slot (same pattern as
/// [`SQLITE_VDBE_MEM_EXPAND_BLOB`]).
pub static mut SQLITE_VDBE_CHANGE_ENCODING: VdbeChangeEncodingFn =
    missing_vdbe_change_encoding;

/// Active `sqlite3VdbeMemMakeWriteable` dispatch slot (same pattern).
pub static mut SQLITE_VDBE_MEM_MAKE_WRITEABLE: VdbeMemMakeWriteableFn =
    missing_vdbe_mem_make_writeable;

/// Active `sqlite3VdbeMemNulTerminate` dispatch slot (same pattern).
pub static mut SQLITE_VDBE_MEM_NUL_TERMINATE: VdbeMemNulTerminateFn =
    missing_vdbe_mem_nul_terminate;

/// Active `sqlite3VdbeMemStringify` dispatch slot (same pattern).
pub static mut SQLITE_VDBE_MEM_STRINGIFY: VdbeMemStringifyFn = missing_vdbe_mem_stringify;

/// Read the expand-blob slot volatile so its default remains
/// replaceable.
#[inline(always)]
pub(crate) unsafe fn expand_blob_op() -> VdbeMemExpandBlobFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_MEM_EXPAND_BLOB))
}

/// Read the change-encoding slot volatile (same pattern).
#[inline(always)]
pub(crate) unsafe fn change_encoding_op() -> VdbeChangeEncodingFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_CHANGE_ENCODING))
}

/// Read the make-writeable slot volatile (same pattern).
#[inline(always)]
pub(crate) unsafe fn mem_make_writeable_op() -> VdbeMemMakeWriteableFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_MEM_MAKE_WRITEABLE))
}

/// Read the nul-terminate slot volatile (same pattern).
#[inline(always)]
pub(crate) unsafe fn mem_nul_terminate_op() -> VdbeMemNulTerminateFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_MEM_NUL_TERMINATE))
}

/// Read the stringify slot volatile (same pattern).
#[inline(always)]
pub(crate) unsafe fn mem_stringify_op() -> VdbeMemStringifyFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_VDBE_MEM_STRINGIFY))
}

/// sqlite_value_text — original: `FUN_08386718` @ 0x08386718 (160
/// bytes).
///
/// `sqlite3ValueText`: render `value` as a NUL-terminated string in
/// encoding `enc` (1 = UTF-8, 2 = UTF-16LE, 3 = UTF-16BE, OR'd with
/// [`SQLITE_UTF16_ALIGNED`] to demand a 2-byte-aligned buffer) and
/// return its `z` pointer. Returns NULL for a NULL/NULL-flagged value,
/// when an odd-aligned buffer cannot be made writable, or when the
/// value's encoding byte does not match the request afterwards (the
/// original's way of reporting an OOM inside a callee).
///
/// Register usage: r0 = value (saved in r4), r1 = enc (saved in r5),
/// r0 = `z` or NULL on return.
///
/// # Safety
/// `value`, when non-NULL, must name a live 0x28-byte `Mem`; its flags
/// at +0x1c may be rewritten (blob promotion, and arbitrarily by the
/// dispatched callees).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_value_text(value: *mut u8, enc: u8) -> *mut u8 {
    if value.is_null() {
        return core::ptr::null_mut();
    }
    let flags_ptr = value.add(MEM_FLAGS_OFFSET) as *mut u16;
    let flags = flags_ptr.read();
    if flags & MEM_NULL != 0 {
        return core::ptr::null_mut();
    }
    // (MEM_Blob >> 3) == MEM_Str: a blob gains the string flag so it
    // takes the recode path below, not the stringify path.
    let flags = flags | ((flags & MEM_BLOB) >> 3);
    flags_ptr.write(flags);
    if flags & MEM_ZERO != 0 {
        (expand_blob_op())(value);
    }
    if flags_ptr.read() & MEM_STR != 0 {
        (change_encoding_op())(value, enc & !SQLITE_UTF16_ALIGNED);
        if enc & SQLITE_UTF16_ALIGNED != 0 {
            let z = (value.add(MEM_Z_OFFSET) as *const *mut u8).read_unaligned();
            if (z as usize) & 1 != 0 && (mem_make_writeable_op())(value) != SQLITE_OK {
                return core::ptr::null_mut();
            }
        }
        (mem_nul_terminate_op())(value);
    } else {
        (mem_stringify_op())(value, enc);
    }
    if u32::from((value.add(MEM_ENC_OFFSET) as *const u8).read())
        == u32::from(enc & !SQLITE_UTF16_ALIGNED)
    {
        (value.add(MEM_Z_OFFSET) as *const *mut u8).read_unaligned()
    } else {
        core::ptr::null_mut()
    }
}

/// sqlite3_value_text — original: `FUN_0839179c` @ 0x0839179c (8
/// bytes).
///
/// Upstream SQLite 3.5.9's public API wrapper
/// (`const void *sqlite3_value_text(sqlite3_value *pVal)` in
/// vdbemem.c):
///
/// ```text
/// 0839179c  mov  r1,#0x1        @ enc = SQLITE_UTF8
/// 083917a0  b    0x08386718     @ tail: sqlite_value_text
/// ```
///
/// The r0 value pointer passes through untouched and the body is a
/// pure tail branch — the extractor sees exactly what this wrapper
/// sees, with `enc` forced to `SQLITE_UTF8` (1). 32 `bl` call sites,
/// all unconditional (no predicated `blne`/`bleq` forms,
/// binary-scanned): no caller NULL-guards the value first, the
/// extractor's own NULL/`MEM_Null` checks are the only guard.
///
/// # Safety
/// Same contract as [`sqlite_value_text`]: `value`, when non-NULL,
/// must name a live 0x28-byte `Mem` whose flags at +0x1c may be
/// rewritten.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_value_text(value: *mut u8) -> *mut u8 {
    sqlite_value_text(value, SQLITE_UTF8)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes the dispatch-slot swaps (the `sqlite/expr_new.rs`
    /// convention).
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    /// The `MEM_Term` flag, only needed to build fixtures.
    const MEM_TERM: u16 = 0x20;
    /// The `MEM_Static` flag, only needed to build fixtures.
    const MEM_STATIC: u16 = 0x80;
    /// The `MEM_Int` flag, only needed to build fixtures.
    const MEM_INT: u16 = 0x4;
    /// The `MEM_Real` flag, only needed to build fixtures.
    const MEM_REAL: u16 = 0x8;

    /// One dispatched callee invocation, in call order.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Call {
        ExpandBlob,
        ChangeEncoding(u8),
        MakeWriteable,
        NulTerminate,
        Stringify(u8),
    }

    static mut CALLS: Vec<Call> = Vec::new();
    /// What the make-writeable recorder returns.
    static mut MAKE_WRITEABLE_RC: i32 = SQLITE_OK;
    /// Whether the change-encoding recorder lands the requested
    /// encoding (true = the original's success shape).
    static mut CHANGE_ENCODING_LANDS: bool = true;
    /// Whether the stringify recorder lands the rendered string (true
    /// = the original's success shape).
    static mut STRINGIFY_LANDS: bool = true;

    unsafe fn push(call: Call) {
        (*core::ptr::addr_of_mut!(CALLS)).push(call);
    }

    unsafe fn calls() -> Vec<Call> {
        (*core::ptr::addr_of!(CALLS)).clone()
    }

    /// Success-shaped recording `sqlite3VdbeMemExpandBlob`: the zero
    /// tail is materialized, so `MEM_Zero|MEM_Term` clear (`& 0xf7df`
    /// in the original).
    unsafe extern "C" fn recording_expand_blob(mem: *mut u8) -> i32 {
        push(Call::ExpandBlob);
        let flags_ptr = mem.add(MEM_FLAGS_OFFSET) as *mut u16;
        flags_ptr.write(flags_ptr.read() & !(MEM_ZERO | MEM_TERM));
        SQLITE_OK
    }

    /// Recording `sqlite3VdbeChangeEncoding`; with
    /// [`CHANGE_ENCODING_LANDS`] set it lands the requested encoding in
    /// `Mem.enc` like a successful recode.
    unsafe extern "C" fn recording_change_encoding(mem: *mut u8, desired_enc: u8) -> i32 {
        push(Call::ChangeEncoding(desired_enc));
        if *core::ptr::addr_of!(CHANGE_ENCODING_LANDS) {
            (mem.add(MEM_ENC_OFFSET) as *mut u8).write(desired_enc);
            SQLITE_OK
        } else {
            SQLITE_NOMEM
        }
    }

    /// Recording `sqlite3VdbeMemMakeWriteable`; returns
    /// [`MAKE_WRITEABLE_RC`].
    unsafe extern "C" fn recording_make_writeable(_mem: *mut u8) -> i32 {
        push(Call::MakeWriteable);
        *core::ptr::addr_of!(MAKE_WRITEABLE_RC)
    }

    /// Recording `sqlite3VdbeMemNulTerminate` (its flag/terminator
    /// writes are unobservable to this wrapper).
    unsafe extern "C" fn recording_nul_terminate(_mem: *mut u8) -> i32 {
        push(Call::NulTerminate);
        SQLITE_OK
    }

    /// Recording `sqlite3VdbeMemStringify`; with [`STRINGIFY_LANDS`]
    /// set it stamps the rendered-string shape (`MEM_Str|MEM_Term`,
    /// `Mem.enc = enc`) like the original's success path.
    unsafe extern "C" fn recording_stringify(mem: *mut u8, enc: u8) -> i32 {
        push(Call::Stringify(enc));
        if *core::ptr::addr_of!(STRINGIFY_LANDS) {
            let flags_ptr = mem.add(MEM_FLAGS_OFFSET) as *mut u16;
            flags_ptr.write(flags_ptr.read() | MEM_STR | MEM_TERM);
            (mem.add(MEM_ENC_OFFSET) as *mut u8).write(enc);
            SQLITE_OK
        } else {
            SQLITE_NOMEM
        }
    }

    /// Install the recording seams with the given effect knobs, run
    /// `body`, then restore the shipped stub defaults (the
    /// `sqlite/value_set_str.rs` convention).
    unsafe fn with_recorders(
        make_writeable_rc: i32,
        change_encoding_lands: bool,
        stringify_lands: bool,
        body: impl FnOnce(),
    ) {
        (*core::ptr::addr_of_mut!(CALLS)).clear();
        *core::ptr::addr_of_mut!(MAKE_WRITEABLE_RC) = make_writeable_rc;
        *core::ptr::addr_of_mut!(CHANGE_ENCODING_LANDS) = change_encoding_lands;
        *core::ptr::addr_of_mut!(STRINGIFY_LANDS) = stringify_lands;
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_EXPAND_BLOB),
            recording_expand_blob,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_CHANGE_ENCODING),
            recording_change_encoding,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_MAKE_WRITEABLE),
            recording_make_writeable,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_NUL_TERMINATE),
            recording_nul_terminate,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_STRINGIFY),
            recording_stringify,
        );
        body();
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_EXPAND_BLOB),
            missing_vdbe_mem_expand_blob,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_CHANGE_ENCODING),
            missing_vdbe_change_encoding,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_MAKE_WRITEABLE),
            missing_vdbe_mem_make_writeable,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_NUL_TERMINATE),
            missing_vdbe_mem_nul_terminate,
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(SQLITE_VDBE_MEM_STRINGIFY),
            missing_vdbe_mem_stringify,
        );
    }

    /// A stand-in 0x28-byte `Mem` plus the byte buffer its `z` names.
    struct TestMem {
        block: [u8; super::super::value_new::MEM_SIZE as usize],
        text: [u8; 8],
    }

    impl TestMem {
        fn new(flags: u16, enc: u8, odd_z: bool) -> TestMem {
            let mut mem = TestMem { block: [0xa5; 0x28], text: *b"media\0\0\0" };
            (mem.block[MEM_FLAGS_OFFSET..MEM_FLAGS_OFFSET + 2])
                .copy_from_slice(&flags.to_ne_bytes());
            mem.block[MEM_ENC_OFFSET] = enc;
            let mut z = mem.text.as_mut_ptr();
            if odd_z {
                z = unsafe { z.add(1) };
            }
            let z_bytes = (z as usize).to_ne_bytes();
            mem.block[MEM_Z_OFFSET..MEM_Z_OFFSET + z_bytes.len()].copy_from_slice(&z_bytes);
            mem
        }

        fn ptr(&mut self) -> *mut u8 {
            self.block.as_mut_ptr()
        }

        fn flags(&self) -> u16 {
            u16::from_ne_bytes(
                self.block[MEM_FLAGS_OFFSET..MEM_FLAGS_OFFSET + 2].try_into().unwrap(),
            )
        }

        fn enc(&self) -> u8 {
            self.block[MEM_ENC_OFFSET]
        }

        fn z(&self) -> *mut u8 {
            let width = core::mem::size_of::<usize>();
            let mut bytes = [0u8; core::mem::size_of::<usize>()];
            bytes.copy_from_slice(&self.block[MEM_Z_OFFSET..MEM_Z_OFFSET + width]);
            usize::from_ne_bytes(bytes) as *mut u8
        }
    }

    /// The recorder-effect knobs, so the reference model can mirror the
    /// seams' success shapes.
    #[derive(Clone, Copy)]
    struct Effects {
        make_writeable_rc: i32,
        change_encoding_lands: bool,
        stringify_lands: bool,
    }

    /// Independent reference model of the original, written straight
    /// from the algorithm: NULL-flag short-circuit, blob promotion,
    /// zero-blob expansion, the recode/aligned/terminate path vs the
    /// stringify path, and the final encoding check. Returns the
    /// result pointer, the expected callee sequence, and the expected
    /// final (flags, enc).
    fn reference_value_text(
        value: *mut u8,
        mut flags: u16,
        mut mem_enc: u8,
        z: *mut u8,
        enc: u8,
        fx: Effects,
    ) -> (*mut u8, Vec<Call>, u16, u8) {
        let mut calls = Vec::new();
        if value.is_null() || flags & MEM_NULL != 0 {
            return (core::ptr::null_mut(), calls, flags, mem_enc);
        }
        flags |= (flags & MEM_BLOB) >> 3;
        if flags & MEM_ZERO != 0 {
            calls.push(Call::ExpandBlob);
            flags &= !(MEM_ZERO | MEM_TERM);
        }
        if flags & MEM_STR != 0 {
            let desired = enc & !SQLITE_UTF16_ALIGNED;
            calls.push(Call::ChangeEncoding(desired));
            if fx.change_encoding_lands {
                mem_enc = desired;
            }
            if enc & SQLITE_UTF16_ALIGNED != 0 && (z as usize) & 1 != 0 {
                calls.push(Call::MakeWriteable);
                if fx.make_writeable_rc != SQLITE_OK {
                    return (core::ptr::null_mut(), calls, flags, mem_enc);
                }
            }
            calls.push(Call::NulTerminate);
        } else {
            calls.push(Call::Stringify(enc));
            if fx.stringify_lands {
                flags |= MEM_STR | MEM_TERM;
                mem_enc = enc;
            }
        }
        let result = if mem_enc == enc & !SQLITE_UTF16_ALIGNED {
            z
        } else {
            core::ptr::null_mut()
        };
        (result, calls, flags, mem_enc)
    }

    #[test]
    fn a_null_value_returns_null_without_touching_anything() {
        let _guard = SLOT_LOCK.lock().unwrap();
        for enc in [1u8, 2, 3, 9, 10, 11] {
            unsafe {
                with_recorders(SQLITE_OK, true, true, || {
                    assert_eq!(
                        sqlite_value_text(core::ptr::null_mut(), enc),
                        core::ptr::null_mut(),
                        "enc={enc}",
                    );
                    assert!(calls().is_empty(), "enc={enc}: no callee is reached");
                });
            }
        }
    }

    #[test]
    fn the_flag_and_encoding_matrix_matches_the_reference_model() {
        let _guard = SLOT_LOCK.lock().unwrap();
        let flag_shapes = [
            ("null", MEM_NULL),
            ("str+term", MEM_STR | MEM_TERM),
            ("str+term+static", MEM_STR | MEM_TERM | MEM_STATIC),
            ("blob", MEM_BLOB),
            ("blob+static", MEM_BLOB | MEM_STATIC),
            ("blob+zero", MEM_BLOB | MEM_ZERO),
            ("str+zero", MEM_STR | MEM_ZERO),
            ("int", MEM_INT),
            ("real", MEM_REAL),
            ("int+str", MEM_INT | MEM_STR),
        ];
        let effects = [
            Effects { make_writeable_rc: SQLITE_OK, change_encoding_lands: true, stringify_lands: true },
            Effects { make_writeable_rc: SQLITE_NOMEM, change_encoding_lands: true, stringify_lands: true },
            Effects { make_writeable_rc: SQLITE_OK, change_encoding_lands: false, stringify_lands: true },
            Effects { make_writeable_rc: SQLITE_OK, change_encoding_lands: true, stringify_lands: false },
            Effects { make_writeable_rc: SQLITE_NOMEM, change_encoding_lands: false, stringify_lands: false },
        ];
        for (shape, flags) in flag_shapes {
            for enc in [1u8, 2, 3, 9, 10, 11] {
                for initial_enc in [1u8, 2] {
                    for odd_z in [false, true] {
                        for fx in effects {
                            unsafe {
                                with_recorders(
                                    fx.make_writeable_rc,
                                    fx.change_encoding_lands,
                                    fx.stringify_lands,
                                    || {
                                        let mut mem = TestMem::new(flags, initial_enc, odd_z);
                                        let z = mem.z();
                                        let (want, want_calls, want_flags, want_enc) =
                                            reference_value_text(
                                                mem.ptr(), flags, initial_enc, z, enc, fx,
                                            );
                                        let got = sqlite_value_text(mem.ptr(), enc);
                                        let case = std::format!(
                                            "shape={shape} enc={enc} enc0={initial_enc} \
                                             odd_z={odd_z} fx=({}, {}, {})",
                                            fx.make_writeable_rc,
                                            fx.change_encoding_lands,
                                            fx.stringify_lands,
                                        );
                                        assert_eq!(got, want, "{case}: result pointer");
                                        assert_eq!(calls(), want_calls, "{case}: callee sequence");
                                        assert_eq!(mem.flags(), want_flags, "{case}: final flags");
                                        assert_eq!(mem.enc(), want_enc, "{case}: final enc");
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_stub_defaults_reproduce_the_documented_end_states() {
        let _guard = SLOT_LOCK.lock().unwrap();
        unsafe {
            // No recorders: the shipped stubs are in place. A string
            // already in the requested encoding needs no recode, so
            // the no-op change-encoding stub IS the original — z out.
            let mut mem = TestMem::new(MEM_STR | MEM_TERM, 1, false);
            let z = mem.z();
            assert_eq!(sqlite_value_text(mem.ptr(), 1), z, "no recode needed: z verbatim");

            // A stale encoding byte fails the final check — the
            // original's recode-OOM end state.
            let mut mem = TestMem::new(MEM_STR | MEM_TERM, 1, false);
            assert_eq!(
                sqlite_value_text(mem.ptr(), 2),
                core::ptr::null_mut(),
                "recode stub lands nothing: NULL",
            );

            // A blob is promoted to MEM_Str even on the failing path.
            let mut mem = TestMem::new(MEM_BLOB, 1, false);
            assert_eq!(sqlite_value_text(mem.ptr(), 2), core::ptr::null_mut());
            assert_eq!(mem.flags(), MEM_BLOB | MEM_STR, "blob promotion still happens");

            // The stringify stub lands nothing, so an integer whose
            // stale encoding byte does not match the request fails
            // the final check.
            let mut mem = TestMem::new(MEM_INT, 2, false);
            assert_eq!(sqlite_value_text(mem.ptr(), 1), core::ptr::null_mut());

            // The make-writeable stub's SQLITE_NOMEM fails the
            // odd-aligned path outright.
            let mut mem = TestMem::new(MEM_STR | MEM_TERM, 2, true);
            assert_eq!(sqlite_value_text(mem.ptr(), 2 | SQLITE_UTF16_ALIGNED), core::ptr::null_mut());
        }
    }

    #[test]
    fn the_api_wrapper_forwards_utf8_unchanged_value_and_result() {
        let _guard = SLOT_LOCK.lock().unwrap();
        unsafe {
            with_recorders(SQLITE_OK, true, true, || {
                // The recode path: ChangeEncoding receives SQLITE_UTF8
                // exactly (the original's `mov r1,#1`); the value
                // pointer and the result pointer pass through
                // untouched.
                let mut mem = TestMem::new(MEM_STR | MEM_TERM, 2, false);
                let z = mem.z();
                assert_eq!(sqlite3_value_text(mem.ptr()), z);
                assert_eq!(
                    calls(),
                    [Call::ChangeEncoding(SQLITE_UTF8), Call::NulTerminate],
                    "the wrapper hands enc = SQLITE_UTF8 (1) down",
                );
            });

            // The stringify path sees the same SQLITE_UTF8.
            with_recorders(SQLITE_OK, true, true, || {
                let mut mem = TestMem::new(MEM_INT, 1, false);
                let z = mem.z();
                assert_eq!(sqlite3_value_text(mem.ptr()), z);
                assert_eq!(calls(), [Call::Stringify(SQLITE_UTF8)]);
            });

            // NULL: no caller among the 32 unconditional `bl` sites
            // guards first, so NULL must reach the extractor's own
            // short-circuit — NULL out, no callee invoked.
            with_recorders(SQLITE_OK, true, true, || {
                assert_eq!(
                    sqlite3_value_text(core::ptr::null_mut()),
                    core::ptr::null_mut(),
                );
                assert!(calls().is_empty());
            });
        }
    }

    #[test]
    fn the_shipped_defaults_are_the_documented_stubs() {
        unsafe {
            assert_eq!(
                expand_blob_op() as usize,
                missing_vdbe_mem_expand_blob as usize,
            );
            assert_eq!(
                change_encoding_op() as usize,
                missing_vdbe_change_encoding as usize,
            );
            assert_eq!(
                mem_make_writeable_op() as usize,
                missing_vdbe_mem_make_writeable as usize,
            );
            assert_eq!(
                mem_nul_terminate_op() as usize,
                missing_vdbe_mem_nul_terminate as usize,
            );
            assert_eq!(
                mem_stringify_op() as usize,
                missing_vdbe_mem_stringify as usize,
            );
        }
    }
}
