//! The aggregate finalize — how the VDBE turns an accumulated
//! aggregate context into a result `Mem` before the guts release.
//!
//! - `mem_finalize` — original: `FUN_0838bc38` @ 0x0838bc38 (124
//!   bytes; 2 `bl` call sites: the aggregate branch of the extern
//!   release @ 0x0838c090, which passes the FuncDef pointer at
//!   Mem+0x00, and the VDBE step machinery @ 0x0838a700). Upstream
//!   SQLite's `sqlite3VdbeMemFinalize`.
//!
//! Algorithm: a NULL `func_def` or a NULL `xFinalize` at FuncDef+0x18
//! returns 0 untouched (`cmp r1,#0x0; ldrne r2,[r1,#0x18]; cmpne
//! r2,#0x0; beq` — the original loads `xFinalize` twice, once for the
//! guard and once for the call). Otherwise a 0x40-byte frame is
//! carved off the stack holding an old-style `sqlite3_context` with
//! the result `Mem` embedded inline (upstream 3.5.x layout:
//! `FuncDef *pFunc; Mem s; Mem *pMem; int isError`):
//!
//! ```text
//! ctx+0x00 pFunc     = func_def          (str r1,[sp,#0x0])
//! ctx+0x04 pad
//! ctx+0x08 s         scratch result Mem, 0x28 bytes:
//!   s+0x10 db        = value->db         (ldr r0,[r4,#0x10]; str @ctx+0x18)
//!   s+0x1c flags     = 1 (MEM_Null)      (mov r0,#0x1; strh @ctx+0x24)
//!   s+0x24 zMalloc   = 0                 (str #0 @ctx+0x2c)
//! ctx+0x30 pMem      = value             (str r4,[sp,#0x30])
//! ctx+0x34 isError   = 0                 (str #0 @ctx+0x34)
//! ```
//!
//! `xFinalize(ctx)` is `blx`'d, then `value->zMalloc` at +0x24 is
//! freed raw (`ldr r0,[r4,#0x24]; bl sqlite3_free` @ 0x083906f4, here
//!   [`tracked_free`]), the 0x28-byte scratch `Mem` is copied over
//!   `value` (`mov r2,#0x28; add r1,sp,#0x8; mov r0,r4; bl 0x08037df8`
//!   — the ROM copy veneer, here the ported
//!   [`memcpy_forward_words`](crate::libc::memcpy::memcpy_forward_words)) —
//!   landing flags = 1 (MEM_Null) unless `xFinalize` set a result, which is
//! what clears `MEM_Agg` for the re-entered extern release — and the
//! return is `isError != 0` normalized to 0/1 (`ldr r0,[sp,#0x34];
//! cmp; movne r0,#0x1`).
//!
//! Deviations:
//! - The original's compiler omitted upstream's `memset`s of the
//!   context and scratch `Mem`; only the seven stored fields above
//!   are initialized. This port zero-fills the whole 0x40-byte frame
//!   instead (upstream's intent, and strictly safer — an `xFinalize`
//!   reading an untouched field sees 0, not stack garbage).
//! - `sqlite3_free` @ 0x083906f4 IS ported
//!   ([`tracked_free`](crate::heap::tracked::tracked_free)) and is
//!   called directly, per the porting rules. Its NULL guard stands in
//!   for the original's, which also runs unconditionally on `zMalloc`.
//! - The ROM veneer @ 0x08037df8 targets `memcpy_forward_words`; the ported
//!   [`memcpy_forward_words`](crate::libc::memcpy::memcpy_forward_words) is
//!   called directly.
//! - On 64-bit hosts the port additionally clears the upper half of
//!   the widened `zMalloc` field after the 0x28-byte result copy
//!   (`#[cfg(target_pointer_width = "64")]`, compiled out on the ARM
//!   target): this crate reads `Mem`'s pointer fields host-sized, and
//!   +0x24 is the only field whose widened read spans past the copy.
//! - This port is the shipped default `agg_finalize` slot of the
//!   extern release's
//!   [`MEM_AGG_FINALIZE_OPS`](crate::sqlite::mem_extern_release::MEM_AGG_FINALIZE_OPS),
//!   replacing the `missing_agg_finalize` stub (which cleared the
//!   `MEM_Agg`/`MEM_Dyn` bits and leaked the external string rather
//!   than guess a destructor).

use crate::heap::tracked::tracked_free;
use crate::libc::memcpy::memcpy_forward_words;
use crate::sqlite::mem_release::Z_MALLOC_OFFSET;

/// Byte offset of `Mem.db` (original: `ldr r0,[r4,#0x10]`).
pub const DB_OFFSET: usize = 0x10;
/// Byte offset of `FuncDef.xFinalize` (original:
/// `ldrne r2,[r1,#0x18]`).
pub const X_FINALIZE_OFFSET: usize = 0x18;
/// Size of a `Mem` — the scratch result copy is `mov r2,#0x28`.
pub const MEM_SIZE: usize = 0x28;
/// `MEM_Null` — the scratch `Mem`'s initial flags (original:
/// `mov r0,#0x1; strh r0,[sp,#0x24]`).
pub const FLAG_NULL: u16 = 1;

/// Byte offset of `ctx.pFunc` in the stack context
/// (original: `str r1,[sp,#0x0]`).
pub const CTX_P_FUNC_OFFSET: usize = 0x00;
/// Byte offset of the embedded scratch result `Mem` (original:
/// `add r1,sp,#0x8`).
pub const CTX_SCRATCH_OFFSET: usize = 0x08;
/// Byte offset of the scratch `Mem.db` (ctx+0x18).
pub const CTX_SCRATCH_DB_OFFSET: usize = CTX_SCRATCH_OFFSET + DB_OFFSET;
/// Byte offset of the scratch `Mem.flags` halfword (ctx+0x24).
pub const CTX_SCRATCH_FLAGS_OFFSET: usize = CTX_SCRATCH_OFFSET + 0x1c;
/// Byte offset of the scratch `Mem.zMalloc` (ctx+0x2c).
pub const CTX_SCRATCH_Z_MALLOC_OFFSET: usize = CTX_SCRATCH_OFFSET + Z_MALLOC_OFFSET;
/// Byte offset of `ctx.pMem` (original: `str r4,[sp,#0x30]`).
pub const CTX_P_MEM_OFFSET: usize = 0x30;
/// Byte offset of `ctx.isError` (original: `str r0,[sp,#0x34]`,
/// read back by `ldr r0,[sp,#0x34]`).
pub const CTX_IS_ERROR_OFFSET: usize = 0x34;
/// The original's frame size (`sub sp,sp,#0x40`).
pub const CTX_FRAME_SIZE: usize = 0x40;

/// mem_finalize — original: `FUN_0838bc38` @ 0x0838bc38 (124 bytes).
///
/// `sqlite3VdbeMemFinalize`: finalize the aggregate context `value`
/// against the FuncDef `func_def`. A NULL `func_def` or NULL
/// `xFinalize` returns 0 untouched; otherwise the user `xFinalize`
/// runs on a stack context whose embedded scratch `Mem` starts as a
/// MEM_Null in `value`'s database, `value->zMalloc` is freed, the
/// 0x28-byte scratch is copied over `value`, and `ctx.isError != 0`
/// is returned as 0/1 — the original's `cmp/cmpne/beq` guard,
/// `blx`/`bl sqlite3_free`/`bl memcpy`/`movne r0,#0x1` body.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mem_finalize(value: *mut u8, func_def: *mut u8) -> i32 {
    // cmp r1,#0x0 / ldrne r2,[r1,#0x18] / cmpne r2,#0x0 / beq — the
    // early-out returns the pre-zeroed r0 with the frame skipped.
    if func_def.is_null() {
        return 0;
    }
    let x_finalize =
        (func_def.add(X_FINALIZE_OFFSET) as *const Option<unsafe extern "C" fn(*mut u8)>).read();
    let Some(x_finalize) = x_finalize else {
        return 0;
    };

    // sub sp,sp,#0x40 — the context frame (zero-filled; see the
    // module header's deviations). All context fields are 4-byte
    // words, matching the original's `str`s; on wide-pointer hosts
    // a pointer-sized store at +0x2c/+0x30 would spill into the
    // adjacent word, so the stores below are explicitly u32 (on the
    // ARM target a pointer IS a u32 — identical codegen).
    let mut frame = [0u8; CTX_FRAME_SIZE];
    let ctx = frame.as_mut_ptr();
    // In-bounds: every store below is inside the 0x40-byte frame.
    // mov r0,#0x1; strh r0,[sp,#0x24] — scratch.flags = MEM_Null.
    (ctx.add(CTX_SCRATCH_FLAGS_OFFSET) as *mut u16).write(FLAG_NULL);
    // ldr r0,[r4,#0x10]; str r0,[sp,#0x18] — scratch.db = value->db.
    let db = (value.add(DB_OFFSET) as *const *mut u8).read();
    (ctx.add(CTX_SCRATCH_DB_OFFSET) as *mut u32).write(db as usize as u32);
    // str r4,[sp,#0x30] — ctx.pMem = value.
    (ctx.add(CTX_P_MEM_OFFSET) as *mut u32).write(value as usize as u32);
    // mov r0,#0x0; str r0,[sp,#0x2c]; str r0,[sp,#0x34] —
    // scratch.zMalloc = 0, ctx.isError = 0.
    (ctx.add(CTX_SCRATCH_Z_MALLOC_OFFSET) as *mut u32).write(0);
    (ctx.add(CTX_IS_ERROR_OFFSET) as *mut i32).write(0);
    // str r1,[sp,#0x0] — ctx.pFunc = func_def.
    (ctx.add(CTX_P_FUNC_OFFSET) as *mut u32).write(func_def as usize as u32);
    // ldr r1,[r1,#0x18]; mov r0,sp; blx r1 — xFinalize(ctx).
    x_finalize(ctx);
    // ldr r0,[r4,#0x24]; bl sqlite3_free — free value->zMalloc raw.
    let z_malloc = (value.add(Z_MALLOC_OFFSET) as *const *mut u8).read();
    tracked_free(z_malloc);
    // mov r2,#0x28; add r1,sp,#0x8; mov r0,r4; bl memcpy — the
    // finalized result replaces the aggregate context (landing
    // flags = MEM_Null, which clears MEM_Agg for the re-entered
    // extern release).
    memcpy_forward_words(value, ctx.add(CTX_SCRATCH_OFFSET), MEM_SIZE);
    // Host accommodation: this crate reads `Mem`'s pointer fields
    // host-sized, and the 0x28-byte ARM struct copy leaves the upper
    // half of the widened `zMalloc` at +0x24 stale — it is the only
    // field whose widened read spans past +0x28. Clear it so a
    // downstream host-sized read sees the NULL the copy landed (a
    // non-NULL 4-byte zMalloc from `xFinalize` is a truncated pointer
    // on a wide host either way). On the 32-bit target the copy
    // covers the whole field and this store is compiled out.
    #[cfg(target_pointer_width = "64")]
    (value.add(Z_MALLOC_OFFSET + 4) as *mut u32).write(0);
    // ldr r0,[sp,#0x34]; cmp r0,#0x0; movne r0,#0x1.
    let is_error = (ctx.add(CTX_IS_ERROR_OFFSET) as *const i32).read();
    i32::from(is_error != 0)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// Every finalize/free the code under test triggered, in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Finalize,
        RawFree(usize, usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();

    /// What the recording `xFinalize` observed in the context at call
    /// time. The pointer fields are 4-byte words (the port stores
    /// them as u32, matching the ARM original's `str`s), so they are
    /// read and compared truncated.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct Observed {
        p_func: u32,
        p_mem: u32,
        scratch_flags: u16,
        scratch_db: u32,
        is_error: i32,
    }

    static mut OBSERVED: Observed = Observed {
        p_func: 0,
        p_mem: 0,
        scratch_flags: 0,
        scratch_db: 0,
        is_error: -1,
    };

    /// The byte ramp the recording finalize writes over the scratch
    /// `Mem` — the "finalized result" the port must copy over `value`.
    fn ramp(i: usize) -> u8 {
        (i as u8) ^ 0x5a
    }

    unsafe extern "C" fn recording_x_finalize(ctx: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Finalize);
        let observed = core::ptr::addr_of_mut!(OBSERVED);
        (*observed).p_func = (ctx.add(CTX_P_FUNC_OFFSET) as *const u32).read();
        (*observed).p_mem = (ctx.add(CTX_P_MEM_OFFSET) as *const u32).read();
        (*observed).scratch_flags = (ctx.add(CTX_SCRATCH_FLAGS_OFFSET) as *const u16).read();
        (*observed).scratch_db = (ctx.add(CTX_SCRATCH_DB_OFFSET) as *const u32).read();
        (*observed).is_error = (ctx.add(CTX_IS_ERROR_OFFSET) as *const i32).read();
        for i in 0..MEM_SIZE {
            ctx.add(CTX_SCRATCH_OFFSET + i).write(ramp(i));
        }
    }

    /// Like [`recording_x_finalize`] but flags the context as failed
    /// (upstream `sqlite3_result_error` sets `ctx.isError`).
    unsafe extern "C" fn failing_x_finalize(ctx: *mut u8) {
        recording_x_finalize(ctx);
        (ctx.add(CTX_IS_ERROR_OFFSET) as *mut i32).write(1);
    }

    unsafe extern "C" fn recording_heap_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::RawFree(ptr as usize, tag));
    }

    /// Installs the mock heap (its guard serializes `HEAP_OPS`) and
    /// routes frees into the event log. The guard must stay alive for
    /// the whole test.
    fn bench() -> MutexGuard<'static, ()> {
        let heap_guard = mock_heap();
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_heap_free;
        }
        heap_guard
    }

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    fn observed() -> Observed {
        unsafe { *core::ptr::addr_of!(OBSERVED) }
    }

    /// A hand-built tag-57 tracked block (layout: `heap::tracked`). Raw
    /// block at offset 0 of a 32-aligned buffer, payload at raw + 32,
    /// pad word 32 - 8 = 24.
    #[repr(align(32))]
    struct TrackedBlock([u8; 64]);

    impl TrackedBlock {
        fn new() -> Self {
            let mut block = TrackedBlock([0; 64]);
            block.0[0..4].copy_from_slice(&24i32.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }
        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn payload(&mut self) -> *mut u8 {
            // In-bounds by construction (64-byte block, payload at 32).
            unsafe { self.0.as_mut_ptr().add(32) }
        }
    }

    /// A scratch `Mem` big enough for the +0x24 field plus one host
    /// pointer (word writes at 0x24 span 0x24..0x2c on a 64-bit host).
    #[repr(align(8))]
    struct Mem([u8; 0x30]);

    impl Mem {
        fn new() -> Self {
            Mem([0; 0x30])
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn set_word(&mut self, offset: usize, word: *mut u8) {
            // In-bounds: largest field is zMalloc at 0x24, block is 0x30.
            unsafe { (self.ptr().add(offset) as *mut *mut u8).write(word) };
        }
        fn set_flags(&mut self, flags: u16) {
            // In-bounds: flags at 0x1c, block is 0x30.
            unsafe {
                (self.ptr()
                    .add(crate::sqlite::mem_release::FLAGS_OFFSET) as *mut u16)
                    .write(flags)
            };
        }
    }

    /// A fake FuncDef: only `xFinalize` at +0x18 is read.
    #[repr(align(8))]
    struct FuncDef([u8; 0x20]);

    impl FuncDef {
        fn with_x_finalize(x_finalize: Option<unsafe extern "C" fn(*mut u8)>) -> Self {
            let mut func_def = FuncDef([0; 0x20]);
            // In-bounds: xFinalize at 0x18, block is 0x20.
            unsafe {
                (func_def.0.as_mut_ptr().add(X_FINALIZE_OFFSET)
                    as *mut Option<unsafe extern "C" fn(*mut u8)>)
                    .write(x_finalize)
            };
            func_def
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    #[test]
    fn a_null_func_def_returns_zero_and_touches_nothing() {
        let _guard = bench();
        let mut value = Mem::new();
        value.set_word(DB_OFFSET, 0x0bad_cafeusize as *mut u8);
        value.set_word(Z_MALLOC_OFFSET, 0x0bad_beefusize as *mut u8);
        value.set_flags(crate::sqlite::mem_release::FLAG_AGG);
        let before = value.0;

        let rc = unsafe { mem_finalize(value.ptr(), core::ptr::null_mut()) };

        assert_eq!(rc, 0, "NULL func_def: the pre-zeroed r0");
        assert!(events().is_empty(), "no finalize, no free");
        assert_eq!(value.0, before, "value untouched");
    }

    #[test]
    fn a_null_x_finalize_returns_zero_and_touches_nothing() {
        let _guard = bench();
        let mut value = Mem::new();
        value.set_word(Z_MALLOC_OFFSET, 0x0bad_beefusize as *mut u8);
        let mut func_def = FuncDef::with_x_finalize(None);
        let before = value.0;

        let rc = unsafe { mem_finalize(value.ptr(), func_def.ptr()) };

        assert_eq!(rc, 0, "NULL xFinalize: same early-out");
        assert!(events().is_empty(), "no finalize, no free");
        assert_eq!(value.0, before, "value untouched");
    }

    #[test]
    fn finalizes_frees_z_malloc_copies_the_result_and_returns_zero() {
        let _guard = bench();
        let mut value = Mem::new();
        let mut z_malloc_block = TrackedBlock::new();
        let z_malloc_raw = z_malloc_block.raw();
        let db = 0x0bad_cafeusize as *mut u8;
        let mut func_def = FuncDef::with_x_finalize(Some(recording_x_finalize));
        value.set_word(DB_OFFSET, db);
        value.set_word(Z_MALLOC_OFFSET, z_malloc_block.payload());
        value.set_flags(crate::sqlite::mem_release::FLAG_AGG);

        let value_ptr = value.ptr();
        let func_def_ptr = func_def.ptr();
        let rc = unsafe { mem_finalize(value_ptr, func_def_ptr) };

        assert_eq!(rc, 0, "isError stayed 0");
        assert_eq!(
            events(),
            std::vec![
                Event::Finalize,
                Event::RawFree(z_malloc_raw as usize, TAG_TRACKED),
            ],
            "xFinalize first, zMalloc free second — the original's blx; ldr/bl order"
        );
        let seen = observed();
        assert_eq!(
            seen.p_func,
            func_def_ptr as usize as u32,
            "ctx.pFunc = func_def (4-byte field, as on ARM)"
        );
        assert_eq!(
            seen.p_mem,
            value_ptr as usize as u32,
            "ctx.pMem = value (4-byte field, as on ARM)"
        );
        assert_eq!(seen.scratch_flags, FLAG_NULL, "scratch starts MEM_Null");
        assert_eq!(
            seen.scratch_db,
            db as usize as u32,
            "scratch.db = value->db (4-byte field, as on ARM)"
        );
        assert_eq!(seen.is_error, 0, "isError zeroed before the call");
        for i in 0..MEM_SIZE {
            assert_eq!(
                value.0[i],
                ramp(i),
                "byte {i:#x} of the finalized result copied over value"
            );
        }
    }

    #[test]
    fn an_x_finalize_error_returns_one_and_still_frees_and_copies() {
        let _guard = bench();
        let mut value = Mem::new();
        let mut z_malloc_block = TrackedBlock::new();
        let z_malloc_raw = z_malloc_block.raw();
        let mut func_def = FuncDef::with_x_finalize(Some(failing_x_finalize));
        value.set_word(Z_MALLOC_OFFSET, z_malloc_block.payload());

        let rc = unsafe { mem_finalize(value.ptr(), func_def.ptr()) };

        assert_eq!(rc, 1, "isError != 0 normalizes to 1 (movne r0,#0x1)");
        assert_eq!(
            events(),
            std::vec![
                Event::Finalize,
                Event::RawFree(z_malloc_raw as usize, TAG_TRACKED),
            ],
            "the free and the copy run even on error — they are unconditional"
        );
        for i in 0..MEM_SIZE {
            assert_eq!(value.0[i], ramp(i), "byte {i:#x} copied even on error");
        }
    }

    #[test]
    fn the_default_agg_finalize_slot_is_this_function() {
        use crate::sqlite::mem_extern_release::DEFAULT_MEM_AGG_FINALIZE_OPS;
        assert_eq!(
            DEFAULT_MEM_AGG_FINALIZE_OPS.agg_finalize as usize,
            mem_finalize as usize,
            "the extern release's aggregate finalize is the ported function by default"
        );
    }
}
