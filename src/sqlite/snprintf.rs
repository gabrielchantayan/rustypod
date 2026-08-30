//! The bounded, never-allocating printf SQLite formats identifiers and
//! small diagnostics into caller buffers with.
//!
//! - `sqlite_snprintf` — original: `FUN_083913b4` @ 0x083913b4 (84
//!   bytes; 41 `bl` call sites, binary-scanned: 40 plain `bl`, 1
//!   `blne` @ 0x0838f234 whose caller gates the whole call on its own
//!   flag — the callee carries no NULL guard and needs none). SQLite
//!   3.5.9's `sqlite3_snprintf` (`char *sqlite3_snprintf(int n, char
//!   *zBuf, const char *zFormat, ...)` in util.c).
//!
//! Extent 0x083913b4..0x08391408 confirmed from raw words: 21
//! instructions, no literal pool, and the sibling at 0x08391408 opens
//! with its own `push {r4,r5,r6,lr}` prologue.
//!
//! Original listing (decoded from osos.dec):
//!
//! ```text
//! 083913b4  push {r0,r1,r2,r3}     @ spill args for va_start
//! 083913b8  cmp  r0,#0
//! 083913bc  push {lr}
//! 083913c0  sub  sp,sp,#28         @ StrAccum at sp+4 (24 bytes)
//! 083913c4  movle r0,r1            @ n <= 0: return zBuf
//! 083913c8  ble  0x08391400        @ ...and skip everything
//! 083913cc  mov  r2,r0             @ n
//! 083913d0  add  r0,sp,#4          @ &acc
//! 083913d4  mov  r3,#0             @ mxAlloc = 0
//! 083913d8  bl   0x08384e84        @ sqlite3StrAccumInit(&acc, zBuf, n, 0)
//! 083913dc  mov  r0,#0
//! 083913e0  strb r0,[sp,#25]       @ acc.useMalloc = 0 (acc+0x15)
//! 083913e4  ldr  r2,[sp,#40]       @ zFormat (spilled r2)
//! 083913e8  add  r0,sp,#4          @ &acc
//! 083913ec  add  r3,sp,#44         @ ap = &spilled r3
//! 083913f0  mov  r1,#0             @ useMalloc = 0
//! 083913f4  bl   0x0839788c        @ sqlite3VXPrintf(&acc, 0, zFormat, ap)
//! 083913f8  add  r0,sp,#4
//! 083913fc  bl   0x08384e14        @ sqlite3StrAccumFinish(&acc)
//! 08391400  add  sp,sp,#28
//! 08391404  ldr  pc,[sp],#20
//! ```
//!
//! Algorithm: an `n <= 0` request returns `zBuf` untouched (the
//! `movle r0,r1` puts the buffer in the return register; nothing is
//! written, the engine never runs). Otherwise the caller's buffer IS
//! the accumulator: `str_accum_init(&acc, zBuf, n, 0)` plants `zBuf`
//! as both base and text with capacity `n` and a zero growth ceiling,
//! then the explicit `strb` at acc+0x15 forces `useMalloc` back to 0
//! (the init had set it) — this printf NEVER grows onto the heap and
//! truncates into the caller's storage. The conversion engine runs
//! with `useMalloc = 0` over `zFormat` (reloaded from the spilled r2)
//! and the variadic words starting at the spilled r3 slot — exactly
//! the `&spilled-arg` a caller's own `push {r0-r3}` builds, the house
//! explicit [`VaList`]. The result is `str_accum_finish(&acc)`: with
//! `useMalloc = 0` the finish takes its no-transfer branch — it
//! NUL-terminates at `zText + nChar` and returns `zText` unchanged,
//! so the return is `zBuf` itself.
//!
//! Call sites (binary-scanned, 41): the SQLite schema/parse/vdbe
//! cluster (0x08373f78, 0x0837cf{a4}, 0x0838b8b0,
//! `vdbe_mem_stringify`'s 0x0838c384, 0x0838f{234,28c,2cc,45c,4b8,62c},
//! 0x083920b0, 0x083921{cc,dc,f8}, 0x0839435c) and the retailOS
//! database/app layer (0x082367c4, 0x082b5{554,56c}, 0x082c2{9e8,aa8},
//! 0x082c5{54c..640}, 0x082d01d8). Representative shapes:
//! `sqlite_snprintf(30, buf, "column %d", i)` @ 0x082d01d8 and
//! `sqlite_snprintf(128, buf, fmt)` @ 0x082b5554.
//!
//! Deviations:
//! - The conversion engine `sqlite3VXPrintf` @ 0x0839788c (3324 bytes)
//!   is not ported: the call crosses the shared [`SQLITE_VXPRINTF`]
//!   dispatch seam (`sqlite/vm_printf.rs`) whose documented no-op
//!   default leaves the accumulator empty — `str_accum_finish` then
//!   just NUL-terminates `zBuf[0]` and returns `zBuf`, a state the
//!   original reaches for an empty format. Same seam
//!   `sqlite_vm_printf` already funnels through.
//! - The other two callees *are* ported and are called directly, per
//!   the porting rules: `str_accum_init` @ 0x08384e84
//!   ([`super::vdbe_op::str_accum_init`]) and `str_accum_finish` @
//!   0x08384e14 ([`super::str_accum::str_accum_finish`]).
//! - The C `va_list` is the house explicit [`VaList`] pointer, exactly
//!   as in `sqlite_vm_printf`.
//! - The 24-byte `StrAccum` lives in the Rust frame; its exact stack
//!   offset (sp+4 in the original) is the compiler's business.

use core::mem::MaybeUninit;

use super::error_msg::VaList;
use super::str_accum::{str_accum_finish, StrAccum};
use super::vdbe_op::str_accum_init;
use super::vm_printf::vx_printf_op;

/// sqlite_snprintf — original: `FUN_083913b4` @ 0x083913b4 (84 bytes;
/// 41 `bl` call sites, binary-scanned).
///
/// `sqlite3_snprintf`: format `format` with the variadic words at
/// `args` into the caller-owned `n`-byte buffer `z_buf`, truncating
/// rather than allocating, and return `z_buf`. An `n <= 0` returns
/// `z_buf` without touching it or running the engine.
///
/// Register usage: r0 = n, r1 = z_buf, r2 = format, r3 = args (the
/// caller-built va_list pointer — see the module header).
///
/// # Safety
/// `z_buf` must name writable storage of at least `n` bytes when
/// `n > 0` (the engine and the finish write through it). `format` and
/// `args` are only forwarded to the active [`SQLITE_VXPRINTF`] engine;
/// their requirements are the engine's.
///
/// [`SQLITE_VXPRINTF`]: super::vm_printf::SQLITE_VXPRINTF
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_snprintf(
    n: i32,
    z_buf: *mut u8,
    format: *const u8,
    args: VaList,
) -> *mut u8 {
    // Original: `cmp r0,#0; movle r0,r1; ble <end>` — the buffer comes
    // back untouched and the engine never runs.
    if n <= 0 {
        return z_buf;
    }
    let mut accum = MaybeUninit::<StrAccum>::uninit();
    let accum = accum.as_mut_ptr();
    // Original: `bl 0x08384e84` with r1 = z_buf, r2 = n, r3 = 0.
    str_accum_init(accum, z_buf, n, 0);
    // Original: `mov r0,#0; strb r0,[sp,#25]` (acc+0x15) — the init set
    // useMalloc; this printf never grows onto the heap.
    core::ptr::addr_of_mut!((*accum).use_malloc).write_volatile(0);
    // Original: `mov r1,#0; bl 0x0839788c`.
    (vx_printf_op())(accum, 0, format, args);
    // Original: `add r0,sp,#4; bl 0x08384e14`.
    str_accum_finish(accum)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use crate::sqlite::vm_printf::{missing_vx_printf, VxPrintfFn, SQLITE_VXPRINTF};
    use std::sync::Mutex;

    /// Serializes tests that swap the engine slot.
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    /// (use_malloc, format, ap, n_alloc, mx_alloc, use_malloc_field)
    /// the engine observed.
    static mut RECORDED: Option<(i32, *const u8, VaList, i32, i32, u8)> = None;

    /// Engine that records its arguments and the accumulator state,
    /// then renders the canned text into the caller's buffer as a
    /// bounded formatter would (base and text are the same buffer).
    unsafe extern "C" fn recording_vx_printf(
        accum: *mut StrAccum,
        use_malloc: i32,
        format: *const u8,
        ap: VaList,
    ) {
        RECORDED = Some((
            use_malloc,
            format,
            ap,
            (*accum).n_alloc,
            (*accum).mx_alloc,
            (*accum).use_malloc,
        ));
        const TEXT: &[u8] = b"hi";
        (*accum).z_base.copy_from_nonoverlapping(TEXT.as_ptr(), TEXT.len());
        (*accum).n_char = TEXT.len() as i32;
    }

    /// Serializes and installs `engine` in the slot; restores the
    /// documented default at the end so a failed assert cannot leak the
    /// mock into another test.
    fn with_engine(engine: VxPrintfFn, body: impl FnOnce()) {
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            RECORDED = None;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VXPRINTF), engine);
        }
        body();
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(SQLITE_VXPRINTF),
                missing_vx_printf,
            );
        }
    }

    #[test]
    fn a_nonpositive_n_returns_the_buffer_untouched_and_never_formats() {
        let mut buf = [0xa5u8; 16];
        let args: [u32; 1] = [7];
        with_engine(recording_vx_printf, || unsafe {
            for n in [0i32, -1, i32::MIN] {
                let result = sqlite_snprintf(n, buf.as_mut_ptr(), b"%d\0".as_ptr(), args.as_ptr());
                assert_eq!(result, buf.as_mut_ptr(), "n={n}: zBuf is returned verbatim");
            }
            assert_eq!(
                core::ptr::read(core::ptr::addr_of!(RECORDED)),
                None,
                "the engine never runs for n <= 0"
            );
        });
        assert_eq!(buf, [0xa5u8; 16], "n <= 0 writes nothing");
    }

    #[test]
    fn formats_into_the_callers_buffer_with_no_heap_growth() {
        let mut canned = [0xccu8; 8];
        let _allocator = install_recorder(canned.as_mut_ptr());
        let mut buf = [0u8; 32];
        let format = b"column %d\0".as_ptr();
        let args: [u32; 1] = [41];
        let mut result = core::ptr::null_mut();
        with_engine(recording_vx_printf, || unsafe {
            result = sqlite_snprintf(32, buf.as_mut_ptr(), format, args.as_ptr());
            let recorded = core::ptr::read(core::ptr::addr_of!(RECORDED));
            assert_eq!(
                recorded,
                Some((0, format, args.as_ptr(), 32, 0, 0)),
                "engine saw (use_malloc=0, format, ap); accumulator got \
                 n_alloc=n, mx_alloc=0, and the forced use_malloc=0"
            );
        });
        assert_eq!(result, buf.as_mut_ptr(), "the no-transfer finish returns zBuf itself");
        assert_eq!(&buf[..3], b"hi\0", "the finish terminated the rendered text in place");
        assert_eq!(
            realloc_log(),
            std::vec![] as std::vec::Vec<(usize, i32)>,
            "use_malloc=0 means the finish never allocates"
        );
    }

    #[test]
    fn the_default_engine_just_terminates_an_empty_render() {
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut buf = [0xa5u8; 4];
        unsafe {
            let result = sqlite_snprintf(4, buf.as_mut_ptr(), b"\0".as_ptr(), [0u32; 1].as_ptr());
            assert_eq!(result, buf.as_mut_ptr());
        }
        assert_eq!(buf[0], 0, "an empty accumulator terminates at n_char = 0");
        assert_eq!(buf[1..], [0xa5u8; 3], "nothing past the terminator is written");
    }
}
