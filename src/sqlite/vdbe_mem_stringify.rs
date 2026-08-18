//! Number-to-text rendering — how the engine turns a numeric `Mem`/
//! `sqlite3_value` cell (INTEGER or REAL) into its text representation.
//!
//! - `vdbe_mem_stringify` — original: `FUN_0838c32c` @ 0x0838c32c
//!   (144 bytes, 0x0838c32c..0x0838c3bc, plus two inline format-string
//!   literals at 0x0838c3bc..0x0838c3cc; **4 `bl` call sites**,
//!   binary-scanned from osos.dec — no predicated or tail branches).
//!   Upstream SQLite 3.5.x's `sqlite3VdbeMemStringify` (`int
//!   sqlite3VdbeMemStringify(Mem *pMem, int enc)` in vdbemem.c). It sits
//!   immediately after [`vdbe_mem_shallow_copy`](super::vdbe_mem_shallow_copy)
//!   @ 0x0838c2d0 in the vdbe Mem helper cluster, and is how
//!   `sqlite3ValueText`-style code materializes text out of a cell that
//!   only carries a number.
//!
//! ### Extent
//!
//! Confirmed from raw words: 0x0838c3b8 is the `ldmia sp!,
//! {r2,r3,r4,r5,r6,r7,r8,pc}` return, and the next two words are the
//! `"%lld"` / `"%!.15g"` literals the `adr` instructions build pointers
//! to; 0x0838c3cc begins the next function (`stmdb sp!, {r4,lr}`).
//! There is no literal pool — the format strings are addressed by `adr`.
//!
//! ### Listing
//!
//! ```text
//! 0838c32c  stmdb sp!, {r2,r3,r4,r5,r6,r7,r8,lr}  @ r2/r3 slots stage
//!                                               @ the varargs payload
//! 0838c330  mov  r7,r1              @ enc
//! 0838c334  ldrh r5,[r0,#0x1c]      @ flags, sampled BEFORE grow
//! 0838c338  mov  r1,#0x20
//! 0838c33c  mov  r6,#0x0            @ SQLITE_OK
//! 0838c340  mov  r4,r0              @ pMem
//! 0838c344  mov  r2,#0x0
//! 0838c348  bl   0x0838bdb0         @ sqlite3VdbeMemGrow(pMem, 32, 0)
//! 0838c34c  cmp  r0,#0x0
//! 0838c350  movne r0,#0x7           @ SQLITE_NOMEM
//! 0838c354  bne  0x0838c3b8
//! 0838c358  tst  r5,#0x4            @ MEM_Int?
//! 0838c35c  ldrdne r0,r1,[r4,#0x0]  @ pMem->u.i
//! 0838c360  strdne r0,r1,[sp,#0x0]  @ varargs slot
//! 0838c364  ldrne r1,[r4,#0x14]     @ pMem->z
//! 0838c368  adrne r2,0x838c3bc      @ "%lld"
//! 0838c36c  bne  0x0838c380
//! 0838c370  ldrd r0,r1,[r4,#0x8]    @ pMem->r
//! 0838c374  strd r0,r1,[sp,#0x0]
//! 0838c378  ldr  r1,[r4,#0x14]
//! 0838c37c  adr  r2,0x838c3c4       @ "%!.15g"
//! 0838c380  mov  r0,#0x20
//! 0838c384  bl   0x083913b4         @ sqlite3_snprintf(32, z, fmt, val)
//! 0838c388  ldr  r0,[r4,#0x14]
//! 0838c38c  bl   0x08392478         @ strlen(z)
//! 0838c390  str  r0,[r4,#0x18]      @ n
//! 0838c394  mov  r0,#0x1            @ SQLITE_UTF8
//! 0838c398  strb r0,[r4,#0x1f]      @ enc
//! 0838c39c  ldrh r0,[r4,#0x1c]      @ flags RELOADED after the calls
//! 0838c3a0  mov  r1,r7              @ the caller's enc, unmasked
//! 0838c3a4  orr  r0,r0,#0x22        @ MEM_Str | MEM_Term
//! 0838c3a8  strh r0,[r4,#0x1c]
//! 0838c3ac  mov  r0,r4
//! 0838c3b0  bl   0x083869f4         @ sqlite3VdbeChangeEncoding (rc dropped)
//! 0838c3b4  mov  r0,r6              @ SQLITE_OK
//! 0838c3b8  ldmia sp!, {r2,r3,r4,r5,r6,r7,r8,pc}
//! 0838c3bc  "%lld\0\0\0\0"
//! 0838c3c4  "%!.15g\0\0"
//! ```
//!
//! ### Algorithm
//!
//! The cell's flags are sampled once, up front. `sqlite3VdbeMemGrow`
//! guarantees 32 bytes of cell-owned payload space (enough for any
//! 64-bit integer or `%!.15g` rendering plus NUL); a failed grow
//! short-circuits to `SQLITE_NOMEM` (7) with the cell untouched. The
//! `MEM_Int` snapshot bit selects the formatter payload: the integer
//! arm renders `Mem.u` with `"%lld"`, anything else renders the
//! floating-point arm `Mem.r` with SQLite's SQL-compatible `"%!.15g"`.
//! The value itself is read *after* the grow, so a grow that moves the
//! cell cannot feed the formatter a stale number. The rendered length
//! (retailOS unguarded `strlen`, terminator excluded) is stamped into
//! `n`, the encoding byte becomes `SQLITE_UTF8` (1), and the freshly
//! reloaded flags gain `MEM_Str | MEM_Term` (0x22) — attribute bits and
//! any concurrent flag change survive the `or`. Finally the text is
//! recoded to the caller's requested encoding by
//! `sqlite3VdbeMemChangeEncoding`, whose return code is deliberately
//! discarded; the function reports only the grow's fate.
//!
//! Call sites (binary-scanned):
//!
//! - `bl` @ 0x08386798 — inside the `sqlite3ValueText` original,
//!   mirrored by the ported [`value_text`](super::value_text) dispatch
//!   slot.
//! - `bl` @ 0x08387634, `bl` @ 0x08387668 and `bl` @ 0x0838ad4c — all
//!   inside the 16 KB vdbe engine routine FUN_08386ef8 (OP_Column /
//!   OP_MakeRecord-style numeric-to-text materialization).
//!
//! ### Deviations
//!
//! - `sqlite3VdbeMemGrow` @ 0x0838bdb0, `sqlite3_snprintf` @
//!   0x083913b4 and `sqlite3VdbeChangeEncoding` @ 0x083869f4 are not
//!   ported. They form the [`VDBE_MEM_STRINGIFY_OPS`] seam: target
//!   builds call their retailOS load addresses, while host tests
//!   install recording mocks.
//! - The `sqlite3_snprintf` slot passes the variadic 8-byte payload as
//!   raw `u64` bits through a non-variadic fourth parameter. Under the
//!   target's AAPCS a 64-bit argument after three word arguments lands
//!   entirely on the stack at `[sp,#0]` — variadic or not — so the bit
//!   pattern the formatter reads is identical (`strd r0,r1,[sp,#0x0]`
//!   in both the integer and real arms). The formatter itself decides
//!   how to interpret the bits from the format string it was handed.
//! - The port goes through the typed `repr(C)` [`Mem`] with named
//!   fields rather than raw offsets; field offsets are statically
//!   asserted on 32-bit targets in `sqlite/vdbe.rs`.
//! - The format strings live in Rust rodata instead of the original's
//!   inline `adr` literals; the bytes are identical.

use crate::libc::strlen::strlen;
use super::error::SQLITE_UTF8;
use super::value_set_str::SQLITE_NOMEM;
use super::value_text::VdbeChangeEncodingFn;
use super::vdbe::Mem;
use super::vdbe_mem_realify::SQLITE_OK;
use super::vdbe_mem_set_int64::MEM_INT;
use super::vdbe_mem_set_str::{VdbeMemGrow, MEM_STR, MEM_TERM};

/// Bytes `sqlite3VdbeMemGrow` is asked to guarantee — upstream's
/// `sqlite3VdbeMemGrow(pMem, 32, 0)` (original: `mov r1,#0x20`).
pub const STRINGIFY_BUF_SIZE: i32 = 0x20;

/// Integer render format (original: the inline literal @ 0x0838c3bc,
/// reached by `adrne r2,0x838c3bc`).
pub const FMT_INT: &[u8; 5] = b"%lld\0";

/// Real render format (original: the inline literal @ 0x0838c3c4,
/// reached by `adr r2,0x838c3c4`).
pub const FMT_REAL: &[u8; 7] = b"%!.15g\0";

/// ABI of the `sqlite3_snprintf(32, z, fmt, value)` call @ 0x083913b4
/// with the variadic 8-byte payload delivered as raw bits (see the
/// module header for why a plain fourth parameter is ABI-identical
/// here). Returns the number of bytes written; this caller discards it.
pub type SqliteSnprintf =
    unsafe extern "C" fn(size: i32, z: *mut u8, fmt: *const u8, value_bits: u64) -> i32;

/// RetailOS load address of `sqlite3_snprintf`.
pub const SQLITE_SNPRINTF_ADDRESS: usize = 0x0839_13b4;
/// RetailOS load address of `sqlite3VdbeChangeEncoding`.
pub const VDBE_CHANGE_ENCODING_ADDRESS: usize = 0x0838_69f4;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_mem_grow(p_mem: *mut Mem, size: i32, preserve: i32) -> i32 {
    let grow: VdbeMemGrow =
        core::mem::transmute(super::vdbe_mem_set_str::VDBE_MEM_GROW_ADDRESS);
    grow(p_mem, size, preserve)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_mem_grow(_p_mem: *mut Mem, _size: i32, _preserve: i32) -> i32 {
    panic!("vdbe_mem_stringify requires sqlite3VdbeMemGrow @ 0x0838bdb0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_sqlite_snprintf(
    size: i32,
    z: *mut u8,
    fmt: *const u8,
    value_bits: u64,
) -> i32 {
    let snprintf: SqliteSnprintf = core::mem::transmute(SQLITE_SNPRINTF_ADDRESS);
    snprintf(size, z, fmt, value_bits)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sqlite_snprintf(
    _size: i32,
    _z: *mut u8,
    _fmt: *const u8,
    _value_bits: u64,
) -> i32 {
    panic!("vdbe_mem_stringify requires sqlite3_snprintf @ 0x083913b4")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_change_encoding(mem: *mut u8, desired_enc: u8) -> i32 {
    let change_encoding: VdbeChangeEncodingFn =
        core::mem::transmute(VDBE_CHANGE_ENCODING_ADDRESS);
    change_encoding(mem, desired_enc)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_change_encoding(_mem: *mut u8, _desired_enc: u8) -> i32 {
    panic!("vdbe_mem_stringify requires sqlite3VdbeChangeEncoding @ 0x083869f4")
}

/// Indirect dispatch for the unported grow, formatter and recode
/// helpers this renderer calls. Host tests install recording
/// implementations; target defaults branch straight into retailOS.
#[derive(Clone, Copy)]
pub struct VdbeMemStringifyOps {
    /// `sqlite3VdbeMemGrow(pMem, size, preserve)` @ 0x0838bdb0.
    pub grow: VdbeMemGrow,
    /// `sqlite3_snprintf(size, z, fmt, value)` @ 0x083913b4.
    pub snprintf: SqliteSnprintf,
    /// `sqlite3VdbeChangeEncoding(pMem, desired_enc)` @ 0x083869f4.
    pub change_encoding: VdbeChangeEncodingFn,
}

/// Target default: the three remaining retailOS helpers.
#[cfg(target_os = "none")]
pub const DEFAULT_VDBE_MEM_STRINGIFY_OPS: VdbeMemStringifyOps = VdbeMemStringifyOps {
    grow: retail_vdbe_mem_grow,
    snprintf: retail_sqlite_snprintf,
    change_encoding: retail_vdbe_change_encoding,
};

/// Host default: fail loudly until a test supplies the unported helpers.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_MEM_STRINGIFY_OPS: VdbeMemStringifyOps = VdbeMemStringifyOps {
    grow: missing_vdbe_mem_grow,
    snprintf: missing_sqlite_snprintf,
    change_encoding: missing_vdbe_change_encoding,
};

/// Active grow/formatter/recode triple. Host tests install recording
/// mocks.
pub static mut VDBE_MEM_STRINGIFY_OPS: VdbeMemStringifyOps = DEFAULT_VDBE_MEM_STRINGIFY_OPS;

/// Reads the grow slot volatile so its host replacement cannot be
/// folded into the default.
#[inline(always)]
unsafe fn grow_op() -> VdbeMemGrow {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_STRINGIFY_OPS.grow))
}

/// Reads the formatter slot volatile (same pattern).
#[inline(always)]
unsafe fn snprintf_op() -> SqliteSnprintf {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_STRINGIFY_OPS.snprintf))
}

/// Reads the recode slot volatile (same pattern).
#[inline(always)]
unsafe fn change_encoding_op() -> VdbeChangeEncodingFn {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_MEM_STRINGIFY_OPS.change_encoding))
}

/// vdbe_mem_stringify — original: `FUN_0838c32c` @ 0x0838c32c (144
/// bytes; 4 `bl` call sites).
///
/// `sqlite3VdbeMemStringify`: render the numeric cell `p_mem` as text
/// in encoding `enc`. The payload buffer is grown to 32 bytes, the
/// integer arm (`MEM_Int`) prints `Mem.u` with `"%lld"` and any other
/// value prints `Mem.r` with `"%!.15g"`; the measured length lands in
/// `n`, `enc` becomes `SQLITE_UTF8`, the reloaded flags gain
/// `MEM_Str | MEM_Term`, and the text is recoded to `enc` (return code
/// discarded). Returns `SQLITE_OK`, or `SQLITE_NOMEM` when the grow
/// fails — the only error the original reports.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_mem_stringify(p_mem: *mut u8, enc: u8) -> i32 {
    let p_mem = p_mem as *mut Mem;
    let flags = (*p_mem).flags;
    if (grow_op())(p_mem, STRINGIFY_BUF_SIZE, 0) != SQLITE_OK {
        return SQLITE_NOMEM;
    }
    let (fmt, value_bits) = if flags & MEM_INT != 0 {
        (FMT_INT.as_ptr(), (*p_mem).u)
    } else {
        (FMT_REAL.as_ptr(), (*p_mem).r.to_bits())
    };
    (snprintf_op())(STRINGIFY_BUF_SIZE, (*p_mem).z, fmt, value_bits);
    let mem = &mut *p_mem;
    mem.n = strlen(mem.z) as i32;
    mem.enc = SQLITE_UTF8;
    mem.flags |= MEM_STR | MEM_TERM;
    (change_encoding_op())(p_mem as *mut u8, enc);
    SQLITE_OK
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::vdbe_mem_realify::MEM_REAL;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that swap the grow/formatter/recode triple.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// The payload space the recording grow hands out (the original
    /// guarantees 32 bytes; extra room keeps sloppy renders safe).
    static mut PAYLOAD: [u8; 64] = [0; 64];
    /// What the recording grow returns.
    static mut GROW_RC: i32 = SQLITE_OK;
    /// What the recording recode returns (the port must discard it).
    static mut RECODE_RC: i32 = SQLITE_OK;
    /// Optional flags overwrite the recording formatter performs,
    /// proving the final `flags |= MEM_Str | MEM_Term` reloads.
    static mut FORMATTER_FLAGS_WRITE: Option<u16> = None;
    /// Optional payload-value overwrite the recording grow performs,
    /// proving the number is read after the grow.
    static mut GROW_U_WRITE: Option<u64> = None;
    /// Optional flags overwrite the recording grow performs, proving
    /// the int/real branch uses the pre-grow snapshot.
    static mut GROW_FLAGS_WRITE: Option<u16> = None;
    /// The cell the recording grow last served, so the formatter mock
    /// (which only receives `z`) can still reach it.
    static mut GROWN_MEM: usize = 0;

    /// One dispatched callee invocation, in call order.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Call {
        Grow { size: i32, preserve: i32 },
        Format { size: i32, fmt_int: bool, bits: u64 },
        ChangeEncoding { enc: u8 },
    }

    static mut CALLS: [Call; 8] = [Call::Grow { size: 0, preserve: 0 }; 8];
    static mut N_CALLS: usize = 0;

    unsafe fn push(call: Call) {
        *CALLS.get_mut(N_CALLS).expect("call log overflow") = call;
        N_CALLS += 1;
    }

    /// The grow mock: hand out the payload buffer, optionally scribble
    /// a replacement integer into the cell (as a buffer-moving grow
    /// would), and fail on request.
    unsafe extern "C" fn recording_grow(p_mem: *mut Mem, size: i32, preserve: i32) -> i32 {
        push(Call::Grow { size, preserve });
        if GROW_RC == SQLITE_OK {
            GROWN_MEM = p_mem as usize;
            if let Some(u) = GROW_U_WRITE {
                (*p_mem).u = u;
            }
            if let Some(flags) = GROW_FLAGS_WRITE {
                (*p_mem).flags = flags;
            }
            PAYLOAD.fill(0xcc);
            (*p_mem).z = core::ptr::addr_of_mut!(PAYLOAD).cast::<u8>();
        }
        GROW_RC
    }

    /// The formatter mock: record the format identity and the raw bits,
    /// then render a faithful decimal (integer) or plain real so the
    /// `strlen` the port measures has real bytes to count.
    unsafe extern "C" fn recording_snprintf(
        size: i32,
        z: *mut u8,
        fmt: *const u8,
        value_bits: u64,
    ) -> i32 {
        let fmt_int = fmt == FMT_INT.as_ptr();
        assert!(
            fmt_int || fmt == FMT_REAL.as_ptr(),
            "formatter saw a format that is neither FMT_INT nor FMT_REAL"
        );
        push(Call::Format { size, fmt_int, bits: value_bits });
        let rendered = if fmt_int {
            std::format!("{}", value_bits as i64)
        } else {
            std::format!("{}", f64::from_bits(value_bits))
        };
        assert!(rendered.len() + 1 <= size as usize, "rendering exceeds the grown buffer");
        core::ptr::copy_nonoverlapping(rendered.as_ptr(), z, rendered.len());
        *z.add(rendered.len()) = 0;
        if let Some(flags) = FORMATTER_FLAGS_WRITE {
            (*(GROWN_MEM as *mut Mem)).flags = flags;
        }
        rendered.len() as i32
    }

    /// The recode mock: record the requested encoding and return
    /// whatever it was told to.
    unsafe extern "C" fn recording_change_encoding(_mem: *mut u8, desired_enc: u8) -> i32 {
        push(Call::ChangeEncoding { enc: desired_enc });
        RECODE_RC
    }

    /// Restores the wired default triple on drop.
    struct OpsGuard;

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VDBE_MEM_STRINGIFY_OPS)
                    .write(DEFAULT_VDBE_MEM_STRINGIFY_OPS);
            }
        }
    }

    /// Takes the module lock, installs the recording triple, and zeroes
    /// its controls/log. The guards must stay alive for the whole test.
    fn bench() -> (MutexGuard<'static, ()>, OpsGuard) {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            GROW_RC = SQLITE_OK;
            RECODE_RC = SQLITE_OK;
            FORMATTER_FLAGS_WRITE = None;
            GROW_U_WRITE = None;
            GROW_FLAGS_WRITE = None;
            GROWN_MEM = 0;
            N_CALLS = 0;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_MEM_STRINGIFY_OPS),
                VdbeMemStringifyOps {
                    grow: recording_grow,
                    snprintf: recording_snprintf,
                    change_encoding: recording_change_encoding,
                },
            );
        }
        (ops_guard, OpsGuard)
    }

    /// The recorded invocations, in order.
    unsafe fn calls() -> std::vec::Vec<Call> {
        CALLS[..N_CALLS].to_vec()
    }

    /// A `Mem` with distinguishable garbage in every field, so an
    /// unintended write shows up as a mismatch. `z` points at real
    /// writable garbage so a premature read or write is visible.
    fn garbage_mem(flags: u16) -> Mem {
        Mem {
            u: 0x0bad_cafe_dead_beef,
            r: f64::from_bits(0x7ff8_0000_5a5a_5a5a),
            db: 0x0bad_1000usize as *mut u8,
            z: 0x0bad_2000usize as *mut u8,
            n: -123_456_789,
            flags,
            value_type: 0xa5,
            enc: 0xa7,
            x_del: 0x0bad_3000usize as *mut u8,
            z_malloc: 0x0bad_4000usize as *mut u8,
        }
    }

    /// The payload bytes the formatter rendered, up to the NUL.
    unsafe fn rendered() -> std::vec::Vec<u8> {
        let z = core::ptr::addr_of!(PAYLOAD).cast::<u8>();
        let mut len = 0;
        while *z.add(len) != 0 {
            len += 1;
        }
        PAYLOAD[..len].to_vec()
    }

    #[test]
    fn integer_cells_render_through_lld_with_the_u_bits() {
        let _guards = bench();
        for value in [0i64, 1, -1, 42, 999_999_999_999, i64::MAX, i64::MIN] {
            let mut mem = garbage_mem(MEM_INT);
            mem.u = value as u64;
            unsafe { N_CALLS = 0 };
            let rc = unsafe { vdbe_mem_stringify(core::ptr::addr_of_mut!(mem).cast(), SQLITE_UTF8) };
            assert_eq!(rc, SQLITE_OK, "value={value}");
            assert_eq!(
                unsafe { calls() },
                [
                    Call::Grow { size: 32, preserve: 0 },
                    Call::Format { size: 32, fmt_int: true, bits: value as u64 },
                    Call::ChangeEncoding { enc: SQLITE_UTF8 },
                ],
                "value={value}"
            );
            assert_eq!(unsafe { rendered() }, std::format!("{value}").into_bytes(), "value={value}");
            assert_eq!(mem.n as usize, unsafe { rendered() }.len(), "value={value}");
            assert_eq!(mem.enc, SQLITE_UTF8, "value={value}");
            assert_eq!(mem.flags, MEM_INT | MEM_STR | MEM_TERM, "value={value}");
        }
    }

    #[test]
    fn real_cells_render_through_15g_with_the_r_bits() {
        let _guards = bench();
        // All renderings must fit the 32-byte buffer the grow
        // guarantees, like the original's `%!.15g` ceiling.
        for bits in [
            0x0000_0000_0000_0000u64, // +0.0
            0x8000_0000_0000_0000,    // -0.0
            0x3ff0_0000_0000_0000,    // 1.0
            0xbff0_0000_0000_0000,    // -1.0
            0x4009_21fb_5444_2d18,    // pi
            0x4059_0000_0000_0000,    // 100.0
        ] {
            let mut mem = garbage_mem(MEM_REAL);
            mem.r = f64::from_bits(bits);
            unsafe { N_CALLS = 0 };
            let rc = unsafe { vdbe_mem_stringify(core::ptr::addr_of_mut!(mem).cast(), 2) };
            assert_eq!(rc, SQLITE_OK, "bits={bits:#018x}");
            assert_eq!(
                unsafe { calls() },
                [
                    Call::Grow { size: 32, preserve: 0 },
                    Call::Format { size: 32, fmt_int: false, bits },
                    Call::ChangeEncoding { enc: 2 },
                ],
                "bits={bits:#018x}"
            );
            assert_eq!(mem.n as usize, unsafe { rendered() }.len(), "bits={bits:#018x}");
            assert_eq!(mem.enc, SQLITE_UTF8, "bits={bits:#018x}");
            assert_eq!(mem.flags, MEM_REAL | MEM_STR | MEM_TERM, "bits={bits:#018x}");
        }
    }

    #[test]
    fn mem_int_wins_the_branch_when_both_type_bits_are_set() {
        let _guards = bench();
        let mut mem = garbage_mem(MEM_INT | MEM_REAL);
        mem.u = 7;
        let rc = unsafe { vdbe_mem_stringify(core::ptr::addr_of_mut!(mem).cast(), SQLITE_UTF8) };
        assert_eq!(rc, SQLITE_OK);
        assert!(matches!(
            unsafe { calls() }[1],
            Call::Format { fmt_int: true, bits: 7, .. }
        ));
    }

    #[test]
    fn grow_failure_returns_nomem_and_touches_nothing() {
        let _guards = bench();
        let mut mem = garbage_mem(MEM_INT);
        let before = Mem { ..mem };
        unsafe {
            GROW_RC = 1;
            N_CALLS = 0;
        }
        let rc = unsafe { vdbe_mem_stringify(core::ptr::addr_of_mut!(mem).cast(), SQLITE_UTF8) };
        assert_eq!(rc, SQLITE_NOMEM);
        assert_eq!(unsafe { calls() }, [Call::Grow { size: 32, preserve: 0 }]);
        assert_eq!(mem.u, before.u);
        assert_eq!(mem.r.to_bits(), before.r.to_bits());
        assert_eq!(mem.z, before.z);
        assert_eq!(mem.n, before.n);
        assert_eq!(mem.flags, before.flags);
        assert_eq!(mem.enc, before.enc);
    }

    #[test]
    fn enc_is_handed_to_the_recode_unmasked() {
        let _guards = bench();
        // SQLITE_UTF16_ALIGNED (0x8) must NOT be masked off here — the
        // original passes r7 through verbatim (`mov r1,r7`).
        for enc in [0u8, 1, 2, 3, 0x0a, 0xff] {
            let mut mem = garbage_mem(MEM_INT);
            mem.u = 1;
            unsafe { N_CALLS = 0 };
            let rc = unsafe { vdbe_mem_stringify(core::ptr::addr_of_mut!(mem).cast(), enc) };
            assert_eq!(rc, SQLITE_OK, "enc={enc}");
            assert_eq!(
                unsafe { calls() }.last().copied(),
                Some(Call::ChangeEncoding { enc }),
                "enc={enc}"
            );
            // The stamped encoding byte is UTF-8 regardless: the recode
            // is what rewrites it later.
            assert_eq!(mem.enc, SQLITE_UTF8, "enc={enc}");
        }
    }

    #[test]
    fn recode_return_code_is_discarded() {
        let _guards = bench();
        let mut mem = garbage_mem(MEM_INT);
        mem.u = 5;
        unsafe {
            RECODE_RC = SQLITE_NOMEM;
            N_CALLS = 0;
        }
        let rc = unsafe { vdbe_mem_stringify(core::ptr::addr_of_mut!(mem).cast(), SQLITE_UTF8) };
        assert_eq!(rc, SQLITE_OK, "the original keeps r6 = SQLITE_OK through the recode");
        assert_eq!(mem.flags, MEM_INT | MEM_STR | MEM_TERM);
    }

    #[test]
    fn final_flags_or_into_the_reloaded_value_not_the_snapshot() {
        let _guards = bench();
        let mut mem = garbage_mem(MEM_INT);
        mem.u = 3;
        unsafe {
            // The formatter mutating flags mid-flight must be visible
            // in the final `|= MEM_Str | MEM_Term`: the original
            // reloads flags after strlen (`ldrh r0,[r4,#0x1c]`).
            FORMATTER_FLAGS_WRITE = Some(0x0e00);
            N_CALLS = 0;
        }
        let rc = unsafe { vdbe_mem_stringify(core::ptr::addr_of_mut!(mem).cast(), SQLITE_UTF8) };
        assert_eq!(rc, SQLITE_OK);
        assert_eq!(mem.flags, 0x0e00 | MEM_STR | MEM_TERM);
    }

    #[test]
    fn the_branch_reads_the_flags_snapshot_taken_before_the_grow() {
        let _guards = bench();
        let mut mem = garbage_mem(MEM_INT);
        mem.u = 11;
        unsafe {
            // A grow that flips the cell to MEM_Real mid-flight must
            // not reroute the formatter: the original sampled r5 =
            // flags before the call (`ldrh r5,[r0,#0x1c]`).
            GROW_FLAGS_WRITE = Some(MEM_REAL);
            N_CALLS = 0;
        }
        let rc = unsafe { vdbe_mem_stringify(core::ptr::addr_of_mut!(mem).cast(), SQLITE_UTF8) };
        assert_eq!(rc, SQLITE_OK);
        assert!(matches!(
            unsafe { calls() }[1],
            Call::Format { fmt_int: true, bits: 11, .. }
        ));
    }

    #[test]
    fn attribute_flags_survive_the_render() {
        let _guards = bench();
        const MEM_ATTR: u16 = 0x0200;
        let mut mem = garbage_mem(MEM_INT | MEM_ATTR);
        mem.u = 3;
        let rc = unsafe { vdbe_mem_stringify(core::ptr::addr_of_mut!(mem).cast(), SQLITE_UTF8) };
        assert_eq!(rc, SQLITE_OK);
        assert_eq!(mem.flags, MEM_INT | MEM_ATTR | MEM_STR | MEM_TERM);
    }

    #[test]
    fn the_number_is_read_after_the_grow() {
        let _guards = bench();
        let mut mem = garbage_mem(MEM_INT);
        mem.u = 1;
        unsafe {
            GROW_U_WRITE = Some(99);
            N_CALLS = 0;
        }
        let rc = unsafe { vdbe_mem_stringify(core::ptr::addr_of_mut!(mem).cast(), SQLITE_UTF8) };
        assert_eq!(rc, SQLITE_OK);
        assert!(matches!(
            unsafe { calls() }[1],
            Call::Format { fmt_int: true, bits: 99, .. }
        ));
        assert_eq!(unsafe { rendered() }, b"99");
    }
}
