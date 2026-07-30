//! The extern release — how the VDBE releases a `Mem`'s external
//! resources (aggregate context or `xDel`-owned string) before the raw
//! `zMalloc` free.
//!
//! - `mem_extern_release` — original: `FUN_0838c074` @ 0x0838c074 (80
//!   bytes; 6 `bl` call sites: `mem_release` @ 0x0838c054, the row /
//!   column teardowns @ 0x083675fc, 0x08386fbc, 0x0838c2e0, 0x0838eeb4
//!   and the make-owned copy helper @ 0x0838bae0). Upstream SQLite's
//!   `vdbeMemClearExternAndSetNull` (this build's variant checks the
//!   aggregate flag first and tail-calls `mem_release`).
//!
//! Algorithm: the flags halfword at +0x1c is loaded once
//! (`ldrh r0,[r0,#0x1c]`). If bit 0x400 (`MEM_Agg`) is set, the
//! aggregate context is finalized — the FuncDef pointer at +0x00 goes
//! to the finalize helper @ 0x0838bc38 (`ldr r1,[r4,#0x0]; bl`,
//! upstream `sqlite3VdbeMemFinalize`, which invokes the user
//! `xFinalize`, frees the accumulation buffer and copies the finalized
//! result over the `Mem`) — and the function tail-calls `mem_release`
//! @ 0x0838c04c (`ldmia sp!,{r4,lr}; b`), which re-enters this
//! function on the finalized value and then frees `zMalloc`. Otherwise
//! bit 0x40 (`MEM_Dyn`) gates the `xDel` destructor at +0x20: when it
//! is also non-NULL it is `blx`'d on the string pointer at +0x14 and
//! `xDel` is NULLed; when either check fails the function returns
//! untouched (`ldmiaeq sp!,{r4,pc}`).
//!
//! `Mem` layout (the same `mem_release` documents, plus the FuncDef
//! pointer only this function reads):
//!
//! ```text
//! +0x00 u.pDef   aggregate FuncDef pointer (upstream Mem's union u)
//! +0x14 z        string/blob payload pointer
//! +0x1c flags    u16; bit 0x400 = aggregate context, bit 0x40 = has xDel
//! +0x20 xDel     external destructor for z
//! ```
//!
//! Deviations:
//! - The aggregate finalize @ 0x0838bc38 is NOT ported; it is the
//!   [`MEM_AGG_FINALIZE_OPS`] dispatch boundary (house pattern — see
//!   `sqlite/mem.rs`, `sqlite/value_free.rs`). Its default slot is a
//!   documented stub: it clears the `MEM_Agg` and `MEM_Dyn` flag bits
//!   and returns without invoking `xFinalize`. Termination of the
//!   aggregate branch relies on the finalize clearing `MEM_Agg` —
//!   exactly as the original relies on @ 0x0838bc38's 0x28-byte copy
//!   of the finalized result over the `Mem` (which lands flags = 1) —
//!   and a pure no-op default would recurse without bound. The stub's
//!   bit clear keeps the leak-rather-than-corrupt stance the
//!   `missing_extern_release` no-op held before this port: `zMalloc`
//!   is still freed by the tail-called `mem_release`, the external
//!   string at `z` is leaked, and no type-tagged destructor is ever
//!   guessed.
//! - `mem_release` @ 0x0838c04c IS ported
//!   ([`mem_release`](crate::sqlite::mem_release::mem_release)) and is
//!   tail-called directly, per the porting rules.
//! - This port is the shipped default `extern_release` slot of
//!   `mem_release`'s `MEM_EXTERN_OPS`, replacing the
//!   `missing_extern_release` no-op.

use crate::sqlite::mem_release::{
    mem_release, FLAGS_OFFSET, FLAG_AGG, FLAG_DYN, X_DEL_OFFSET, Z_OFFSET,
};

/// Byte offset of the aggregate FuncDef pointer (original:
/// `ldr r1,[r4,#0x0]`, upstream `Mem.u.pDef`).
pub const FUNC_DEF_OFFSET: usize = 0x00;

/// Indirect dispatch for the unported aggregate finalize @ 0x0838bc38
/// (kept behind the table so host tests can intercept it).
#[derive(Clone, Copy)]
pub struct MemAggFinalizeOps {
    /// The aggregate finalize @ 0x0838bc38: invoke the FuncDef's
    /// `xFinalize` on the context, free the accumulation buffer and
    /// copy the finalized result over the `Mem` (returning 1 on
    /// error). Upstream's `sqlite3VdbeMemFinalize`. NOT ported — the
    /// default is a documented stub (see the module header).
    pub agg_finalize: unsafe extern "C" fn(value: *mut u8, func_def: *mut u8) -> i32,
}

/// Default stub: skip the type-tagged `xFinalize` invocation; clear
/// the `MEM_Agg` and `MEM_Dyn` flag bits so the tail-called
/// `mem_release` terminates without running a destructor this stub
/// cannot identify (see the module header). Returns 0 (no error), as
/// the original does on its NULL-FuncDef early-out.
unsafe extern "C" fn missing_agg_finalize(value: *mut u8, _func_def: *mut u8) -> i32 {
    let flags = value.add(FLAGS_OFFSET) as *mut u16;
    // In-bounds: the caller just read the flags halfword at this offset.
    flags.write(flags.read() & !(FLAG_AGG | FLAG_DYN));
    0
}

/// Wired default: the one unported helper is a documented stub.
pub const DEFAULT_MEM_AGG_FINALIZE_OPS: MemAggFinalizeOps = MemAggFinalizeOps {
    agg_finalize: missing_agg_finalize,
};

/// The active aggregate finalize. Host tests install recording mocks;
/// the real port replaces the default when 0x0838bc38 lands.
pub static mut MEM_AGG_FINALIZE_OPS: MemAggFinalizeOps = DEFAULT_MEM_AGG_FINALIZE_OPS;

/// Reads the aggregate-finalize slot (volatile — the slot is meant to
/// be swapped at runtime, and a plain read lets LLVM const-fold the
/// default away).
#[inline(always)]
pub(crate) unsafe fn agg_finalize_op() -> unsafe extern "C" fn(*mut u8, *mut u8) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(MEM_AGG_FINALIZE_OPS.agg_finalize))
}

/// mem_extern_release — original: `FUN_0838c074` @ 0x0838c074 (80
/// bytes).
///
/// `vdbeMemClearExternAndSetNull`: release the value `value`'s
/// external resources. An aggregate context (flags bit [`FLAG_AGG`])
/// is finalized through the [`MEM_AGG_FINALIZE_OPS`] slot with the
/// FuncDef pointer at [`FUNC_DEF_OFFSET`] and the function tail-calls
/// `mem_release`; otherwise a `MEM_Dyn` value with a non-NULL `xDel`
/// has that destructor invoked on the string at [`Z_OFFSET`] and
/// `xDel` NULLed — the original's `tst 0x400 / bl / b 0x0838c04c` vs
/// `tst 0x40 / ldrne / cmpne / blx / str #0` body.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mem_extern_release(value: *mut u8) {
    let flags = (value.add(FLAGS_OFFSET) as *const u16).read();
    if flags & FLAG_AGG != 0 {
        let func_def = (value.add(FUNC_DEF_OFFSET) as *const *mut u8).read();
        (agg_finalize_op())(value, func_def);
        // Original: `b 0x0838c04c` — a tail call; the finalize has
        // cleared MEM_Agg, so the re-entry takes no branch.
        mem_release(value);
        return;
    }
    if flags & FLAG_DYN != 0 {
        let x_del = (value.add(X_DEL_OFFSET) as *const Option<unsafe extern "C" fn(*mut u8)>).read();
        if let Some(x_del) = x_del {
            let z = (value.add(Z_OFFSET) as *const *mut u8).read();
            x_del(z);
            (value.add(X_DEL_OFFSET) as *mut *mut u8).write(core::ptr::null_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use crate::sqlite::mem_release::{MemExternOps, MEM_EXTERN_OPS, Z_MALLOC_OFFSET};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the finalize / extern-release slots.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Every destructor/finalize/free the code under test triggered,
    /// in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        AggFinalize(usize, usize),
        XDel(usize),
        RawFree(usize, usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();

    /// Recording finalize that mimics the original's contract: it
    /// clears `MEM_Agg` (the original's result copy lands flags = 1).
    unsafe extern "C" fn recording_agg_finalize(value: *mut u8, func_def: *mut u8) -> i32 {
        (*core::ptr::addr_of_mut!(EVENTS))
            .push(Event::AggFinalize(value as usize, func_def as usize));
        let flags = value.add(FLAGS_OFFSET) as *mut u16;
        flags.write(flags.read() & !FLAG_AGG);
        0
    }

    unsafe extern "C" fn recording_x_del(z: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::XDel(z as usize));
    }

    unsafe extern "C" fn recording_heap_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::RawFree(ptr as usize, tag));
    }

    /// Installs the mock heap (first — the lock order `error_msg`'s
    /// tests establish), routes frees into the event log, and installs
    /// the recording finalize. The extern-release slot stays at its
    /// default — the ported function under test — so the tail-called
    /// `mem_release` re-enters it. The guards must stay alive for the
    /// whole test.
    fn bench() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let heap_guard = mock_heap();
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_AGG_FINALIZE_OPS),
                MemAggFinalizeOps {
                    agg_finalize: recording_agg_finalize,
                },
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_EXTERN_OPS),
                MemExternOps {
                    extern_release: mem_extern_release,
                },
            );
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_heap_free;
        }
        (heap_guard, ops_guard)
    }

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
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
        fn word(&self, offset: usize) -> *mut u8 {
            unsafe { (self.0.as_ptr().add(offset) as *const *mut u8).read() }
        }
        fn set_flags(&mut self, flags: u16) {
            // In-bounds: flags at 0x1c, block is 0x30.
            unsafe { (self.ptr().add(FLAGS_OFFSET) as *mut u16).write(flags) };
        }
    }

    #[test]
    fn a_static_value_is_returned_untouched() {
        let _guards = bench();
        let mut value = Mem::new();
        let z = 0x0bad_beefusize as *mut u8;
        let x_del = 0x0bad_d00dusize as *mut u8;
        value.set_word(Z_OFFSET, z);
        value.set_word(X_DEL_OFFSET, x_del);
        // flags == 0: neither branch runs (`ldmiaeq sp!,{r4,pc}`).

        unsafe { mem_extern_release(value.ptr()) };

        assert!(events().is_empty(), "no finalize, no xDel, no free");
        assert_eq!(value.word(Z_OFFSET), z, "z untouched");
        assert_eq!(value.word(X_DEL_OFFSET), x_del, "xDel untouched");
    }

    #[test]
    fn a_dyn_value_invokes_x_del_on_z_and_nulls_x_del() {
        let _guards = bench();
        let mut value = Mem::new();
        let z = 0x0bad_beefusize as *mut u8;
        value.set_word(Z_OFFSET, z);
        value.set_word(
            X_DEL_OFFSET,
            recording_x_del as unsafe extern "C" fn(*mut u8) as *mut u8,
        );
        value.set_flags(FLAG_DYN);

        unsafe { mem_extern_release(value.ptr()) };

        assert_eq!(
            events(),
            std::vec![Event::XDel(z as usize)],
            "xDel blx'd with z in r0 — the original's ldr r0,[r4,#0x14]; blx r1"
        );
        assert!(
            value.word(X_DEL_OFFSET).is_null(),
            "xDel NULLed after the call"
        );
        assert_eq!(value.word(Z_OFFSET), z, "z is NOT nulled here — mem_release's job");
    }

    #[test]
    fn a_dyn_value_with_null_x_del_returns_untouched() {
        let _guards = bench();
        let mut value = Mem::new();
        let z = 0x0bad_beefusize as *mut u8;
        value.set_word(Z_OFFSET, z);
        value.set_flags(FLAG_DYN);
        // xDel left NULL: the original's cmpne r1,#0 / ldmiaeq early-out.

        unsafe { mem_extern_release(value.ptr()) };

        assert!(events().is_empty(), "no destructor runs on a NULL xDel");
        assert_eq!(value.word(Z_OFFSET), z, "z untouched");
    }

    #[test]
    fn an_agg_value_is_finalized_then_tail_calls_mem_release() {
        let _guards = bench();
        let mut value = Mem::new();
        let mut z_malloc_block = TrackedBlock::new();
        let z_malloc_raw = z_malloc_block.raw();
        let func_def = 0x0bad_f00dusize as *mut u8;
        value.set_word(FUNC_DEF_OFFSET, func_def);
        value.set_word(Z_OFFSET, 0x0bad_beefusize as *mut u8);
        value.set_word(Z_MALLOC_OFFSET, z_malloc_block.payload());
        value.set_flags(FLAG_AGG);

        let value_ptr = value.ptr();
        unsafe { mem_extern_release(value_ptr) };

        assert_eq!(
            events(),
            std::vec![
                Event::AggFinalize(value_ptr as usize, func_def as usize),
                Event::RawFree(z_malloc_raw as usize, TAG_TRACKED),
            ],
            "finalize with the FuncDef at +0x00, then the tail-called \
             mem_release frees zMalloc — the original's bl; b 0x0838c04c"
        );
        assert!(value.word(Z_OFFSET).is_null(), "z NULLed by the tail call");
        assert!(value.word(Z_MALLOC_OFFSET).is_null(), "zMalloc NULLed");
        assert!(value.word(X_DEL_OFFSET).is_null(), "xDel NULLed");
    }

    #[test]
    fn the_default_extern_release_slot_is_this_function() {
        use crate::sqlite::mem_release::DEFAULT_MEM_EXTERN_OPS;
        assert_eq!(
            DEFAULT_MEM_EXTERN_OPS.extern_release as usize,
            mem_extern_release as usize,
            "mem_release's extern release is the ported function by default"
        );
    }

    #[test]
    fn the_default_finalize_stub_clears_the_extern_bits_and_leaks() {
        // With the shipped defaults (ported extern release + stub
        // finalize), a value claiming both an aggregate context and an
        // xDel destructor — with a garbage xDel — is still torn down
        // safely: no destructor runs, the bits are cleared, zMalloc is
        // freed and the three fields are NULLed by the tail-called
        // mem_release. Leak the external string, never corrupt.
        let _heap_guard = mock_heap();
        let _ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_AGG_FINALIZE_OPS),
                DEFAULT_MEM_AGG_FINALIZE_OPS,
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_EXTERN_OPS),
                crate::sqlite::mem_release::DEFAULT_MEM_EXTERN_OPS,
            );
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_heap_free;
            (*core::ptr::addr_of_mut!(EVENTS)).clear();

            let mut value = Mem::new();
            let mut z_malloc_block = TrackedBlock::new();
            let z_malloc_raw = z_malloc_block.raw();
            value.set_word(FUNC_DEF_OFFSET, 0x0bad_f00dusize as *mut u8);
            value.set_word(Z_OFFSET, 0x0bad_beefusize as *mut u8);
            value.set_word(X_DEL_OFFSET, 0x0bad_d00dusize as *mut u8);
            value.set_word(Z_MALLOC_OFFSET, z_malloc_block.payload());
            value.set_flags(FLAG_AGG | FLAG_DYN);

            mem_extern_release(value.ptr());

            assert_eq!(
                events(),
                std::vec![Event::RawFree(z_malloc_raw as usize, TAG_TRACKED)],
                "the garbage xDel never runs; zMalloc is still freed"
            );
            assert!(value.word(X_DEL_OFFSET).is_null(), "xDel NULLed by mem_release");
        }
    }
}
