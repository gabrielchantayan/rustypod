//! The function-context aux-record sweep — how the VDBE destroys the
//! per-argument destructor records hanging off a function context.
//!
//! - `vdbe_context_aux_sweep` — original: `FUN_08386e08` @ 0x08386e08
//!   (100 bytes; 2 `bl` call sites: `vdbe_free_p4` @ 0x082cf3f4 with
//!   mask 0, and the statement-exec path @ 0x08387b00 with a live mask;
//!   Ghidra's C additionally attributes it to `vdbe_change_p4`'s -7
//!   branch, which shares the same two machine-code sites). Upstream
//!   SQLite's `sqlite3VdbeDeleteAuxData` loop, here freestanding over a
//!   context's record array.
//!
//! The context layout this walks:
//!
//! ```text
//! +0   owner (the FuncDef pointer) — never touched by the sweep
//! +4   count (i32, signed bound)   — number of records
//! +8   record[0]  { arg: *mut, destructor: fn(*mut) }   8 bytes each
//! +16  record[1]  ...
//! ```
//!
//! Algorithm (original: `r4` is the record index, `r7` the mask, `r6`
//! the context, `r5` the record's arg slot): for each index from 0
//! while strictly below the signed count, the slot is *exempt* when the
//! index is at most 31 and the mask has that bit set (`cmp r4,#0x1f;
//! bgt` / `tst r7,r8, lsl r4` — indices past 31 cannot be exempted).
//! A non-exempt slot with a non-NULL arg is destroyed: the destructor
//! word is loaded and, when non-NULL, `blx`'d with the arg in `r0`
//! (Ghidra renders this `(*pcVar2)()`; the argument is the arg loaded
//! two instructions earlier), then the arg slot is zeroed (`str
//! r9,[r5]`). A NULL arg is skipped entirely — its destructor word is
//! never even loaded.
//!
//! Deviations: none. The record is modeled as a typed struct, so the
//! pointer fields widen on a 64-bit host (asserts below pin the 32-bit
//! layout); the target codegen keeps the original's +4/+8 offsets.

/// One (arg, destructor) record of the context's aux array (original:
/// 8 bytes at `ctx + 8 + index*8`).
#[repr(C)]
struct AuxRecord {
    /// +0: the destructor's argument; zeroed once destroyed.
    arg: *mut u8,
    /// +4: the destructor, called as `destructor(arg)` when set.
    destructor: Option<unsafe extern "C" fn(arg: *mut u8)>,
}

/// The context header the sweep reads (original: owner at +0, record
/// count at +4, records from +8).
#[repr(C)]
struct AuxRecordArray {
    /// +0: the owning FuncDef; the sweep never touches it.
    owner: *mut u8,
    /// +4: number of records (signed loop bound).
    count: i32,
}

// The original's byte offsets, asserted on the 32-bit target (see the
// module header — on a 64-bit host the pointer fields widen and all
// access goes through the typed structs).
#[cfg(target_pointer_width = "32")]
const _ARRAY_HEADER_SIZE: [u8; 8] = [0; core::mem::size_of::<AuxRecordArray>()];
#[cfg(target_pointer_width = "32")]
const _COUNT_OFFSET: [u8; 4] = [0; core::mem::offset_of!(AuxRecordArray, count)];
#[cfg(target_pointer_width = "32")]
const _RECORD_SIZE: [u8; 8] = [0; core::mem::size_of::<AuxRecord>()];
#[cfg(target_pointer_width = "32")]
const _DESTRUCTOR_OFFSET: [u8; 4] = [0; core::mem::offset_of!(AuxRecord, destructor)];

/// vdbe_context_aux_sweep — original: `FUN_08386e08` @ 0x08386e08
/// (100 bytes; 2 `bl` call sites).
///
/// Walk the context's aux-record array: every record whose index is not
/// exempted by `exempt_mask` (only indices 0..=31 can be exempted) and
/// whose arg is non-NULL has its destructor — when set — called with
/// the arg, after which the arg slot is zeroed. Exempt slots and
/// already-NULL slots are left exactly as found.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_context_aux_sweep(ctx: *mut u8, exempt_mask: i32) {
    let array = ctx as *mut AuxRecordArray;
    let records = array.add(1) as *mut AuxRecord;
    let mut index = 0i32;
    // Volatile: the original reloads the count every iteration (`ldr
    // r0,[r6,#4]` inside the loop), so a destructor that mutates it
    // mid-sweep is honored exactly; a plain read lets LLVM hoist it.
    while index < core::ptr::read_volatile(core::ptr::addr_of!((*array).count)) {
        let record = &mut *records.add(index as usize);
        // Original: `cmp r4,#0x1f; bgt` skips the mask test entirely
        // past index 31 — the shift `r8, lsl r4` is only ever 0..=31.
        if (index > 31 || (exempt_mask as u32) & (1u32 << index) == 0)
            && !record.arg.is_null()
        {
            if let Some(destructor) = record.destructor {
                destructor(record.arg);
            }
            record.arg = core::ptr::null_mut();
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests — the recorder is a shared global.
    static SWEEP_LOCK: Mutex<()> = Mutex::new(());

    /// Args handed to the recording destructor, in call order.
    static mut CALLS: Vec<usize> = Vec::new();

    unsafe extern "C" fn recording_destructor(arg: *mut u8) {
        (*core::ptr::addr_of_mut!(CALLS)).push(arg as usize);
    }

    /// Fixture with the firmware layout: header, then records (on a
    /// 64-bit host the typed structs widen; the code under test reaches
    /// the records through the same struct math).
    #[repr(C)]
    struct Fixture<const N: usize> {
        array: AuxRecordArray,
        records: [AuxRecord; N],
    }

    impl<const N: usize> Fixture<N> {
        fn new(count: i32) -> Self {
            Fixture {
                array: AuxRecordArray {
                    owner: 0x1111_0000 as *mut u8,
                    count,
                },
                records: [const { AuxRecord { arg: core::ptr::null_mut(), destructor: None } }; N],
            }
        }
        fn live(&mut self, index: usize, arg: usize) {
            self.records[index].arg = arg as *mut u8;
            self.records[index].destructor = Some(recording_destructor);
        }
        fn arg(&self, index: usize) -> *mut u8 {
            self.records[index].arg
        }
    }

    fn bench() -> MutexGuard<'static, ()> {
        let guard = SWEEP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { (*core::ptr::addr_of_mut!(CALLS)).clear() };
        guard
    }

    fn calls() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    #[test]
    fn a_non_positive_count_sweeps_nothing() {
        let _guard = bench();
        for count in [0i32, -1, i32::MIN] {
            let mut fixture = Fixture::<2>::new(count);
            fixture.live(0, 0xa001);
            fixture.live(1, 0xa002);
            unsafe {
                vdbe_context_aux_sweep(&mut fixture.array as *mut _ as *mut u8, 0)
            };
            assert!(calls().is_empty(), "count {count} runs no destructor");
            assert_eq!(fixture.arg(0), 0xa001 as *mut u8);
            assert_eq!(fixture.arg(1), 0xa002 as *mut u8);
        }
    }

    #[test]
    fn mask_zero_destroys_every_live_slot_and_clears_it() {
        let _guard = bench();
        let mut fixture = Fixture::<3>::new(3);
        fixture.live(0, 0xb001);
        // A live arg with no destructor: cleared, but nothing is called.
        fixture.records[1].arg = 0xb002 as *mut u8;
        // A NULL arg with a destructor: skipped without loading the fn.
        fixture.records[2].destructor = Some(recording_destructor);

        unsafe { vdbe_context_aux_sweep(&mut fixture.array as *mut _ as *mut u8, 0) };
        assert_eq!(calls(), std::vec![0xb001], "only the destructor slot with a live arg fires");
        assert!(fixture.arg(0).is_null(), "destroyed slot is zeroed");
        assert!(fixture.arg(1).is_null(), "destructor-less live slot is still zeroed");
        assert!(fixture.arg(2).is_null(), "the already-NULL slot stays NULL");
    }

    #[test]
    fn mask_bits_exempt_slots_zero_through_31() {
        let _guard = bench();
        let mut fixture = Fixture::<5>::new(5);
        for (index, arg) in [0xc010, 0xc011, 0xc012, 0xc013, 0xc014].iter().enumerate() {
            fixture.live(index, *arg);
        }
        // Exempt slots 1 and 3.
        let mask = (1i32 << 1) | (1i32 << 3);
        unsafe { vdbe_context_aux_sweep(&mut fixture.array as *mut _ as *mut u8, mask) };
        assert_eq!(calls(), std::vec![0xc010, 0xc012, 0xc014]);
        assert!(fixture.arg(0).is_null());
        assert_eq!(fixture.arg(1), 0xc011 as *mut u8, "exempt slot keeps its arg");
        assert!(fixture.arg(2).is_null());
        assert_eq!(fixture.arg(3), 0xc013 as *mut u8, "exempt slot keeps its arg");
        assert!(fixture.arg(4).is_null());
    }

    #[test]
    fn slots_at_and_past_32_cannot_be_exempted() {
        let _guard = bench();
        let mut fixture = Fixture::<34>::new(34);
        for index in 0..34 {
            fixture.live(index, 0xd000 + index);
        }
        // Every mask bit set: indices 0..=31 survive, 32 and 33 burn.
        unsafe { vdbe_context_aux_sweep(&mut fixture.array as *mut _ as *mut u8, -1) };
        assert_eq!(calls(), std::vec![0xd000 + 32, 0xd000 + 33]);
        assert_eq!(fixture.arg(31), 0xd01f as *mut u8);
        assert!(fixture.arg(32).is_null());
        assert!(fixture.arg(33).is_null());
    }

    #[test]
    fn the_destructor_sees_the_arg_before_the_slot_is_cleared() {
        let _guard = bench();
        /// Slot the probe inspects while the destructor runs.
        static mut PROBE_SLOT: *mut *mut u8 = core::ptr::null_mut();
        static mut SEEN: usize = 0;
        unsafe extern "C" fn probing_destructor(arg: *mut u8) {
            let slot = *core::ptr::addr_of!(PROBE_SLOT);
            // The arg slot must still hold the arg at call time — the
            // original zeroes it only after the `blx` returns.
            assert_eq!(slot.read(), arg, "slot cleared before the destructor ran");
            (*core::ptr::addr_of_mut!(SEEN)) = arg as usize;
        }
        let mut fixture = Fixture::<1>::new(1);
        fixture.records[0].arg = 0xe001 as *mut u8;
        fixture.records[0].destructor = Some(probing_destructor);
        unsafe {
            (*core::ptr::addr_of_mut!(PROBE_SLOT)) = &mut fixture.records[0].arg;
            vdbe_context_aux_sweep(&mut fixture.array as *mut _ as *mut u8, 0);
            assert_eq!(*core::ptr::addr_of!(SEEN), 0xe001);
        }
        assert!(fixture.arg(0).is_null());
    }

    #[test]
    fn records_beyond_the_count_are_untouched() {
        let _guard = bench();
        let mut fixture = Fixture::<4>::new(2);
        for index in 0..4 {
            fixture.live(index, 0xf000 + index);
        }
        unsafe { vdbe_context_aux_sweep(&mut fixture.array as *mut _ as *mut u8, 0) };
        assert_eq!(calls(), std::vec![0xf000, 0xf001]);
        assert_eq!(fixture.arg(2), 0xf002 as *mut u8);
        assert_eq!(fixture.arg(3), 0xf003 as *mut u8);
    }
}
