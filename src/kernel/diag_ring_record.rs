//! Appending one event to the calling task's diagnostic ring buffer —
//! the firmware-wide "record a diagnostic triple plus two data words"
//! primitive behind every `0x22/0x6f/...`-style trace call.
//!
//! - `diag_ring_record` — original: `FUN_08049a84` @ 0x08049a84 (212
//!   bytes, 0x08049a84..0x08049b58, no literal pool; the next function
//!   starts at 0x08049b58). **197 `bl` call sites**, binary-scanned over
//!   the whole decrypted image — every one an unconditional `bl`, none
//!   predicated: no caller NULL-guards or gates this function, which is
//!   what you expect for a logger that is always safe to call. Among the
//!   callers: the traced allocator's failure path (the `(0x22, 0x6f,
//!   0x41)` triple recorded by `sqlite::blob_to_hex`) and the storage
//!   layer's error reporters.
//!
//! The per-task record block (332 bytes) is created and found by
//! `FUN_080498f8` @ 0x080498f8 — get-or-create under the task-table
//! lock, keyed by task id. Its layout, decoded from this function and
//! from the reset routine @ 0x08049694 and consumed by the formatter @
//! 0x080496f0:
//!
//! ```text
//! +0x000  owner task id            (written by 0x080498f8)
//! +0x004  tags[16]                 packed facility/subsystem/code words
//! +0x044  pointers[16]             optional heap blocks owned by a slot
//! +0x084  flags[16]                bit 0 = pointers[i] must be freed
//! +0x0c4  data0[16]                raw fourth argument
//! +0x104  data1[16]                raw fifth argument (reset fills -1)
//! +0x144  head                     next slot to write
//! +0x148  tail                     oldest live slot
//! ```
//!
//! Five parallel arrays of 16 words each — column-major, not an array
//! of structs: every field access in the original is
//! `block + index*4 + <field base>`, with field bases 0x40 apart.
//!
//! Algorithm (the original's exact store order):
//!
//! 1. `head = (head + 1) % 16`. The modulo is signed C `%`, compiled to
//!    the branchless `asr/bic/sub` idiom; indices only ever hold 0..15,
//!    so it is plain wraparound in practice.
//! 2. If `head == tail` the ring was full: `tail = (tail + 1) % 16`,
//!    dropping the oldest entry.
//! 3. Pack the first three arguments into one tag word,
//!    `facility << 24 | (subsystem & ~0xff000) << 12 | code & 0xfff`
//!    (`bic r2,r6,#0xff000` + `orr r2,r2,lsl #12`: bits 12..19 of the
//!    subsystem are stripped; everything at bit 20 and above falls off
//!    the 32-bit shift), and store it in `tags[head]`.
//! 4. Store arguments four and five verbatim in `data0[head]` and
//!    `data1[head]`.
//! 5. If `pointers[head] != NULL` **and** `flags[head] & 1`, release the
//!    stale block through `traced_free` @ 0x08043994 and clear
//!    `pointers[head]`. This is the slot-reuse hazard: the pointer being
//!    freed belongs to the record that occupied the slot 16 writes ago,
//!    and the new tag/data are already stored when the free runs.
//! 6. Clear `flags[head]` for the new occupant.
//!
//! Note the first record lands in slot **1**: `head` starts at 0 after
//! reset and is advanced before use, so slot 0 stays empty until the
//! first full wraparound. Reproduced, not fixed.
//!
//! Deviations:
//!
//! - The block getter 0x080498f8 is unported, so it sits behind the
//!   [`DIAG_RING_BLOCK_GETTER`] seam. Its default is a documented no-op
//!   (the original's getter never returns NULL — it allocates or finds
//!   — so there is no faithful NULL behavior to inherit); on target,
//!   hooks.yaml wires the real getter once that function is ported.
//! - [`traced_free`] is ported and is called directly, as in the
//!   original (`bl 0x08043994`; Ghidra's C drops its argument — r0
//!   still holds the stale pointer loaded from `[r1,#0x44]`).
//! - The original reloads `head` from memory before every store; the
//!   port keeps those five separate reads rather than caching the index,
//!   so the instruction structure (and the store-before-free order) is
//!   preserved.
//! - Slot addressing is raw pointer arithmetic (`block + idx*4 + base`),
//!   not bounds-checked indexing: the original has no checks, and with
//!   them LLVM emits an abort path a corrupt `head` could reach that
//!   the firmware does not have.

use crate::drivers::ata_cmd::traced_free;

/// Ring capacity: 16 slots per task, decoded from both the `% 0x10`
/// wraparound here and the reset loop bound `cmp r0,#16` @ 0x08049770.
pub const RING_CAPACITY: usize = 16;

/// Byte size of one record block: owner word + five 16-word arrays +
/// head + tail = 332 (the size `0x080498f8` requests from
/// `traced_alloc`, `mov r0,#332` @ 0x08049934).
pub const DIAG_RING_BLOCK_SIZE: usize = 332;

/// One task's diagnostic ring buffer, exactly as laid out above. Every
/// field is a 32-bit word: `pointers` holds *target* addresses as u32
/// (the original frees them by loading the word straight into r0), so
/// the struct is 332 bytes on both the ARM target and any host — never
/// model these as real Rust pointers, which would be 8 bytes apart on
/// the host and silently overlap the arrays.
#[repr(C)]
pub struct DiagEventRing {
    /// +0x000: owner task id, stamped by 0x080498f8.
    pub owner: u32,
    /// +0x004: packed `facility<<24 | subsystem<<12 | code` per slot.
    pub tags: [u32; RING_CAPACITY],
    /// +0x044: u32 target address of an owned heap block, or 0.
    pub pointers: [u32; RING_CAPACITY],
    /// +0x084: per-slot flags; bit 0 = [`DiagEventRing::pointers`] entry
    /// must be released through `traced_free` on slot reuse.
    pub flags: [u32; RING_CAPACITY],
    /// +0x0c4: fourth argument, verbatim.
    pub data0: [u32; RING_CAPACITY],
    /// +0x104: fifth argument, verbatim (the reset routine pre-fills
    /// -1; this function only ever writes them).
    pub data1: [u32; RING_CAPACITY],
    /// +0x144: write cursor, always 0..15 through this function.
    pub head: i32,
    /// +0x148: read cursor of the consumer (0x080496f0's family).
    pub tail: i32,
}

/// The one unported service `diag_ring_record` reaches: the per-task
/// block getter `FUN_080498f8` @ 0x080498f8, which returns the calling
/// task's [`DiagEventRing`], allocating and registering it on first
/// use. It never returns NULL.
pub type BlockGetter = unsafe extern "C" fn() -> *mut DiagEventRing;

/// Active model of the block getter. `None` (the shipped default while
/// 0x080498f8 is unported) makes [`diag_ring_record`] a documented
/// no-op: without a ring there is nothing to append to, and the
/// function has no return value any caller inspects.
pub static mut DIAG_RING_BLOCK_GETTER: Option<BlockGetter> = None;

/// Reads the hook slot. Volatile so LLVM cannot constant-fold the load
/// to the `None` default (the house pattern — `cxx/string_object.rs`).
#[inline(always)]
fn block_getter() -> Option<BlockGetter> {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DIAG_RING_BLOCK_GETTER)) }
}

/// diag_ring_record — original: `FUN_08049a84` @ 0x08049a84 (212
/// bytes; 197 unconditional `bl` call sites).
///
/// Appends one event to the calling task's diagnostic ring: packs
/// `facility`, `subsystem` and `code` into the slot's tag word, stores
/// `data0`/`data1` beside it, releases the reused slot's flagged stale
/// pointer through [`traced_free`], and clears the slot flags. Advances
/// `head` with wraparound at 16; when the ring is full, advances `tail`
/// too, dropping the oldest record. No return value.
///
/// With [`DIAG_RING_BLOCK_GETTER`] unset (or returning NULL) this is a
/// no-op — see the module deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn diag_ring_record(
    facility: u32,
    subsystem: u32,
    code: u32,
    data0: u32,
    data1: u32,
) {
    let Some(getter) = block_getter() else { return };
    let block = getter();
    if block.is_null() {
        return;
    }

    // head = (head + 1) % 16 — signed C `%`, the branchless
    // asr/bic/sub idiom; indices only ever hold 0..15.
    let head = ((*block).head.wrapping_add(1)) % 16;
    (*block).head = head;

    // Full ring: the write lands on the oldest live slot, so the
    // read cursor follows, dropping it.
    if head == (*block).tail {
        let tail = ((*block).tail.wrapping_add(1)) % 16;
        (*block).tail = tail;
    }

    // Pack the tag: strip the subsystem's bits 12..19 (`bic #0xff000`)
    // and shift it up; bits at 20+ fall off the 32-bit shift, leaving
    // exactly its low 12 bits at 12..23.
    let tag = (facility << 24) | ((subsystem & !0x00ff_0000) << 12) | (code & 0xfff);

    // Slot addressing is the original's `add r1, r4, r1, lsl #2 ;
    // str ..., [r1, #<field base>]` — raw, unchecked: a corrupt head
    // writes out of range exactly as on device, rather than aborting.
    let tags = core::ptr::addr_of_mut!((*block).tags).cast::<u32>();
    let pointers = core::ptr::addr_of_mut!((*block).pointers).cast::<u32>();
    let flags = core::ptr::addr_of_mut!((*block).flags).cast::<u32>();
    let data0_slots = core::ptr::addr_of_mut!((*block).data0).cast::<u32>();
    let data1_slots = core::ptr::addr_of_mut!((*block).data1).cast::<u32>();

    // The original reloads head before every store; kept verbatim.
    *tags.add((*block).head as usize) = tag;
    *data0_slots.add((*block).head as usize) = data0;
    *data1_slots.add((*block).head as usize) = data1;

    // Slot reuse: free the previous occupant's block if it owned one.
    let stale = *pointers.add((*block).head as usize);
    if stale != 0 && ((*flags.add((*block).head as usize)) & 1) != 0 {
        traced_free(stale as usize as *mut u8);
        // Reloaded after the free returns, as in the original.
        *pointers.add((*block).head as usize) = 0;
    }
    *flags.add((*block).head as usize) = 0;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::TRACED_FREE_HOOKS;
    use crate::testing::{DIAG_RING_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Stale-pointer word planted in a slot, recognizable as a target
    /// address. Never dereferenced by anything — the mock free only
    /// records it.
    const MARKER: u32 = 0x0812_3450;

    /// Blocks the mock free saw, as u32 words round-tripped back from
    /// the pointer argument.
    static FREED: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    /// The fixture block handed out by the mock getter.
    static mut FIXTURE_BLOCK: *mut DiagEventRing = core::ptr::null_mut();

    unsafe extern "C" fn mock_free(block: *mut u8) {
        FREED.lock().unwrap().push(block as usize as u32);
    }

    /// Mock getter: returns the fixture block, like 0x080498f8's
    /// find-existing path (it never returns NULL).
    unsafe extern "C" fn mock_getter() -> *mut DiagEventRing {
        FIXTURE_BLOCK
    }

    /// Getter returning NULL — not a state the original can produce,
    /// pinned here so the documented no-op stays deliberate.
    unsafe extern "C" fn null_getter() -> *mut DiagEventRing {
        core::ptr::null_mut()
    }

    /// Installs the mock getter + mock free over a fresh zeroed block
    /// (the reset state: head = tail = 0) and restores the shipped
    /// defaults on drop. Holds both crate-wide locks the test touches,
    /// so parallel suite threads never race the hook tables.
    struct Fixture {
        _ring_guard: MutexGuard<'static, ()>,
        _alloc_guard: MutexGuard<'static, ()>,
        /// The free slot's value before the mock, restored on drop
        /// (the default stub is private to `drivers::ata_cmd`).
        saved_free: unsafe extern "C" fn(*mut u8),
    }

    impl Fixture {
        fn new() -> Self {
            let ring_guard = DIAG_RING_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let alloc_guard =
                TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            FREED.lock().unwrap().clear();
            let (block, saved_free) = unsafe {
                let block = Box::leak(Box::new(core::mem::zeroed::<DiagEventRing>()));
                FIXTURE_BLOCK = block;
                (*core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER)) = Some(mock_getter);
                let saved_free = (*core::ptr::addr_of!(TRACED_FREE_HOOKS)).free;
                (*core::ptr::addr_of_mut!(TRACED_FREE_HOOKS)).free = mock_free;
                (*core::ptr::addr_of_mut!(TRACED_FREE_HOOKS)).trace = None;
                (block, saved_free)
            };
            Fixture { _ring_guard: ring_guard, _alloc_guard: alloc_guard, saved_free }
        }

        fn block(&self) -> &DiagEventRing {
            unsafe { &*FIXTURE_BLOCK }
        }

        fn freed(&self) -> Vec<u32> {
            FREED.lock().unwrap().clone()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER)) = None;
                (*core::ptr::addr_of_mut!(TRACED_FREE_HOOKS)).free = self.saved_free;
                FIXTURE_BLOCK = core::ptr::null_mut();
            }
        }
    }

    /// Drives `n` appends of a distinct, decodable event each.
    fn push_n(n: u32) {
        for i in 0..n {
            unsafe {
                diag_ring_record(0x10 + i, 0x200 + i, 0x300 + i, 0x1000 + i, !i);
            }
        }
    }

    #[test]
    fn block_layout_matches_the_firmware_object() {
        // Field bases 0x40 apart, head/tail at 0x144/0x148, total 332 —
        // the sizes 0x080498f8 allocates and the offsets every member
        // of the family loads. A repr(C) drift here would corrupt the
        // neighbor arrays silently.
        assert_eq!(core::mem::size_of::<DiagEventRing>(), DIAG_RING_BLOCK_SIZE);
        assert_eq!(core::mem::size_of::<DiagEventRing>(), 332);
        assert_eq!(
            core::mem::offset_of!(DiagEventRing, tags),
            0x004,
        );
        assert_eq!(core::mem::offset_of!(DiagEventRing, pointers), 0x044);
        assert_eq!(core::mem::offset_of!(DiagEventRing, flags), 0x084);
        assert_eq!(core::mem::offset_of!(DiagEventRing, data0), 0x0c4);
        assert_eq!(core::mem::offset_of!(DiagEventRing, data1), 0x104);
        assert_eq!(core::mem::offset_of!(DiagEventRing, head), 0x144);
        assert_eq!(core::mem::offset_of!(DiagEventRing, tail), 0x148);
    }

    #[test]
    fn first_record_lands_in_slot_one_leaving_slot_zero_empty() {
        // head starts at 0 and is advanced BEFORE use: the first event
        // occupies slot 1, and slot 0 stays untouched until the first
        // full wraparound. Faithful quirk, not an off-by-one.
        let fixture = Fixture::new();
        unsafe {
            diag_ring_record(0xab, 0xcd, 0xef, 0x1234, 0x5678);
        }
        let block = fixture.block();
        assert_eq!(block.head, 1);
        assert_eq!(block.tail, 0, "not full yet");
        assert_eq!(block.tags[0], 0, "slot 0 skipped");
        assert_eq!(block.data0[0], 0);
        assert_eq!(block.data1[0], 0);
        assert_eq!(block.tags[1], 0xab << 24 | 0xcd << 12 | 0xef);
        assert_eq!(block.data0[1], 0x1234);
        assert_eq!(block.data1[1], 0x5678);
        assert!(fixture.freed().is_empty());
    }

    #[test]
    fn packs_facility_subsystem_code_with_the_original_masks() {
        let fixture = Fixture::new();
        // Plain values: 0x12456789.
        unsafe { diag_ring_record(0x12, 0x3456, 0x789, 0, 0) };
        // Maxima: 0xffffffff.
        unsafe { diag_ring_record(0xff, 0xfff, 0xfff, 0, 0) };
        // Facility keeps only its low byte (shifted off): 0.
        unsafe { diag_ring_record(0x100, 0, 0, 0, 0) };
        // Subsystem bits 12..19 stripped BEFORE the shift (`bic
        // #0xff000`): 0x12345678 & ~0xff000 = 0x12300678, whose low
        // word << 12 truncates to 0x00678000. Code keeps its low 12
        // bits: 0xfff.
        unsafe { diag_ring_record(0, 0x1234_5678, 0x1fff, 0, 0) };
        let tags = &fixture.block().tags;
        // 0x3456 loses bit 12 to the mask (it sits inside 0xff000):
        // contributes 0x2456 << 12, so the facility byte ORs nothing.
        assert_eq!(tags[1], 0x1245_6789 | 0x0100_0000);
        assert_eq!(tags[1], 0x1345_6789);
        assert_eq!(tags[2], 0xffff_ffff);
        assert_eq!(tags[3], 0);
        assert_eq!(tags[4], 0x0567_8fff);
    }

    #[test]
    fn data_words_are_stored_verbatim_in_their_parallel_arrays() {
        let fixture = Fixture::new();
        unsafe { diag_ring_record(1, 2, 3, 0xdead_beef, 0xffff_ffff) };
        unsafe { diag_ring_record(1, 2, 4, 0, 0) };
        let block = fixture.block();
        assert_eq!(block.data0[1], 0xdead_beef);
        assert_eq!(block.data1[1], 0xffff_ffff);
        assert_eq!(block.data0[2], 0);
        assert_eq!(block.data1[2], 0);
    }

    #[test]
    fn head_wraps_mod_sixteen_and_tail_drops_the_oldest_when_full() {
        let fixture = Fixture::new();
        push_n(15);
        let block = fixture.block();
        assert_eq!(block.head, 15, "slots 1..=15 filled");
        assert_eq!(block.tail, 0);

        // 16th append wraps head to 0 == tail: the ring is full, tail
        // follows to 1, dropping the record in slot 1.
        unsafe { diag_ring_record(0x21, 0x22, 0x23, 0x24, 0x25) };
        assert_eq!(block.head, 0);
        assert_eq!(block.tail, 1);
        assert_eq!(block.tags[0], 0x21 << 24 | 0x22 << 12 | 0x23);

        // 17th append lands on slot 1 == tail again: tail follows once
        // more. Slot 0 — written by the 16th — is now the oldest.
        unsafe { diag_ring_record(0x31, 0x32, 0x33, 0x34, 0x35) };
        assert_eq!(block.head, 1);
        assert_eq!(block.tail, 2);
        assert_eq!(block.tags[1], 0x31 << 24 | 0x32 << 12 | 0x33);
    }

    #[test]
    fn reused_slot_frees_a_flagged_stale_pointer_and_clears_it() {
        let fixture = Fixture::new();
        // Plant a flagged stale pointer in slot 2 (two pushes from the
        // reset state land there).
        unsafe {
            (*FIXTURE_BLOCK).pointers[2] = MARKER;
            (*FIXTURE_BLOCK).flags[2] = 1;
        }
        push_n(3);
        assert_eq!(fixture.freed(), std::vec![MARKER], "traced_free got the stale word");
        let block = fixture.block();
        assert_eq!(block.pointers[2], 0, "cleared after the free");
        assert_eq!(block.flags[2], 0, "cleared for the new occupant");
        // push #2 (i=1) occupies slot 2: facility 0x11, subsystem
        // 0x201, code 0x301.
        assert_eq!(block.tags[2], 0x11 << 24 | 0x201 << 12 | 0x301, "new record stored");
    }

    #[test]
    fn unflagged_or_null_stale_pointers_are_not_freed_but_flags_still_clear() {
        let fixture = Fixture::new();
        unsafe {
            // Pointer set, flag bit 0 clear: kept.
            (*FIXTURE_BLOCK).pointers[1] = MARKER;
            (*FIXTURE_BLOCK).flags[1] = 0;
            // Pointer set, only bit 1 set (`tst #1` misses it): kept.
            (*FIXTURE_BLOCK).pointers[2] = MARKER + 1;
            (*FIXTURE_BLOCK).flags[2] = 2;
            // Flag set but pointer NULL (`cmp r0,#0` fails first):
            // no free call.
            (*FIXTURE_BLOCK).pointers[3] = 0;
            (*FIXTURE_BLOCK).flags[3] = 1;
        }
        push_n(4);
        assert!(fixture.freed().is_empty(), "no slot qualified for a free");
        let block = fixture.block();
        assert_eq!(block.pointers[1], MARKER, "unflagged pointer survives");
        assert_eq!(block.pointers[2], MARKER + 1, "bit-1-only flag does not free");
        assert_eq!(block.flags[1], 0, "flags cleared regardless");
        assert_eq!(block.flags[2], 0);
        assert_eq!(block.flags[3], 0);
    }

    /// Snapshot of `(tags[1], freed word)` taken by the free below,
    /// proving the store-before-free order.
    static SNAPSHOT: Mutex<Option<(u32, u32)>> = Mutex::new(None);

    /// Mock free that inspects the block mid-call: the new tag must
    /// already be in the slot when the stale pointer is released.
    unsafe extern "C" fn tag_snapshot_free(block: *mut u8) {
        let b = &*FIXTURE_BLOCK;
        *SNAPSHOT.lock().unwrap() = Some((b.tags[1], block as usize as u32));
    }

    #[test]
    fn the_new_tag_is_already_stored_when_the_free_runs() {
        // Pins the original's order: tag/data stores precede the free
        // (the mock free inspects the block mid-call).
        let _fixture = Fixture::new();
        unsafe {
            (*FIXTURE_BLOCK).pointers[1] = MARKER;
            (*FIXTURE_BLOCK).flags[1] = 1;
            (*core::ptr::addr_of_mut!(TRACED_FREE_HOOKS)).free = tag_snapshot_free;
            diag_ring_record(0x7e, 0x57a, 0x11, 0, 0);
        }
        assert_eq!(
            SNAPSHOT.lock().unwrap().take(),
            Some((0x7e << 24 | 0x57a << 12 | 0x11, MARKER)),
            "free ran after the new tag landed, with the stale pointer",
        );
    }

    #[test]
    fn no_block_getter_is_a_documented_noop() {
        // Shipped default: DIAG_RING_BLOCK_GETTER is None. Nothing may
        // crash and no hook may fire.
        let _fixture = Fixture::new();
        unsafe {
            (*core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER)) = None;
            diag_ring_record(1, 2, 3, 4, 5);
        }
        assert!(FREED.lock().unwrap().is_empty());
    }

    #[test]
    fn null_block_from_the_getter_is_also_a_noop() {
        // Not reachable via the stock getter (it allocates or finds),
        // but a wired replacement could; guarded, as documented.
        let _fixture = Fixture::new();
        unsafe {
            (*core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER)) = Some(null_getter);
            diag_ring_record(1, 2, 3, 4, 5);
        }
        assert!(FREED.lock().unwrap().is_empty());
    }
}
