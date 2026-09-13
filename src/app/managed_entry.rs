//! Managed two-word entry release — the unconditional cleanup companion of
//! the flagged release at 0x0806ce40.
//!
//! A *managed entry* is a two-word slot whose first word points at a record
//! while occupied. Callers across 0x0803c4c0..0x08068408 (40 verified `bl`
//! sites, all unconditional — no predicated calls) treat the pair as an
//! in/out handle: acquisition paths fill it, work paths consume it, and
//! error/cleanup paths hand it to [`managed_entry_release`], which returns
//! the slot to the empty state no matter how the release went.
//!
//! The manager object owns a release callback at `+0x40` and the opaque
//! context word passed as its first argument at `+0x04`. Two release
//! counters sit side by side: `+0x50` is bumped by this unconditional
//! release, `+0x54` by the flagged sibling
//! [`managed_entry_release_flagged`], which passes `flags | 2`, preserves
//! the slot when that callback fails, and returns the callback status. The
//! bit-1 flag therefore plausibly marks a dirty/write-back release; this
//! port is the clean/abandon variant.
//!
//! Records recovered from callers hold two big-endian u32 ids at `+0x00`
//! and `+0x04` (via the BE word helpers 0x08031140/0x08031160), a state
//! byte at `+0x08` (`-1` marks a special state), a kind byte at `+0x09`,
//! and a u16 count at `+0x0a`. The owning subsystem is not recovered; the
//! name describes the mechanism only.

use core::ptr;

/// ABI of the manager's release callback stored at `+0x40`.
///
/// `context` is the manager's `+0x04` word, `entry` the two-word slot,
/// `flags` the release flags (always 0 from [`managed_entry_release`];
/// the sibling 0x0806ce40 passes `flags | 2`). Returns a status word that
/// the release forwards unchanged.
pub type ManagedEntryReleaseFn =
    unsafe extern "C" fn(context: *mut u8, entry: *mut ManagedEntry, flags: u32) -> i32;

/// Two-word managed entry slot (8 bytes on target).
///
/// `record` is non-NULL while the slot is occupied. `auxiliary` is
/// recovered only as "the second word, cleared together with the first";
/// no caller of this function inspects it.
#[repr(C)]
pub struct ManagedEntry {
    /// `+0x00`: occupied-record pointer, NULL when the slot is empty.
    pub record: *mut u8,
    /// `+0x04`: auxiliary word, always cleared alongside `record`.
    pub auxiliary: u32,
}

/// The manager object as far as this function recovers it.
///
/// Field layout matches the firmware exactly on the 32-bit target (every
/// member is one 4-byte word); on host the same `#[repr(C)]` model lets
/// tests install native function pointers — the crate's standing
/// deviation for object-carried callbacks.
#[repr(C)]
pub struct ManagedEntryManager {
    /// `+0x00`: not recovered by this function.
    pub opaque_00: u32,
    /// `+0x04`: opaque context word, first argument to the callback.
    pub release_context: *mut u8,
    /// `+0x08..+0x40`: not recovered by this function.
    pub opaque_08: [u32; 14],
    /// `+0x40`: release callback code word.
    pub release_callback: ManagedEntryReleaseFn,
    /// `+0x44..+0x50`: not recovered by this function.
    pub opaque_44: [u32; 3],
    /// `+0x50`: count of unconditional releases performed.
    pub release_count: u32,
    /// `+0x54`: count of flagged releases whose callbacks succeeded.
    pub flagged_release_count: u32,
}

/// managed_entry_release — original: `FUN_080645b8` @ 0x080645b8
/// (76 bytes, 19 instructions, ending at 0x08064604 where the next
/// function begins; 40 `bl` call sites verified by decoding every B/BL
/// word in osos.dec, all unconditional — zero predicated calls).
///
/// ```text
/// 080645b8  push  {r4, r5, r6, lr}
/// 080645bc  mov   r5, r1            @ r5 = entry
/// 080645c0  ldr   r1, [r1]          @ r1 = entry->record
/// 080645c4  mov   r4, r0            @ r4 = manager
/// 080645c8  cmp   r1, #0
/// 080645cc  mov   r0, #0            @ status = 0
/// 080645d0  beq   0x080645f4        @ empty slot: skip to clear
/// 080645d4  ldr   r3, [r4, #0x40]   @ release callback
/// 080645d8  ldr   r0, [r4, #4]      @ callback context
/// 080645dc  mov   r2, #0            @ flags = 0
/// 080645e0  mov   r1, r5            @ entry
/// 080645e4  blx   r3
/// 080645e8  ldr   r1, [r4, #0x50]
/// 080645ec  add   r1, r1, #1
/// 080645f0  str   r1, [r4, #0x50]   @ manager->release_count++
/// 080645f4  mov   r1, #0
/// 080645f8  str   r1, [r5]          @ entry->record = NULL
/// 080645fc  str   r1, [r5, #4]      @ entry->auxiliary = 0
/// 08064600  pop   {r4, r5, r6, pc}
/// ```
///
/// If the slot is occupied, invokes
/// `manager->release_callback(manager->release_context, entry, 0)` and
/// bumps `manager->release_count`, keeping the callback's status. The
/// slot is then cleared unconditionally — both words are zeroed even when
/// the callback fails or rewrites the slot mid-call — and the status (0
/// for an already-empty slot) is returned.
///
/// Deviations: the manager and entry are this module's `#[repr(C)]`
/// models, so field accesses replace the raw `+0x04`/`+0x40`/`+0x50` byte
/// offsets (the crate's standing idiom for object-carried callbacks,
/// see app/scoped_context.rs); all target-side fields are single 4-byte
/// words, so the target layout is exact. The callback is an
/// object-carried code word, not a fixed firmware address, so no
/// dispatch seam is needed and none was added.
///
/// # Safety
///
/// `manager` must point at a valid manager whose `+0x40` callback and
/// `+0x04` context words are initialized, and `entry` at a writable
/// two-word slot. As in retailOS, an occupied slot with a corrupt
/// callback is not guarded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn managed_entry_release(
    manager: *mut ManagedEntryManager,
    entry: *mut ManagedEntry,
) -> i32 {
    let mut status = 0;
    if !(*entry).record.is_null() {
        status = ((*manager).release_callback)((*manager).release_context, entry, 0);
        (*manager).release_count = (*manager).release_count.wrapping_add(1);
    }
    (*entry).record = ptr::null_mut();
    (*entry).auxiliary = 0;
    status
}

/// managed_entry_release_flagged — original: `FUN_0806ce40` @ 0x0806ce40
/// (84 bytes, 21 instructions, ending at 0x0806ce94 where the next function
/// begins; 21 `bl` call sites verified by decoding every ARM B/BL word in
/// osos.dec, all unconditional — zero predicated calls and zero plain
/// branches).
///
/// ```text
/// 0806ce40  push  {r4, r5, r6, lr}
/// 0806ce44  mov   r5, r1            @ r5 = entry
/// 0806ce48  ldr   r1, [r1]          @ r1 = entry->record
/// 0806ce4c  mov   r4, r0            @ r4 = manager
/// 0806ce50  cmp   r1, #0
/// 0806ce54  mov   r0, r3            @ status = supplied flags
/// 0806ce58  beq   0x0806ce84        @ empty slot: clear and return 0
/// 0806ce5c  ldr   r3, [r4, #0x40]   @ release callback
/// 0806ce60  orr   r2, r0, #2        @ callback flags = flags | 2
/// 0806ce64  ldr   r0, [r4, #4]      @ callback context
/// 0806ce68  mov   r1, r5            @ entry
/// 0806ce6c  blx   r3
/// 0806ce70  cmp   r0, #0
/// 0806ce74  popne {r4, r5, r6, pc}  @ failure: preserve slot
/// 0806ce78  ldr   r0, [r4, #0x54]
/// 0806ce7c  add   r0, r0, #1
/// 0806ce80  str   r0, [r4, #0x54]   @ manager->flagged_release_count++
/// 0806ce84  mov   r0, #0
/// 0806ce88  str   r0, [r5]          @ entry->record = NULL
/// 0806ce8c  str   r0, [r5, #4]      @ entry->auxiliary = 0
/// 0806ce90  pop   {r4, r5, r6, pc}
/// ```
///
/// An empty slot is normalized to two zero words and returns zero without
/// calling the manager. Otherwise invokes
/// `manager->release_callback(manager->release_context, entry, flags | 2)`.
/// A nonzero callback status returns immediately, preserving the entry and
/// leaving `flagged_release_count` unchanged. A zero callback status bumps
/// that counter, then clears both entry words and returns zero.
///
/// Deliberate deviations: the manager and entry use this module's
/// `#[repr(C)]` models instead of raw byte offsets. The target fields are all
/// one four-byte word, so their target layout is exact. The callback is an
/// object-carried code word, not a fixed firmware address, so no dispatch
/// seam is needed or added. The unused r2 argument is explicit to preserve
/// the retailOS four-register ABI; the routine reads its flags from r3.
///
/// # Safety
///
/// `manager` must point at a valid manager whose `+0x40` callback and
/// `+0x04` context words are initialized, and `entry` at a writable
/// two-word slot. As in retailOS, an occupied slot with a corrupt callback
/// is not guarded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn managed_entry_release_flagged(
    manager: *mut ManagedEntryManager,
    entry: *mut ManagedEntry,
    _unused: u32,
    flags: u32,
) -> i32 {
    if (*entry).record.is_null() {
        (*entry).record = ptr::null_mut();
        (*entry).auxiliary = 0;
        return 0;
    }

    let status = ((*manager).release_callback)(
        (*manager).release_context,
        entry,
        flags | 2,
    );
    if status != 0 {
        return status;
    }

    (*manager).flagged_release_count =
        (*manager).flagged_release_count.wrapping_add(1);
    (*entry).record = ptr::null_mut();
    (*entry).auxiliary = 0;
    0
}

/// ABI prefix used to search a managed record's reverse offset table.
///
/// The target object stores its comparison callback at `+0x08` and the
/// halfword one-past-end offset of its reverse `u16` table at `+0x1c`.
/// Host pointer width makes the host layout different after `compare`; field
/// accesses deliberately preserve the callback contract in host tests while
/// retaining the exact target offsets.
#[repr(C)]
pub struct ManagedEntrySearchManager {
    /// `+0x00..+0x04`: not recovered by this search helper.
    pub opaque_00: u32,
    pub opaque_04: u32,
    /// `+0x08`: compares `(key, record + table_offset)`.
    pub compare: ManagedEntrySearchCompare,
    /// `+0x0c..+0x1b`: not recovered by this search helper.
    pub opaque_0c: [u32; 4],
    /// `+0x1c`: byte offset immediately after the reverse `u16` table.
    pub reverse_offsets_end: u16,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(ManagedEntrySearchManager, compare) == 8);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(ManagedEntrySearchManager, reverse_offsets_end) == 28);

/// Callback used by [`managed_entry_search_key_index`].
pub type ManagedEntrySearchCompare =
    unsafe extern "C" fn(key: *const u8, candidate: *const u8) -> i32;

/// Prefix of a managed record searched by [`managed_entry_search_key_index`].
#[repr(C)]
pub struct ManagedEntrySearchRecord {
    /// `+0x00..+0x07`: opaque record identifier.
    pub identifier: [u8; 8],
    /// `+0x08`: special-state marker used by callers, not by this helper.
    pub state: i8,
    /// `+0x09`: record kind used by callers, not by this helper.
    pub kind: u8,
    /// `+0x0a`: number of offsets in the reverse table.
    pub entry_count: u16,
}

/// managed_entry_search_key_index — original: `FUN_08066160` @ `0x08066160`
/// (128 bytes, `0x08066160..0x080661e0`; the sibling function begins with
/// `push {r4-r9,sl,fp,lr}` at `0x080661e0`). Seven direct `bl` call sites
/// were verified by decoding every ARM B/BL immediate in `osos.dec`: all are
/// unconditional (`0x08041df8`, `0x08041e88`, `0x08050858`, `0x080508d8`,
/// `0x080509a4`, `0x08066248`, and `0x0806b774`), with no predicated calls.
///
/// Performs a lower-bound binary search of a managed record's reverse `u16`
/// offset table.  Index `mid` is read from
/// `record + manager->reverse_offsets_end - 2 - 2*mid`, then passed with the
/// key to the manager's comparison callback. A negative result searches the
/// lower half; a positive result searches the upper half. On equality it
/// writes `mid` and returns one. Otherwise it writes the insertion index and
/// returns zero. A zero count writes zero without calling the comparator.
/// No deliberate deviations.
///
/// # Safety
///
/// `manager` must carry a valid comparison callback and a reverse-table end
/// offset within `record`; `record` must contain `entry_count` aligned `u16`
/// offsets immediately before that end, and every selected offset must name a
/// callback-valid candidate. `out_index` must be writable. RetailOS provides
/// no null guards for any of these pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn managed_entry_search_key_index(
    manager: *const ManagedEntrySearchManager,
    record: *const ManagedEntrySearchRecord,
    key: *const u8,
    out_index: *mut u16,
) -> u32 {
    let mut lower = 0i32;
    let mut upper = (*record).entry_count as i32 - 1;
    let record_bytes = record.cast::<u8>();

    while lower <= upper {
        let middle = (lower + upper) >> 1;
        let offset_address = record_bytes
            .add((*manager).reverse_offsets_end as usize)
            .sub(2 + middle as usize * 2);
        let candidate_offset = *offset_address.cast::<u16>() as usize;
        let comparison = ((*manager).compare)(key, record_bytes.add(candidate_offset));

        if comparison < 0 {
            upper = middle - 1;
        } else if comparison > 0 {
            lower = middle + 1;
        } else {
            *out_index = middle as u16;
            return 1;
        }
    }

    *out_index = lower as u16;
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;

    /// What the recording callback observed, driven through the manager's
    /// context word so no shared statics (and no test lock) are needed.
    #[derive(Default)]
    struct ReleaseCallLog {
        calls: u32,
        context_seen: usize,
        entry_seen: usize,
        flags_seen: u32,
        /// Value of `entry->record` sampled *inside* the callback: proves
        /// the slot is still occupied during the release and cleared only
        /// afterwards.
        record_during_call: usize,
        status_to_return: i32,
    }

    unsafe extern "C" fn recording_release(
        context: *mut u8,
        entry: *mut ManagedEntry,
        flags: u32,
    ) -> i32 {
        let log = &mut *(context as *mut ReleaseCallLog);
        log.calls += 1;
        log.context_seen = context as usize;
        log.entry_seen = entry as usize;
        log.flags_seen = flags;
        log.record_during_call = (*entry).record as usize;
        log.status_to_return
    }

    fn fixture(count: u32, status: i32) -> (Box<ManagedEntryManager>, Box<ReleaseCallLog>) {
        let log = Box::new(ReleaseCallLog { status_to_return: status, ..Default::default() });
        let manager = Box::new(ManagedEntryManager {
            opaque_00: 0xaaaa_0000,
            release_context: &*log as *const ReleaseCallLog as *mut u8,
            opaque_08: [0xdead_beef; 14],
            release_callback: recording_release,
            opaque_44: [0xdead_beef; 3],
            release_count: count,
            flagged_release_count: count,
        });
        (manager, log)
    }

    #[test]
    fn empty_slot_skips_callback_and_clears_both_words() {
        let (mut manager, log) = fixture(41, 0);
        let mut entry = ManagedEntry { record: ptr::null_mut(), auxiliary: 0x1234_5678 };
        let status = unsafe { managed_entry_release(&mut *manager, &mut entry) };
        assert_eq!(status, 0);
        assert_eq!(log.calls, 0, "callback must not run for an empty slot");
        assert_eq!(manager.release_count, 41, "counter must not move");
        assert!(entry.record.is_null());
        assert_eq!(entry.auxiliary, 0, "second word is cleared even when empty");
    }

    #[test]
    fn occupied_slot_releases_with_zero_flags_and_counts() {
        let (mut manager, log) = fixture(41, 0);
        let mut record = 0x5au8;
        let mut entry = ManagedEntry { record: &mut record, auxiliary: 0xfeed_face };
        let status = unsafe { managed_entry_release(&mut *manager, &mut entry) };
        assert_eq!(status, 0);
        assert_eq!(log.calls, 1);
        assert_eq!(log.context_seen, &*log as *const _ as usize);
        assert_eq!(log.entry_seen, &entry as *const _ as usize);
        assert_eq!(log.flags_seen, 0, "this variant always releases with flags 0");
        assert_eq!(log.record_during_call, &record as *const _ as usize,
            "slot is still occupied while the callback runs");
        assert_eq!(manager.release_count, 42);
        assert!(entry.record.is_null());
        assert_eq!(entry.auxiliary, 0);
    }

    #[test]
    fn callback_error_still_clears_slot_and_counts() {
        let (mut manager, log) = fixture(7, -0x24);
        let mut record = 0u8;
        let mut entry = ManagedEntry { record: &mut record, auxiliary: 1 };
        let status = unsafe { managed_entry_release(&mut *manager, &mut entry) };
        assert_eq!(status, -0x24, "callback status propagates unchanged");
        assert_eq!(manager.release_count, 8, "count bumps before/independent of the clear");
        assert!(entry.record.is_null(), "slot cleared even on error");
        assert_eq!(entry.auxiliary, 0);
    }

    /// A callback that scribbles on the slot mid-release: the trailing
    /// clear must still win, matching the ARM order (blx, count, clear).
    #[test]
    fn callback_writes_to_slot_are_overwritten_by_trailing_clear() {
        unsafe extern "C" fn scribbling_release(
            _context: *mut u8,
            entry: *mut ManagedEntry,
            _flags: u32,
        ) -> i32 {
            (*entry).record = 0xbaad_f00d as *mut u8;
            (*entry).auxiliary = 0x0bad_cafe;
            9
        }
        let (mut manager, _log) = fixture(0, 0);
        manager.release_callback = scribbling_release;
        let mut record = 0u8;
        let mut entry = ManagedEntry { record: &mut record, auxiliary: 2 };
        let status = unsafe { managed_entry_release(&mut *manager, &mut entry) };
        assert_eq!(status, 9);
        assert!(entry.record.is_null());
        assert_eq!(entry.auxiliary, 0);
        assert_eq!(manager.release_count, 1);
    }

    #[test]
    fn release_count_wraps_like_the_arm_add() {
        let (mut manager, _log) = fixture(u32::MAX, 0);
        let mut record = 0u8;
        let mut entry = ManagedEntry { record: &mut record, auxiliary: 0 };
        unsafe { managed_entry_release(&mut *manager, &mut entry) };
        assert_eq!(manager.release_count, 0, "u32 wrap, no widening");
    }

    #[test]
    fn flagged_empty_slot_skips_callback_and_normalizes_entry() {
        let (mut manager, log) = fixture(41, 0);
        let mut entry = ManagedEntry { record: ptr::null_mut(), auxiliary: 0x1234_5678 };
        let status = unsafe {
            managed_entry_release_flagged(&mut *manager, &mut entry, 0xfeed_face, 0x100)
        };
        assert_eq!(status, 0);
        assert_eq!(log.calls, 0, "empty slots do not call the callback");
        assert_eq!(manager.flagged_release_count, 41, "counter must not move");
        assert!(entry.record.is_null());
        assert_eq!(entry.auxiliary, 0);
    }

    #[test]
    fn flagged_success_forwards_orred_flags_counts_and_clears() {
        let (mut manager, log) = fixture(41, 0);
        let mut record = 0x5au8;
        let mut entry = ManagedEntry { record: &mut record, auxiliary: 0xfeed_face };
        let status = unsafe {
            managed_entry_release_flagged(&mut *manager, &mut entry, 0, 0x100)
        };
        assert_eq!(status, 0);
        assert_eq!(log.calls, 1);
        assert_eq!(log.context_seen, &*log as *const _ as usize);
        assert_eq!(log.entry_seen, &entry as *const _ as usize);
        assert_eq!(log.flags_seen, 0x102, "callback receives flags | 2");
        assert_eq!(log.record_during_call, &record as *const _ as usize);
        assert_eq!(manager.flagged_release_count, 42);
        assert!(entry.record.is_null());
        assert_eq!(entry.auxiliary, 0);
    }

    #[test]
    fn flagged_callback_error_preserves_entry_and_does_not_count() {
        let (mut manager, log) = fixture(7, -0x24);
        let mut record = 0u8;
        let mut entry = ManagedEntry { record: &mut record, auxiliary: 0xfeed_face };
        let status = unsafe {
            managed_entry_release_flagged(&mut *manager, &mut entry, 0, 0)
        };
        assert_eq!(status, -0x24, "callback status propagates unchanged");
        assert_eq!(log.calls, 1);
        assert_eq!(log.flags_seen, 2);
        assert_eq!(manager.flagged_release_count, 7, "failure skips counter");
        assert_eq!(entry.record, &mut record as *mut u8, "failure keeps the slot");
        assert_eq!(entry.auxiliary, 0xfeed_face, "failure keeps both words");
    }

    #[test]
    fn flagged_release_count_wraps_like_the_arm_add() {
        let (mut manager, _log) = fixture(u32::MAX, 0);
        let mut record = 0u8;
        let mut entry = ManagedEntry { record: &mut record, auxiliary: 0 };
        unsafe { managed_entry_release_flagged(&mut *manager, &mut entry, 0, 0) };
        assert_eq!(manager.flagged_release_count, 0, "u32 wrap, no widening");
        assert!(entry.record.is_null());
        assert_eq!(entry.auxiliary, 0);
    }

    #[repr(C)]
    struct SearchRecordFixture {
        identifier: [u8; 8],
        state: i8,
        kind: u8,
        entry_count: u16,
        reverse_table: [u8; 20],
        values: [u8; 3],
    }

    unsafe extern "C" fn compare_key_byte(key: *const u8, candidate: *const u8) -> i32 {
        *key as i32 - *candidate as i32
    }

    unsafe extern "C" fn comparator_must_not_run(_: *const u8, _: *const u8) -> i32 {
        panic!("zero entries must not invoke the comparator");
    }

    fn search_manager(compare: ManagedEntrySearchCompare) -> ManagedEntrySearchManager {
        ManagedEntrySearchManager {
            opaque_00: 0,
            opaque_04: 0,
            compare,
            opaque_0c: [0; 4],
            reverse_offsets_end: 18,
        }
    }

    fn search_record() -> SearchRecordFixture {
        let mut record = SearchRecordFixture {
            identifier: [0; 8],
            state: -1,
            kind: 0,
            entry_count: 3,
            reverse_table: [0; 20],
            values: [10, 20, 30],
        };
        let base = (&mut record as *mut SearchRecordFixture).cast::<u8>();
        let values_offset = core::mem::offset_of!(SearchRecordFixture, values) as u16;
        unsafe {
            base.add(16).cast::<u16>().write(values_offset);
            base.add(14).cast::<u16>().write(values_offset + 1);
            base.add(12).cast::<u16>().write(values_offset + 2);
        }
        record
    }

    #[test]
    fn search_finds_an_exact_key_through_the_reverse_offset_table() {
        let manager = search_manager(compare_key_byte);
        let record = search_record();
        let key = 20u8;
        let mut index = u16::MAX;

        assert_eq!(
            unsafe {
                managed_entry_search_key_index(
                    &manager,
                    (&record as *const SearchRecordFixture).cast(),
                    &key,
                    &mut index,
                )
            },
            1
        );
        assert_eq!(index, 1);
    }

    #[test]
    fn search_returns_each_lower_bound_when_the_key_is_absent() {
        let manager = search_manager(compare_key_byte);
        let record = search_record();

        for (key, expected_index) in [(5u8, 0u16), (25, 2), (35, 3)] {
            let mut index = u16::MAX;
            assert_eq!(
                unsafe {
                    managed_entry_search_key_index(
                        &manager,
                        (&record as *const SearchRecordFixture).cast(),
                        &key,
                        &mut index,
                    )
                },
                0,
                "key {key} must not match"
            );
            assert_eq!(index, expected_index, "key {key}");
        }
    }

    #[test]
    fn empty_search_writes_zero_without_dispatching() {
        let manager = search_manager(comparator_must_not_run);
        let mut record = search_record();
        record.entry_count = 0;
        let key = 0u8;
        let mut index = u16::MAX;

        assert_eq!(
            unsafe {
                managed_entry_search_key_index(
                    &manager,
                    (&record as *const SearchRecordFixture).cast(),
                    &key,
                    &mut index,
                )
            },
            0
        );
        assert_eq!(index, 0);
    }
}
