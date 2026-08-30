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
//! release, `+0x54` by the flagged sibling `FUN_0806ce40`, which passes
//! `flags | 2` instead of 0, propagates a callback error *without* clearing
//! the slot, and returns `void`. The bit-1 flag therefore plausibly marks a
//! dirty/write-back release; this port is the clean/abandon variant.
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
}
