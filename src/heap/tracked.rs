//! The tag-57 *tracked* allocator's free side — 32-byte-aligned blocks
//! with a size cookie and a running byte counter. Cluster
//! 0x083906f4..0x08390774 plus the tag-57 veneers @ 0x08391d24/0x08391d2c.
//!
//! Block layout produced by `tracked_alloc_tail` @ 0x08390b8c (ported
//! below; the enclosing allocator's entry @ 0x08390b14 is not — see
//! below):
//!
//! ```text
//! raw + 0x00  i32   size          bytes the caller asked for
//! raw + 0x04  i32   size >> 31    sign extension, so the pair is an i64
//! raw + 0x08        base          first byte of the payload area
//! ...               padding       so that `data` lands 32-byte aligned
//! data - 0x04 u32   pad           data - base, recovered on free
//! data              payload
//! ```
//!
//! The allocator computes `data = (base + 36) & ~31`, i.e. at least 4 and
//! at most 36 bytes of padding — the +4 guarantees room for the `pad`
//! word itself.
//!
//! Accounting globals live in the 0x08adc2c0 block (9 code references):
//!
//! ```text
//! +0x20  i64  soft_limit       entry warns when current + size reaches it
//! +0x28  u32   limit_callback  pointer word; blx'd by the warn helper
//! +0x2c  u32   callback_arg    pointer word; the callback's 1st argument
//! +0x30  u32   callback_active reentrancy guard around the blx
//! +0x34  u32   lock_flag       stats lock, armed to 8 (see arm_lock)
//! +0x38  i64  current_bytes   incremented on alloc, decremented on free
//! +0x40  i64  peak_bytes      raised to current_bytes whenever it grows
//! ```
//!
//! The +0x20..+0x30 group is the soft-limit configuration, written by
//! `tracked_stats_set_soft_limit` @ 0x08390bf0 (ported below) and read
//! by the allocator entry @ 0x08390b14 — when the callback word is
//! nonzero and `current_bytes + size` reaches `soft_limit` it calls the
//! warn helper @ 0x0837d67c, which `blx`s the callback as
//! `callback(callback_arg, current_bytes, size)` under the +0x30 guard.
//!
//! Both are read/written with `ldrd`/`strd`, so the block is 8-aligned
//! (0x08adc2f8 and 0x08adc300 are). The peak is only touched by the
//! allocator and by the peak reader @ 0x08390c24 (ported below; its
//! 0x08390c30 tail does the conditional `peak := current` reset); the
//! free path here just subtracts, and it subtracts a *signed* 32-bit
//! size widened to 64 (`sbc r1, r1, r2, asr #31`).
//!
//! Ported here (binary-scanned call counts):
//!
//! - `tracked_alloc_tail` — original @ 0x08390b8c (92 bytes: the tail of
//!   the tag-57 tracked allocator whose entry @ 0x08390b14 has the size
//!   gate, the soft-limit check and the retry-warning call; **41 `bl`
//!   call sites of the entry**). Retries `alloc_tag57(size + 44)`, builds
//!   the block above, and does the alloc-side accounting.
//! - `tracked_free` — original: `FUN_083906f4` @ 0x083906f4 (68 bytes:
//!   64 code + the 0x08adc2c0 literal; **218 `bl` + 22 tail `b` call
//!   sites**). Undoes the layout above and hands the raw block to the
//!   tag-57 free veneer.
//! - `tracked_free_pointer_array` — original: `FUN_08390734` @ 0x08390734
//!   (68 bytes, 3 call sites). Frees a block that starts with a word
//!   count and continues with `count - 1` pointers, releasing each
//!   non-NULL element with `tracked_free` before releasing the block.
//! - `free_tag57` / `alloc_tag57` — originals @ 0x08391d24 and
//!   0x08391d2c (8 bytes each): `mov r1, #57` in front of `free_wrapper`
//!   @ 0x080e7970 / `malloc_wrapper` @ 0x080eb67c (heap/veneers.rs).
//! - `tracked_stats_peak` — original: `FUN_08390c24` @ 0x08390c24
//!   (44 bytes — functions.csv's size, verified against osos.asm: the
//!   COMPLETE peak reader whose 0x08390c30 tail the ledger lists
//!   separately as `tracked_stats_reset_peak`). Arms the stats lock,
//!   reads the peak (+0x40) with `ldrd` into the return pair, then
//!   conditionally copies current (+0x38) over the peak when the reset
//!   argument is nonzero — the returned peak is the pre-reset value.
//! - `tracked_stats_current` — original: `FUN_08390c54` @ 0x08390c54
//!   (20 bytes, 1 `bl` call site @ 0x08391450). Arms the stats lock
//!   (scheduler-flag setter @ 0x082ccc74) and returns the running byte
//!   counter (+0x38) read with `ldrd`.
//! - `tracked_stats_arm_lock` — original: `FUN_082ccc74` @ 0x082ccc74
//!   (24 bytes; 4 `bl` call sites: the allocator entry @ 0x08390b14, the
//!   soft-limit setter @ 0x08390bf0, the peak reader @ 0x08390c24 and
//!   `tracked_stats_current` @ 0x08390c54). The "scheduler-flag setter":
//!   arms the stats-lock word (stats + 0x34) to 8 when it is 0, so a
//!   running scheduler knows not to tear the `ldrd` counter reads.
//!   Verified against osos.dec: its literal-pool pointer is 0x08adc2e0
//!   (stats base + 0x20), so the flag it arms — `*(0x08adc2e0 + 0x14)` —
//!   is 0x08adc2f4, i.e. **the word at stats + 0x34 inside the same
//!   0x08adc2c0 accounting block**, immediately before `current_bytes`.
//!   The RTXC scheduler is never touched; the flag is the allocator's
//!   own tear-guard for the two i64 counters.
//! - `tracked_stats_set_soft_limit` — original: `FUN_08390bf0` @
//!   0x08390bf0 (52 bytes, 1 `bl` call site @ 0x0839144c; the init path
//!   reaches the same setter through the thunk @ 0x0813eb3c). The
//!   ledger's "stats init": arms the stats lock and writes the
//!   soft-limit configuration — the i64 limit @ +0x20 and the
//!   callback/callback-arg words @ +0x28/+0x2c — then returns 0.
//! - `tracked_stats_warn_soft_limit` — original: `FUN_0837d67c` @
//!   0x0837d67c (84 bytes; 4 call sites: the `blge`/`bl` pair in the
//!   allocator entry @ 0x08390b14 and the `blge`/`bl` pair in the
//!   tracked realloc @ 0x08390eec). The soft-limit warn helper: when
//!   the callback word (+0x28) is nonzero and the reentrancy guard
//!   (+0x30) is clear, it sets the guard and `blx`s the callback as
//!   `callback(callback_arg, current_bytes, size)`, then clears it.
//!
//! Simplification, same as `heap/veneers.rs` makes for the default heap:
//! the accounting block is a `static` here instead of living at
//! 0x08adc2c0.
//!
//! Word-index rule: every field `tracked_free` touches is a 32-bit
//! scalar, so its literal byte offsets are correct on a 64-bit host too.
//! The stats block's pointer-valued words (the soft-limit callback and
//! its argument) are likewise modeled as `u32` for the same reason.
//! The pointer array is different — its cookie and elements are
//! pointer-sized, so it is addressed by *index* through a `*mut *mut u8`,
//! which is stride 4 on the target and stride 8 on the host.

use crate::heap::veneers::{free_wrapper, malloc_wrapper};

/// Caller tag this allocator uses for both halves (`mov r1, #57`).
pub const TAG_TRACKED: usize = 57;

/// Bytes of header below the payload area (`size`, `size >> 31`).
pub const BLOCK_HEADER_SIZE: usize = 8;

/// Allocation accounting block. Original: 0x08adc2c0; only the words
/// this module and the allocator touch are named. The pointer-valued
/// words are modeled as `u32` so the literal byte offsets hold on a
/// 64-bit host too (the module's word-index rule).
#[repr(C)]
pub struct AllocStats {
    /// 0x00..0x20 — fields owned by other parts of the allocator.
    pub reserved: [u32; 8],
    /// +0x20: soft limit. The allocator entry @ 0x08390b14 warns when
    /// `current_bytes + size` reaches it (gated on the callback word).
    pub soft_limit: i64,
    /// +0x28: limit-warning callback (pointer-valued word). The warn
    /// helper @ 0x0837d67c `blx`s it as
    /// `callback(callback_arg, current_bytes, size)` when the limit is
    /// reached; the allocator entry skips the whole check when it is 0.
    pub soft_limit_callback: u32,
    /// +0x2c: the callback's first argument (pointer-valued word).
    pub soft_limit_callback_arg: u32,
    /// +0x30: reentrancy guard the warn helper sets around the `blx`.
    pub soft_limit_callback_active: u32,
    /// +0x34: stats-lock flag (original 0x08adc2f4). Armed to 8 by
    /// `tracked_stats_arm_lock` when 0; guards the `ldrd` reads of the
    /// two i64 counters below against a running scheduler.
    pub lock_flag: u32,
    /// +0x38: bytes currently outstanding.
    pub current_bytes: i64,
    /// +0x40: high-water mark of `current_bytes`.
    pub peak_bytes: i64,
}

/// The accounting block (original @ 0x08adc2c0).
pub static mut ALLOC_STATS: AllocStats = AllocStats {
    reserved: [0; 8],
    soft_limit: 0,
    soft_limit_callback: 0,
    soft_limit_callback_arg: 0,
    soft_limit_callback_active: 0,
    lock_flag: 0,
    current_bytes: 0,
    peak_bytes: 0,
};

/// alloc_tag57 — original @ 0x08391d2c (8 bytes): `malloc_wrapper` with
/// caller tag 57.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn alloc_tag57(size: usize) -> *mut u8 {
    malloc_wrapper(size, TAG_TRACKED)
}

/// free_tag57 — original @ 0x08391d24 (8 bytes): `free_wrapper` with
/// caller tag 57.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn free_tag57(block: *mut u8) {
    free_wrapper(block, TAG_TRACKED)
}

/// tracked_alloc_tail — original @ 0x08390b8c (92 bytes).
///
/// Tail of the tag-57 tracked allocator (entry @ 0x08390b14): the head
/// rejects `size <= 0`, enforces the soft limit, and warns before the
/// retry — the tail IS the retry. Requests `size + 44` bytes from
/// `alloc_tag57` (8-byte header + at most 36 bytes of alignment
/// padding + payload), returns NULL if the heap is out. On success it
/// writes the signed size cookie and its sign extension at raw+0/+4,
/// computes `data = (base + 36) & !31` with `base = raw + 8`, stores
/// `pad = data - base` at data-4, adds the sign-extended size to the
/// running byte counter, and raises the peak when the counter grew past
/// it. Returns the 32-byte-aligned payload pointer.
///
/// Deviations: the accounting block is the `ALLOC_STATS` static instead
/// of the literal 0x08adc2c0 (module simplification), and the size
/// arrives as the function argument instead of register r5.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_alloc_tail(size: i32) -> *mut u8 {
    let raw = alloc_tag57(size as usize + 0x24 + 8);
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    (raw.add(4) as *mut i32).write(size >> 31);
    let base = raw.add(BLOCK_HEADER_SIZE);
    let data = ((base as usize + 0x24) & !31) as *mut u8;
    (raw as *mut i32).write(size);
    (data.sub(4) as *mut u32).write((data as usize - base as usize) as u32);
    let stats = core::ptr::addr_of_mut!(ALLOC_STATS);
    (*stats).current_bytes = (*stats).current_bytes.wrapping_add(size as i64);
    if (*stats).peak_bytes < (*stats).current_bytes {
        (*stats).peak_bytes = (*stats).current_bytes;
    }
    data
}

/// tracked_free — original @ 0x083906f4.
///
/// Recovers the raw block from an aligned payload pointer, subtracts the
/// recorded size from the running byte counter, and releases the block
/// with caller tag 57. NULL is ignored.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_free(payload: *mut u8) {
    if payload.is_null() {
        return;
    }
    let pad = (payload.sub(4) as *const u32).read() as usize;
    let base = payload.sub(pad);
    let block = base.sub(BLOCK_HEADER_SIZE);
    let size = (block as *const i32).read();
    let stats = core::ptr::addr_of_mut!(ALLOC_STATS);
    (*stats).current_bytes = (*stats).current_bytes.wrapping_sub(size as i64);
    free_tag57(block);
}

/// tracked_free_pointer_array — original @ 0x08390734.
///
/// The block starts one word below `elements` with a *word count*; the
/// remaining `count - 1` words are pointers to tracked blocks. Frees each
/// non-NULL element, then the block itself. NULL is ignored.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_free_pointer_array(elements: *mut *mut u8) {
    if elements.is_null() {
        return;
    }
    let base = elements.sub(1);
    let count = (base as *const usize).read();
    let mut index = 1usize;
    while index < count {
        let element = base.add(index).read();
        if !element.is_null() {
            tracked_free(element);
        }
        index += 1;
    }
    tracked_free(base as *mut u8);
}

/// tracked_stats_arm_lock — original: `FUN_082ccc74` @ 0x082ccc74
/// (24 bytes; 4 `bl` call sites: the tracked-allocator entry
/// @ 0x08390b14, the soft-limit setter @ 0x08390bf0, the peak reader
/// @ 0x08390c24 and `tracked_stats_current` @ 0x08390c54).
///
/// The "scheduler-flag setter" the stats readers arm before touching the
/// 64-bit counters. Original:
///
/// ```text
/// ldr r0, [0x82ccc8c]   ; literal 0x08adc2e0 (stats base + 0x20)
/// ldr r1, [r0, #0x14]   ; the lock word @ 0x08adc2f4 (stats + 0x34)
/// cmp r1, #0
/// moveq r1, #8
/// streq r1, [r0, #0x14] ; arm it to 8 when clear
/// bx lr
/// ```
///
/// One-way arm: when the stats-lock word is 0 it is set to 8; any other
/// value is left alone. Callers (every stats reader/writer of the
/// 0x0839xxxx cluster) run it before the `ldrd`/`strd` pairs on
/// `current_bytes`/`peak_bytes`, so a running scheduler can see the
/// counters are mid-access and not tear the 64-bit reads.
///
/// Deviation: the flag word is `ALLOC_STATS.lock_flag` — the literal
/// pointer resolves to 0x08adc2e0, so `+0x14` is 0x08adc2f4, the word at
/// stats + 0x34 inside the same accounting block the rest of the module
/// already models as a static (same module simplification).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_stats_arm_lock() {
    let stats = core::ptr::addr_of_mut!(ALLOC_STATS);
    // Volatile: the flag is cross-context synchronization state (the
    // allocator arms it, the scheduler reads it) — and without volatile
    // LLVM's globalopt narrows the word to a boolean byte and drops the
    // 8 (observed in ARM release: ldrb/moveq #1/strbeq).
    let flag = core::ptr::addr_of_mut!((*stats).lock_flag);
    if flag.read_volatile() == 0 {
        flag.write_volatile(8);
    }
}

/// Wired default for the invoke slot: the warn helper's `blx r1` @
/// 0x0837d6c0 — transmutes the callback word and calls it as
/// `callback(callback_arg, current_bytes, size)`. Only meaningful on
/// target (a real code address); host tests swap the slot for a
/// recorder, same as they do for `lock`.
unsafe extern "C" fn blx_soft_limit_callback(
    callback: u32,
    callback_arg: u32,
    current_bytes: i64,
    size: i32,
) {
    let callback: unsafe extern "C" fn(u32, i64, i32) =
        core::mem::transmute(callback as usize);
    callback(callback_arg, current_bytes, size);
}

/// Indirect dispatch table for the stats-lock call in
/// `tracked_stats_current` (house ops-slot pattern: an indirect call in
/// place of the original's `bl 0x082ccc74`, so host tests can record the
/// call). The default is the ported `tracked_stats_arm_lock` itself.
#[derive(Clone, Copy)]
pub struct TrackedStatsOps {
    /// Stats lock @ 0x082ccc74 — the scheduler-flag setter
    /// (`if [stats + 0x34] == 0 { [stats + 0x34] = 8 }`), called before
    /// the 64-bit counter reads so a running scheduler can't tear the
    /// `ldrd`. Defaults to the ported [`tracked_stats_arm_lock`].
    pub lock: unsafe extern "C" fn(),
    /// Soft-limit callback `blx` @ 0x0837d6c0 — invokes the callback
    /// word as `callback(callback_arg, current_bytes, size)`. The
    /// callback is a 32-bit word (module word-index rule), so the
    /// default transmutes it; host tests swap in a recorder.
    pub invoke_soft_limit_callback:
        unsafe extern "C" fn(callback: u32, callback_arg: u32, current_bytes: i64, size: i32),
}

/// Wired default: the ported scheduler-flag setter @ 0x082ccc74.
pub(crate) const DEFAULT_TRACKED_STATS_OPS: TrackedStatsOps = TrackedStatsOps {
    lock: tracked_stats_arm_lock,
    invoke_soft_limit_callback: blx_soft_limit_callback,
};

/// The active implementation table. Written once at init on target;
/// host tests swap in recorders and restore the default.
pub static mut TRACKED_STATS_OPS: TrackedStatsOps = DEFAULT_TRACKED_STATS_OPS;

/// tracked_stats_peak — original: `FUN_08390c24` @ 0x08390c24
/// (44 bytes, functions.csv's own size; verified against osos.asm and
/// osos.dec — the literal @ 0x8390c50 is 0x08adc2c0, the stats base).
///
/// The peak reader of the tag-57 tracked allocator's stats block, and
/// the COMPLETE function the ledger's 0x08390c30 entry
/// (`tracked_stats_reset_peak`) is the fall-through tail of:
///
/// ```text
/// stmdb sp!,{r4,lr}
/// mov r4,r0               ; reset flag
/// bl 0x082ccc74           ; arm the stats lock (scheduler-flag setter)
/// ldr r2,[lit 0x08adc2c0]
/// cmp r4,#0
/// ldrd r0,r1,[r2,#0x40]   ; peak into the return pair (PRE-reset)
/// ldrne r3,[r2,#0x38]     ; \
/// ldrne r12,[r2,#0x3c]    ;  } reset != 0: peak := current, word-wise
/// strne r3,[r2,#0x40]     ;  }
/// strne r12,[r2,#0x44]    ; /
/// ldmia sp!,{r4,pc}
/// ```
///
/// Arms the stats lock, then reads the high-water mark (stats + 0x40,
/// i64) with `ldrd` into the return pair BEFORE the conditional reset,
/// so the caller always gets the pre-reset peak; when `reset` is
/// nonzero it then copies the running counter (stats + 0x38, i64) over
/// the peak word by word. Because the tail is not a separate callee —
/// the head falls through into it — this port absorbs the 0x08390c30
/// tail rather than calling a fragment (unlike `tracked_alloc_tail`,
/// whose enclosing entry @ 0x08390b14 is genuinely unported).
///
/// Deviations:
///
/// - The accounting block is the `ALLOC_STATS` static instead of the
///   literal 0x08adc2c0 (module simplification, same as the rest of
///   heap/tracked).
/// - The lock callee @ 0x082ccc74 (ported as
///   [`tracked_stats_arm_lock`]) dispatches through the
///   [`TRACKED_STATS_OPS`]`.lock` slot (house ops-slot pattern, an
///   indirect call in place of `bl`) whose default is that port, same
///   as [`tracked_stats_current`], so host tests can swap in a
///   recorder.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_stats_peak(reset: i32) -> i64 {
    let lock = core::ptr::read_volatile(core::ptr::addr_of!(TRACKED_STATS_OPS.lock));
    lock();
    let stats = core::ptr::addr_of_mut!(ALLOC_STATS);
    let peak = (*stats).peak_bytes;
    if reset != 0 {
        (*stats).peak_bytes = (*stats).current_bytes;
    }
    peak
}

/// tracked_stats_current — original: `FUN_08390c54` @ 0x08390c54
/// (20 bytes; 1 `bl` call site @ 0x08391450).
///
/// The current-bytes reader of the tag-57 tracked allocator's stats
/// block, sibling of the peak reader/reset pair @ 0x08390c24 /
/// 0x08390c30. Verified against osos.asm: unlike that pair (an
/// envelope head carrying the lock call plus a tail fragment), this is
/// a COMPLETE function whose 20 bytes include the lock call inline —
/// `stmdb sp!,{r4,lr}; bl 0x082ccc74; ldr r1,[lit 0x08adc2c0];
/// ldrd r0,r1,[r1,#0x38]; ldmia sp!,{r4,pc}`. It arms the stats lock,
/// reads the running byte counter (stats + 0x38, i64) with `ldrd`,
/// and returns it in the r0:r1 pair.
///
/// Deviations:
///
/// - The accounting block is the `ALLOC_STATS` static instead of the
///   literal 0x08adc2c0 (module simplification, same as the rest of
///   heap/tracked).
/// - The lock callee @ 0x082ccc74 (scheduler-flag setter) is ported as
///   [`tracked_stats_arm_lock`]; the `bl` dispatches through the
///   [`TRACKED_STATS_OPS`]`.lock` slot (house ops-slot pattern, an
///   indirect call in place of `bl`) whose default is that port, so
///   host tests can still swap in a recorder.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_stats_current() -> i64 {
    let lock = core::ptr::read_volatile(core::ptr::addr_of!(TRACKED_STATS_OPS.lock));
    lock();
    let stats = core::ptr::addr_of!(ALLOC_STATS);
    (*stats).current_bytes
}

/// tracked_stats_set_soft_limit — original: `FUN_08390bf0` @ 0x08390bf0
/// (52 bytes; 1 `bl` call site @ 0x0839144c, inside the memory-pressure
/// reclaimer @ 0x08391408 — the init path reaches the same setter
/// through the thunk @ 0x0813eb3c with a 0x80000 limit).
///
/// The soft-limit setter of the tag-57 tracked allocator's stats block
/// (the ledger's "stats init"). Verified against osos.asm:
///
/// ```text
/// stmdb sp!,{r4,r5,r6,r7,r8,lr}
/// mov r7,r3 / mov r6,r2 / mov r5,r1 / mov r4,r0
/// bl 0x082ccc74             ; arm the stats lock
/// ldr r0,[lit 0x08adc2e0]   ; stats base + 0x20
/// strd r4,r5,[r0,#0x8]      ; callback @ +0x28, callback_arg @ +0x2c
/// sub r0,r0,#0x20
/// strd r6,r7,[r0,#0x20]     ; soft_limit @ +0x20 (i64)
/// mov r0,#0
/// ldmia sp!,{r4,r5,r6,r7,r8,pc}
/// ```
///
/// Everything it writes is consumed by the alloc side: the entry
/// @ 0x08390b14 warns when the callback word is nonzero and
/// `current_bytes + size` reaches `soft_limit`, and the warn helper
/// @ 0x0837d67c `blx`s the callback as
/// `callback(callback_arg, current_bytes, size)` under the +0x30
/// reentrancy guard. Returns 0.
///
/// Deviations:
///
/// - The accounting block is the `ALLOC_STATS` static instead of the
///   literal 0x08adc2c0 (module simplification, same as the rest of
///   heap/tracked).
/// - The callback and its argument arrive pointer-sized but are stored
///   as 32-bit words (the `strd` pair at +0x28), so on a 64-bit host
///   the store truncates — host tests use low sentinel values.
/// - The lock callee @ 0x082ccc74 (ported as
///   [`tracked_stats_arm_lock`]) dispatches through the
///   [`TRACKED_STATS_OPS`]`.lock` slot (house ops-slot pattern, an
///   indirect call in place of `bl`), same as
///   [`tracked_stats_current`], so host tests can swap in a recorder.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_stats_set_soft_limit(
    callback: *mut core::ffi::c_void,
    callback_arg: *mut core::ffi::c_void,
    soft_limit: i64,
) -> i32 {
    let lock = core::ptr::read_volatile(core::ptr::addr_of!(TRACKED_STATS_OPS.lock));
    lock();
    let stats = core::ptr::addr_of_mut!(ALLOC_STATS);
    (*stats).soft_limit_callback = callback as u32;
    (*stats).soft_limit_callback_arg = callback_arg as u32;
    (*stats).soft_limit = soft_limit;
    0
}

/// tracked_stats_warn_soft_limit — original: `FUN_0837d67c` @
/// 0x0837d67c (84 bytes; 4 call sites, all in the tag-57 tracked
/// allocator family: `blge` @ 0x08390b58 and `bl` @ 0x08390b84 in the
/// allocator entry @ 0x08390b14 — warn-before-retry and warn-on-OOM —
/// and `blge` @ 0x08390f50 and `bl` @ 0x08390f84 in the tracked realloc
/// @ 0x08390eec).
///
/// The soft-limit warn helper of the tracked allocator's stats block.
/// Verified against osos.asm and osos.dec (the literal @ 0x0837d6d0 is
/// 0x08adc2e0, stats base + 0x20):
///
/// ```text
/// stmdb sp!,{r3,r4,r5,lr}
/// ldr r4,[lit 0x08adc2e0]  ; stats base + 0x20
/// mov r3,r0                ; r3 = size
/// ldr r1,[r4,#0x8]         ; callback @ +0x28
/// cmp r1,#0
/// beq out                  ; no callback configured: done
/// ldr r0,[r4,#0x10]        ; reentrancy guard @ +0x30
/// cmp r0,#0
/// bne out                  ; already warning: done
/// mov r0,#1
/// str r0,[r4,#0x10]        ; guard = 1
/// sub r0,r4,#0x20          ; stats base
/// ldr r2,[r0,#0x38]        ; current_bytes, low word
/// ldr r12,[r0,#0x3c]       ; current_bytes, high word
/// ldr r0,[r4,#0xc]         ; callback_arg @ +0x2c
/// str r3,[sp,#0x0]         ; size -> stack argument
/// mov r3,r12
/// blx r1                   ; callback(callback_arg, current_bytes, size)
/// mov r0,#0
/// str r0,[r4,#0x10]        ; guard = 0
/// out: ldmia sp!,{r3,r4,r5,pc}
/// ```
///
/// With the callback word nonzero and the guard clear, sets the guard
/// and calls the callback as `callback(callback_arg, current_bytes,
/// size)`: AAPCS puts `callback_arg` in r0, the i64 `current_bytes` in
/// the aligned r2:r3 pair (r1 skipped — it still holds the callback
/// pointer, which is how Ghidra's decompile picked up its phantom
/// second argument) and `size` on the stack. The counter is read
/// word-wise AFTER the guard store, so the callback sees the pre-alloc
/// total and a nested warning from inside the callback is suppressed.
/// The guard is cleared on the way out.
///
/// Deviations:
///
/// - The accounting block is the `ALLOC_STATS` static instead of the
///   literal 0x08adc2c0 (module simplification, same as the rest of
///   heap/tracked).
/// - The `blx r1` dispatches through the
///   [`TRACKED_STATS_OPS`]`.invoke_soft_limit_callback` slot (house
///   ops-slot pattern, an indirect call in place of the original's
///   `blx`) whose default transmutes the callback word exactly like the
///   original; host tests swap in a recorder because a real code
///   address does not survive the u32 word on a 64-bit host.
/// - The guard word uses volatile accesses, same as `lock_flag` in
///   [`tracked_stats_arm_lock`]: it is cross-context state (the
///   callback runs under it) and plain accesses let LLVM's globalopt
///   narrow the word to a boolean byte, dropping the full-word
///   `str` of the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_stats_warn_soft_limit(size: i32) {
    let stats = core::ptr::addr_of_mut!(ALLOC_STATS);
    let callback = (*stats).soft_limit_callback;
    if callback == 0 {
        return;
    }
    let guard = core::ptr::addr_of_mut!((*stats).soft_limit_callback_active);
    if guard.read_volatile() != 0 {
        return;
    }
    guard.write_volatile(1);
    let current_bytes = (*stats).current_bytes;
    let callback_arg = (*stats).soft_limit_callback_arg;
    let invoke = core::ptr::read_volatile(core::ptr::addr_of!(
        TRACKED_STATS_OPS.invoke_soft_limit_callback
    ));
    invoke(callback, callback_arg, current_bytes, size);
    guard.write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use std::sync::MutexGuard;

    const ARENA_SIZE: usize = 4096;

    #[repr(C, align(32))]
    struct Arena([u8; ARENA_SIZE]);

    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);
    static mut ARENA_USED: usize = 0;
    static mut FREED: [*mut u8; 16] = [core::ptr::null_mut(); 16];
    static mut FREE_TAGS: [usize; 16] = [0; 16];
    static mut FREE_COUNT: usize = 0;
    static mut LAST_ALLOC_SIZE: usize = 0;
    static mut LAST_ALLOC_TAG: usize = 0;

    unsafe extern "C" fn arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        LAST_ALLOC_SIZE = size;
        LAST_ALLOC_TAG = tag;
        let used = ARENA_USED;
        let aligned = (size + 31) & !31;
        if used + aligned > ARENA_SIZE {
            return core::ptr::null_mut();
        }
        ARENA_USED = used + aligned;
        core::ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(used)
    }

    unsafe extern "C" fn arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        if FREE_COUNT < 16 {
            FREED[FREE_COUNT] = ptr;
            FREE_TAGS[FREE_COUNT] = tag;
            FREE_COUNT += 1;
        }
    }

    unsafe extern "C" fn arena_create(
        desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        desc as *mut HeapDescriptorDescriptor
    }

    /// One guard per test function — a second, shadowed guard would
    /// self-deadlock on the same mutex.
    fn arena() -> MutexGuard<'static, ()> {
        let guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            ARENA_USED = 0;
            FREE_COUNT = 0;
            LAST_ALLOC_SIZE = 0;
            LAST_ALLOC_TAG = 0;
            FREED = [core::ptr::null_mut(); 16];
            FREE_TAGS = [0; 16];
            ALLOC_STATS.soft_limit = 0;
            ALLOC_STATS.soft_limit_callback = 0;
            ALLOC_STATS.soft_limit_callback_arg = 0;
            ALLOC_STATS.soft_limit_callback_active = 0;
            ALLOC_STATS.lock_flag = 0;
            ALLOC_STATS.current_bytes = 0;
            ALLOC_STATS.peak_bytes = 0;
            let ops = core::ptr::addr_of_mut!(HEAP_OPS);
            (*ops).alloc = arena_alloc;
            (*ops).free = arena_free;
            (*ops).create = arena_create;
        }
        guard
    }

    unsafe fn freed() -> &'static [*mut u8] {
        let count = core::ptr::read(core::ptr::addr_of!(FREE_COUNT));
        core::slice::from_raw_parts(core::ptr::addr_of!(FREED).cast::<*mut u8>(), count)
    }

    /// Builds a tracked block exactly the way the allocator @ 0x08390b8c
    /// does, and returns (raw block, payload).
    /// `size` is only the recorded cookie; the arena always hands out a
    /// fixed 160 bytes so a negative cookie can be tested too.
    unsafe fn make_block(size: i32) -> (*mut u8, *mut u8) {
        let raw = arena_alloc(core::ptr::null_mut(), 160, TAG_TRACKED);
        assert!(!raw.is_null());
        (raw as *mut i32).write(size);
        (raw.add(4) as *mut i32).write(size >> 31);
        let base = raw.add(BLOCK_HEADER_SIZE);
        let payload = ((base as usize + 36) & !31) as *mut u8;
        (payload.sub(4) as *mut u32).write((payload as usize - base as usize) as u32);
        (raw, payload)
    }

    #[test]
    fn null_is_ignored() {
        let _guard = arena();
        unsafe {
            tracked_free(core::ptr::null_mut());
            tracked_free_pointer_array(core::ptr::null_mut());
            assert!(freed().is_empty());
            assert_eq!(ALLOC_STATS.current_bytes, 0);
        }
    }

    #[test]
    fn frees_the_raw_block_with_tag_fifty_seven() {
        let _guard = arena();
        unsafe {
            let (raw, payload) = make_block(100);
            ALLOC_STATS.current_bytes = 500;
            tracked_free(payload);
            assert_eq!(freed(), &[raw]);
            assert_eq!(FREE_TAGS[0], 57);
            assert_eq!(ALLOC_STATS.current_bytes, 400);
        }
    }

    /// The payload is 32-byte aligned and the padding is 4..=36 bytes, so
    /// the pad word always fits below it. Sweep every raw alignment the
    /// arena can produce.
    #[test]
    fn recovers_the_block_at_every_alignment() {
        let _guard = arena();
        unsafe {
            for skew in 0..8usize {
                ARENA_USED = skew * 4;
                let (raw, payload) = make_block(8);
                assert_eq!(payload as usize % 32, 0, "payload must be 32-aligned");
                let pad = payload as usize - (raw as usize + BLOCK_HEADER_SIZE);
                assert!((4..=36).contains(&pad), "pad={pad}");
                FREE_COUNT = 0;
                tracked_free(payload);
                assert_eq!(freed(), &[raw], "skew={skew}");
            }
        }
    }

    /// The size cookie is signed and widened to 64 bits
    /// (`sbc r1, r1, r2, asr #31`), so a negative cookie *raises* the
    /// counter.
    #[test]
    fn the_size_cookie_is_signed() {
        let _guard = arena();
        unsafe {
            let (_, payload) = make_block(-16);
            ALLOC_STATS.current_bytes = 0;
            tracked_free(payload);
            assert_eq!(ALLOC_STATS.current_bytes, 16);
        }
    }

    /// The subtraction borrows across the 32-bit boundary.
    #[test]
    fn the_counter_is_a_full_sixty_four_bit_subtract() {
        let _guard = arena();
        unsafe {
            let (_, payload) = make_block(1);
            ALLOC_STATS.current_bytes = 0x1_0000_0000;
            tracked_free(payload);
            assert_eq!(ALLOC_STATS.current_bytes, 0xffff_ffff);
        }
    }

    #[test]
    fn the_pointer_array_frees_every_element_then_itself() {
        let _guard = arena();
        unsafe {
            // Three tracked payloads, one NULL slot, then the array.
            let (raw_a, pay_a) = make_block(10);
            let (raw_b, pay_b) = make_block(20);
            let (raw_c, pay_c) = make_block(30);
            let (array_raw, array_payload) = make_block(64);
            let base = array_payload as *mut *mut u8;
            // base[0] = word count, base[1..] = elements.
            (base as *mut usize).write(5);
            base.add(1).write(pay_a);
            base.add(2).write(core::ptr::null_mut());
            base.add(3).write(pay_b);
            base.add(4).write(pay_c);

            ALLOC_STATS.current_bytes = 1000;
            tracked_free_pointer_array(base.add(1));

            // 10 + 20 + 30 + 64 subtracted; NULL slot skipped.
            assert_eq!(ALLOC_STATS.current_bytes, 1000 - 124);
            assert_eq!(freed(), &[raw_a, raw_b, raw_c, array_raw]);
        }
    }

    /// A count of 1 (or 0) means no elements — only the block is freed.
    #[test]
    fn an_empty_pointer_array_frees_only_itself() {
        let _guard = arena();
        unsafe {
            let (array_raw, array_payload) = make_block(16);
            let base = array_payload as *mut *mut u8;
            (base as *mut usize).write(1);
            tracked_free_pointer_array(base.add(1));
            assert_eq!(freed(), &[array_raw]);
        }
    }

    // ---- tracked_alloc_tail --------------------------------------------

    /// Recovers the raw block the way `tracked_free` does.
    unsafe fn raw_of(payload: *mut u8) -> *mut u8 {
        let pad = (payload.sub(4) as *const u32).read() as usize;
        payload.sub(pad).sub(BLOCK_HEADER_SIZE)
    }

    #[test]
    fn a_failed_retry_returns_null_and_touches_nothing() {
        let _guard = arena();
        unsafe {
            ARENA_USED = ARENA_SIZE; // heap is out
            ALLOC_STATS.current_bytes = 7;
            ALLOC_STATS.peak_bytes = 9;
            assert!(tracked_alloc_tail(16).is_null());
            assert_eq!(ALLOC_STATS.current_bytes, 7);
            assert_eq!(ALLOC_STATS.peak_bytes, 9);
        }
    }

    /// The request is size + 44 (8-byte header + up to 36 bytes of
    /// alignment padding + payload) with caller tag 57, and the returned
    /// payload is 32-aligned at every raw alignment the arena can produce.
    #[test]
    fn builds_the_block_the_free_path_undoes() {
        let _guard = arena();
        unsafe {
            for skew in 0..8usize {
                ARENA_USED = skew * 4;
                ALLOC_STATS.current_bytes = 0;
                ALLOC_STATS.peak_bytes = 0;
                let payload = tracked_alloc_tail(40);
                assert!(!payload.is_null(), "skew={skew}");
                assert_eq!(LAST_ALLOC_SIZE, 40 + 44);
                assert_eq!(LAST_ALLOC_TAG, TAG_TRACKED);
                assert_eq!(payload as usize % 32, 0, "payload must be 32-aligned");
                let raw = raw_of(payload);
                assert_eq!((raw as *const i32).read(), 40);
                assert_eq!((raw.add(4) as *const i32).read(), 0);
                let pad = payload as usize - (raw as usize + BLOCK_HEADER_SIZE);
                assert!((4..=36).contains(&pad), "skew={skew} pad={pad}");
                assert_eq!(
                    (payload.sub(4) as *const u32).read() as usize,
                    pad,
                    "pad word below the payload"
                );
            }
        }
    }

    #[test]
    fn adds_the_size_and_raises_the_peak_when_it_grew() {
        let _guard = arena();
        unsafe {
            ALLOC_STATS.current_bytes = 100;
            ALLOC_STATS.peak_bytes = 100;
            tracked_alloc_tail(64);
            assert_eq!(ALLOC_STATS.current_bytes, 164);
            assert_eq!(ALLOC_STATS.peak_bytes, 164, "peak follows current up");

            ALLOC_STATS.peak_bytes = 1000;
            tracked_alloc_tail(64);
            assert_eq!(ALLOC_STATS.current_bytes, 228);
            assert_eq!(ALLOC_STATS.peak_bytes, 1000, "peak is a high-water mark");
        }
    }

    /// The add sign-extends the 32-bit size into the 64-bit counter
    /// (`adc r1, r1, r5, asr #31`) and carries across the 32-bit boundary.
    #[test]
    fn the_counter_is_a_full_sixty_four_bit_add() {
        let _guard = arena();
        unsafe {
            ALLOC_STATS.current_bytes = 0xffff_ffff;
            ALLOC_STATS.peak_bytes = 0;
            tracked_alloc_tail(1);
            assert_eq!(ALLOC_STATS.current_bytes, 0x1_0000_0000);
            assert_eq!(ALLOC_STATS.peak_bytes, 0x1_0000_0000);
        }
    }

    // ---- tracked_stats_current ----------------------------------------

    /// `arena()` plus a restored stats ops table — one guard, no
    /// shadowed self-deadlock.
    fn stats() -> MutexGuard<'static, ()> {
        let guard = arena();
        unsafe { TRACKED_STATS_OPS = DEFAULT_TRACKED_STATS_OPS };
        guard
    }

    /// The whole i64 at stats+0x38 comes back: small, negative, and
    /// wider-than-32-bit values.
    #[test]
    fn returns_the_running_counter() {
        let _guard = stats();
        unsafe {
            ALLOC_STATS.current_bytes = 0x1234;
            assert_eq!(tracked_stats_current(), 0x1234);
            ALLOC_STATS.current_bytes = -7;
            assert_eq!(tracked_stats_current(), -7);
            ALLOC_STATS.current_bytes = 0x1_0000_0001;
            assert_eq!(tracked_stats_current(), 0x1_0000_0001);
        }
    }

    /// The lock runs before the read: the mock leaves its mark in the
    /// counter and the reader must return the value the lock set.
    #[test]
    fn calls_the_lock_before_reading() {
        static mut LOCK_CALLS: usize = 0;
        unsafe extern "C" fn mock_lock() {
            LOCK_CALLS += 1;
            ALLOC_STATS.current_bytes = 0x2a;
        }
        let _guard = stats();
        unsafe {
            LOCK_CALLS = 0;
            TRACKED_STATS_OPS.lock = mock_lock;
            assert_eq!(tracked_stats_current(), 0x2a);
            assert_eq!(LOCK_CALLS, 1);
        }
    }

    /// The wired default is the ported scheduler-flag setter: the
    /// reader arms the lock word (stats + 0x34) to 8 before returning
    /// the counter.
    #[test]
    fn the_default_lock_is_the_ported_arm() {
        let _guard = stats();
        unsafe {
            ALLOC_STATS.current_bytes = 99;
            assert_eq!(tracked_stats_current(), 99);
            assert_eq!(ALLOC_STATS.lock_flag, 8, "the default lock arms the flag");
        }
    }

    // ---- tracked_stats_peak (0x08390c24) -----------------------------

    /// The whole i64 at stats+0x40 comes back — small, negative and
    /// wider-than-32-bit values — and reset = 0 leaves both counters
    /// alone (`cmp r4,#0` guards the whole copy).
    #[test]
    fn returns_the_peak_and_leaves_it_alone_when_reset_is_clear() {
        let _guard = stats();
        unsafe {
            for peak in [0x1234i64, -7, 0x1_0000_0001, i64::MIN] {
                ALLOC_STATS.peak_bytes = peak;
                ALLOC_STATS.current_bytes = 42;
                assert_eq!(tracked_stats_peak(0), peak, "peak={peak:#x}");
                assert_eq!(ALLOC_STATS.peak_bytes, peak, "peak untouched");
                assert_eq!(ALLOC_STATS.current_bytes, 42, "current untouched");
            }
        }
    }

    /// A nonzero reset copies current(+0x38) over peak(+0x40) — the
    /// full i64, so wider-than-32-bit and negative currents survive —
    /// but the RETURNED peak is the pre-reset value: the `ldrd` at
    /// +0x40 runs before the conditional copy.
    #[test]
    fn reset_copies_current_over_peak_but_returns_the_pre_reset_peak() {
        let _guard = stats();
        unsafe {
            ALLOC_STATS.peak_bytes = 0x1_0000_0001;
            ALLOC_STATS.current_bytes = 0x2_0000_0002;
            assert_eq!(tracked_stats_peak(1), 0x1_0000_0001, "pre-reset peak");
            assert_eq!(ALLOC_STATS.peak_bytes, 0x2_0000_0002, "peak := current");
            assert_eq!(ALLOC_STATS.current_bytes, 0x2_0000_0002);

            ALLOC_STATS.peak_bytes = -5;
            ALLOC_STATS.current_bytes = -9;
            assert_eq!(tracked_stats_peak(-1), -5, "any nonzero resets");
            assert_eq!(ALLOC_STATS.peak_bytes, -9);
        }
    }

    /// The lock runs before the read AND the conditional copy: the mock
    /// leaves its marks in both counters and the reader must return and
    /// copy the values the lock set.
    #[test]
    fn calls_the_lock_before_reading_and_resetting() {
        static mut LOCK_CALLS: usize = 0;
        unsafe extern "C" fn mock_lock() {
            LOCK_CALLS += 1;
            ALLOC_STATS.peak_bytes = 0x2a;
            ALLOC_STATS.current_bytes = 0x5a;
        }
        let _guard = stats();
        unsafe {
            LOCK_CALLS = 0;
            TRACKED_STATS_OPS.lock = mock_lock;
            assert_eq!(tracked_stats_peak(1), 0x2a, "the lock's peak, read after it");
            assert_eq!(
                ALLOC_STATS.peak_bytes, 0x5a,
                "the lock's current, copied after it"
            );
            assert_eq!(LOCK_CALLS, 1);
        }
    }

    /// The wired default lock is the ported scheduler-flag setter, so
    /// the peak reader arms the flag (stats + 0x34) to 8 on its way in.
    #[test]
    fn the_default_lock_arms_the_flag_before_the_peak_read() {
        let _guard = stats();
        unsafe {
            ALLOC_STATS.peak_bytes = 99;
            assert_eq!(tracked_stats_peak(0), 99);
            assert_eq!(ALLOC_STATS.lock_flag, 8, "the default lock arms the flag");
        }
    }

    // ---- tracked_stats_set_soft_limit (0x08390bf0) ------------------

    /// The two pointer words and the i64 limit land at +0x28/+0x2c/+0x20
    /// and the return value is 0 (`mov r0, #0`).
    #[test]
    fn stores_the_callback_arg_and_limit_and_returns_zero() {
        let _guard = stats();
        unsafe {
            let result = tracked_stats_set_soft_limit(
                0x0835_e9a0 as *mut core::ffi::c_void,
                0x1122_3344 as *mut core::ffi::c_void,
                0x0008_0000,
            );
            assert_eq!(result, 0);
            assert_eq!(ALLOC_STATS.soft_limit_callback, 0x0835_e9a0);
            assert_eq!(ALLOC_STATS.soft_limit_callback_arg, 0x1122_3344);
            assert_eq!(ALLOC_STATS.soft_limit, 0x0008_0000);
        }
    }

    /// The limit is a full `strd` at +0x20: wider-than-32-bit and
    /// negative values survive.
    #[test]
    fn the_limit_is_a_full_sixty_four_bit_store() {
        let _guard = stats();
        unsafe {
            for limit in [0x1_0000_0001i64, -1, i64::MIN, 0] {
                tracked_stats_set_soft_limit(
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    limit,
                );
                assert_eq!(ALLOC_STATS.soft_limit, limit, "limit={limit:#x}");
            }
        }
    }

    /// The lock runs before the stores: the mock samples the limit word
    /// and must see the pre-call value.
    #[test]
    fn calls_the_lock_before_writing() {
        static mut LOCK_CALLS: usize = 0;
        static mut LIMIT_AT_LOCK: i64 = 0;
        unsafe extern "C" fn mock_lock() {
            LOCK_CALLS += 1;
            LIMIT_AT_LOCK = ALLOC_STATS.soft_limit;
        }
        let _guard = stats();
        unsafe {
            LOCK_CALLS = 0;
            ALLOC_STATS.soft_limit = 0x5a;
            TRACKED_STATS_OPS.lock = mock_lock;
            tracked_stats_set_soft_limit(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0x1234,
            );
            assert_eq!(LOCK_CALLS, 1);
            assert_eq!(LIMIT_AT_LOCK, 0x5a, "the lock ran before the stores");
            assert_eq!(ALLOC_STATS.soft_limit, 0x1234);
        }
    }

    /// The wired default lock is the ported scheduler-flag setter, so
    /// the setter arms the flag (stats + 0x34) to 8 on its way in.
    #[test]
    fn the_default_lock_arms_the_flag() {
        let _guard = stats();
        unsafe {
            tracked_stats_set_soft_limit(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0x8000,
            );
            assert_eq!(ALLOC_STATS.lock_flag, 8, "the default lock arms the flag");
        }
    }

    /// The counters, the peak and the reentrancy guard are not this
    /// function's business.
    #[test]
    fn leaves_the_counters_and_guard_untouched() {
        let _guard = stats();
        unsafe {
            ALLOC_STATS.current_bytes = 7;
            ALLOC_STATS.peak_bytes = 9;
            ALLOC_STATS.soft_limit_callback_active = 1;
            tracked_stats_set_soft_limit(
                0x1111_1111 as *mut core::ffi::c_void,
                0x2222_2222 as *mut core::ffi::c_void,
                0x3333_3333,
            );
            assert_eq!(ALLOC_STATS.current_bytes, 7);
            assert_eq!(ALLOC_STATS.peak_bytes, 9);
            assert_eq!(ALLOC_STATS.soft_limit_callback_active, 1);
        }
    }

    // ---- tracked_stats_warn_soft_limit (0x0837d67c) -----------------

    static mut INVOKE_CALLS: usize = 0;
    static mut INVOKE_CALLBACK: u32 = 0;
    static mut INVOKE_ARG: u32 = 0;
    static mut INVOKE_CURRENT: i64 = 0;
    static mut INVOKE_SIZE: i32 = 0;
    static mut GUARD_DURING_CALL: u32 = 0;

    unsafe extern "C" fn record_invoke(
        callback: u32,
        callback_arg: u32,
        current_bytes: i64,
        size: i32,
    ) {
        INVOKE_CALLS += 1;
        INVOKE_CALLBACK = callback;
        INVOKE_ARG = callback_arg;
        INVOKE_CURRENT = current_bytes;
        INVOKE_SIZE = size;
        GUARD_DURING_CALL = ALLOC_STATS.soft_limit_callback_active;
    }

    /// `stats()` plus a cleared recorder swapped into the invoke slot —
    /// one guard, no shadowed self-deadlock.
    fn warn() -> MutexGuard<'static, ()> {
        let guard = stats();
        unsafe {
            INVOKE_CALLS = 0;
            INVOKE_CALLBACK = 0;
            INVOKE_ARG = 0;
            INVOKE_CURRENT = 0;
            INVOKE_SIZE = 0;
            GUARD_DURING_CALL = 0;
            TRACKED_STATS_OPS.invoke_soft_limit_callback = record_invoke;
        }
        guard
    }

    /// `cmp r1,#0; beq out` — no callback configured means no call and
    /// the guard word is never touched.
    #[test]
    fn a_null_callback_is_a_no_op() {
        let _guard = warn();
        unsafe {
            ALLOC_STATS.soft_limit_callback = 0;
            ALLOC_STATS.soft_limit_callback_active = 0;
            tracked_stats_warn_soft_limit(0x100);
            assert_eq!(INVOKE_CALLS, 0);
            assert_eq!(ALLOC_STATS.soft_limit_callback_active, 0);
        }
    }

    /// `cmp r0,#0; bne out` — a set guard suppresses the call entirely
    /// and is left as it was (never cleared by the suppressed path).
    #[test]
    fn an_active_guard_suppresses_the_call() {
        let _guard = warn();
        unsafe {
            ALLOC_STATS.soft_limit_callback = 0x0835_e9a0;
            ALLOC_STATS.soft_limit_callback_active = 1;
            ALLOC_STATS.current_bytes = 0x2a;
            tracked_stats_warn_soft_limit(0x100);
            assert_eq!(INVOKE_CALLS, 0);
            assert_eq!(ALLOC_STATS.soft_limit_callback_active, 1, "guard untouched");
        }
    }

    /// The callback fires as `callback(callback_arg, current_bytes,
    /// size)` with the guard held at 1 for the whole call and cleared
    /// afterwards; the i64 counter crosses the 32-bit boundary whole.
    #[test]
    fn invokes_the_callback_under_the_guard() {
        let _guard = warn();
        unsafe {
            ALLOC_STATS.soft_limit_callback = 0x0835_e9a0;
            ALLOC_STATS.soft_limit_callback_arg = 0x1122_3344;
            ALLOC_STATS.current_bytes = 0x1_0000_0001;
            tracked_stats_warn_soft_limit(0x40);
            assert_eq!(INVOKE_CALLS, 1);
            assert_eq!(INVOKE_CALLBACK, 0x0835_e9a0, "the callback word itself");
            assert_eq!(INVOKE_ARG, 0x1122_3344);
            assert_eq!(INVOKE_CURRENT, 0x1_0000_0001, "the full i64 counter");
            assert_eq!(INVOKE_SIZE, 0x40);
            assert_eq!(GUARD_DURING_CALL, 1, "guard held across the call");
            assert_eq!(ALLOC_STATS.soft_limit_callback_active, 0, "cleared on return");
        }
    }

    /// The counter is read AFTER the guard store: a callback that
    /// samples the stats block sees guard = 1, and a nested warn from
    /// inside the callback is suppressed by its own guard.
    #[test]
    fn a_nested_warning_is_suppressed_by_the_guard() {
        unsafe extern "C" fn reentrant_invoke(
            _callback: u32,
            _callback_arg: u32,
            _current_bytes: i64,
            _size: i32,
        ) {
            INVOKE_CALLS += 1;
            GUARD_DURING_CALL = ALLOC_STATS.soft_limit_callback_active;
            // Nested warning: must hit the guard and return.
            tracked_stats_warn_soft_limit(8);
        }
        let _guard = warn();
        unsafe {
            TRACKED_STATS_OPS.invoke_soft_limit_callback = reentrant_invoke;
            ALLOC_STATS.soft_limit_callback = 0x0835_e9a0;
            ALLOC_STATS.current_bytes = 5;
            tracked_stats_warn_soft_limit(0x80);
            assert_eq!(INVOKE_CALLS, 1, "no recursive invoke");
            assert_eq!(GUARD_DURING_CALL, 1);
            assert_eq!(ALLOC_STATS.soft_limit_callback_active, 0);
        }
    }

    /// The wired default invoke slot is the transmuting `blx`: its
    /// identity is all a host test can check (calling it needs a real
    /// 32-bit code address, which only exists on target).
    #[test]
    fn the_default_invoke_slot_is_the_blx() {
        let _guard = stats();
        unsafe {
            let invoke = core::ptr::read_volatile(core::ptr::addr_of!(
                TRACKED_STATS_OPS.invoke_soft_limit_callback
            ));
            assert_eq!(invoke as usize, blx_soft_limit_callback as usize);
        }
    }

    // ---- tracked_stats_arm_lock (0x082ccc74) -------------------------

    /// A clear lock word is armed to 8 (`cmp r1,#0; moveq r1,#8;
    /// streq r1,[r0,#0x14]`).
    #[test]
    fn arms_a_clear_flag_to_eight() {
        let _guard = arena();
        unsafe {
            assert_eq!(ALLOC_STATS.lock_flag, 0);
            tracked_stats_arm_lock();
            assert_eq!(ALLOC_STATS.lock_flag, 8);
        }
    }

    /// One-way arm: an already-armed (or any non-zero) flag is left
    /// untouched, and a second call is a no-op.
    #[test]
    fn never_overwrites_a_nonzero_flag() {
        let _guard = arena();
        unsafe {
            for value in [8u32, 1, 0xdead_beef] {
                ALLOC_STATS.lock_flag = value;
                tracked_stats_arm_lock();
                assert_eq!(ALLOC_STATS.lock_flag, value, "value={value:#x}");
            }
            ALLOC_STATS.lock_flag = 0;
            tracked_stats_arm_lock();
            tracked_stats_arm_lock();
            assert_eq!(ALLOC_STATS.lock_flag, 8, "second arm is a no-op");
        }
    }
}
