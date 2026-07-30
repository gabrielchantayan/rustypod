//! The counting-semaphore cluster and its interrupt-safe atomics: the
//! RAM-side layer that turns a bare RTXC waiter object (kernel/kobj.rs)
//! into a counting semaphore, plus the cpsr save helper the atomics build
//! their critical sections from.
//!
//! Originals (all sizes/call sites verified against osos.dec, not just
//! osos.asm — the disassembly listing drops occasional lines):
//!
//! - `irq_save` — helper @ 0x081b02b8 (24 bytes; 2 call sites, both
//!   atomics below). `mrs r1, cpsr; and r2, r1, #0xc0; orr r1, r1, #0xc0;
//!   str r2, [r0]; msr cpsr_c, r1; bx lr` — masks IRQ **and** FIQ and
//!   stores the *previous* I/F bits (cpsr & 0xc0) through the out-pointer
//!   in r0. It does not return a value in r0; the caller passes a stack
//!   slot.
//! - `atomic_add_irqsafe` — `FUN_08056328` @ 0x08056328 (60 bytes; 4 call
//!   sites: 0x080567b8, 0x080567e0, csem_wait's timeout undo @ 0x08056948,
//!   and the bare alias thunk `b` @ 0x080f041c — a line osos.asm omits).
//!   irq_save into a stack slot, `old = *ptr; *ptr = old + amount`, then
//!   the inline restore sequence `mrs; bic #0xc0; orr saved; msr cpsr_c`
//!   merges the saved I/F bits back, returns `old`. Argument order is
//!   r0 = amount, r1 = ptr.
//! - `atomic_sub_irqsafe` — `FUN_08056364` @ 0x08056364 (60 bytes; 3 call
//!   sites: csem_wait @ 0x08056918, csem_signal @ 0x0805698c, alias thunk
//!   @ 0x080f0420). Twin with `*ptr = old - amount`.
//! - `csem_wait` — `FUN_08056904` @ 0x08056904 (88 bytes; 1 call site,
//!   0x080b4ae4 in the queue-get wrapper `FUN_080b4adc`). P operation:
//!   `old = atomic_sub_irqsafe(1, &count)`; if `old - 1 < 0` (signed — no
//!   token was available) it sleeps on the waiter id via thunk 0x08037ea0
//!   -> ROM 0x220043c0 with the timeout (zero clamped to 1 tick); RTXC
//!   return code 5 (timeout) undoes the decrement with
//!   `atomic_add_irqsafe(1, &count)` and returns 1, any other code (woken)
//!   returns 0.
//! - `csem_signal` — `FUN_0805697c` @ 0x0805697c (40 bytes; 2 call sites:
//!   tail `b` @ 0x0808e2b4 in the deref wrapper `FUN_0808e2b0`, `bl` @
//!   0x080bbb90). `old = atomic_sub_irqsafe(1, &count)`; if `old - 1 < 0`
//!   it tail-branches thunk 0x08037ea8 -> ROM 0x22004368 with the waiter
//!   id (wake the sleeper). NAMING CORRECTION: earlier scouting notes
//!   (and the prior names.yaml entry) claimed the signal side *adds*; the
//!   binary word @ 0x0805698c is `ebfffe74` = `bl 0x08056364` — the SUB
//!   twin — and the wake condition is on the count going negative. Both
//!   halves decrement; the count is a fast-path heuristic (positive =
//!   skip the ROM), and once it has drifted negative every wait parks and
//!   every signal wakes, so the pair still behaves as a wait/notify
//!   event. The ROM keeps the real signaled state.
//! - `csem_wake` — `thunk_EXT_FUN_22004368` @ 0x080569a4 (4 bytes;
//!   2 call sites, 0x080eda08 / 0x0810789c): bare `b 0x08037ea8`, the raw
//!   ROM wake with r0 = waiter id, no count bookkeeping.
//! - `csem_post` — `FUN_080567a8` @ 0x080567a8 (40 bytes; 2 call
//!   sites: tail `b` @ 0x0808e2ac in the deref wrapper `FUN_0808e2a8`,
//!   `bl` @ 0x080b26b8). The classic add-and-wake V op:
//!   `old = atomic_add_irqsafe(1, &count)`; if `old + 1 == 0` (the
//!   original's `adds r0, r0, #1` + EQ — old exactly -1, a single
//!   sleeper may be parked) it tail-branches thunk 0x08037e78 -> ROM
//!   0x220041cc with the waiter id. BINARY-VERIFIED CORRECTION to the
//!   scouting notes: the wake target is kobj's waiter-signal entry
//!   (ported as `kobj::waiter_wake` @ 0x080567f8, the bare alias of
//!   the same thunk), NOT thunk 0x08037ea8 / ROM 0x22004368
//!   (CSEM_ROM_WAKE, which only csem_signal/csem_wake use), and the
//!   wake condition is equality with -1, not a signed < 0.
//! - `csem_post_deferred` — (no Ghidra name; absent from functions.csv,
//!   extent verified from osos.asm) @ 0x080567d0 (40 bytes; 1 call
//!   site: the tail `b` @ 0x080c692c of the deref wrapper
//!   `FUN_080c6928`, whose Ghidra decomp is this function verbatim).
//!   Instruction-for-instruction twin of `csem_post` except the wake
//!   tail-branches thunk 0x08037e80 -> ROM 0x22001cbc: under the
//!   kernel lock the ROM walks a pending-id table (mirror 0x08001cbc)
//!   and appends the waiter id if not already present, instead of
//!   invoking the gateway signal stub directly — a deferred-wake
//!   flavor of the same V op (the name is inferred from that
//!   difference). Routed through the ported
//!   `task_lock::rom_svc_22001cbc`.
//!
//! # The interrupt-masking boundary (deviation, by necessity)
//!
//! cpsr is reached through the two `#[inline(always)]` primitives
//! `cpsr_read`/`cpsr_write_c`, cfg-gated on `target_arch = "arm"`:
//!
//! - On ARM they are the real `mrs {r}, cpsr` / `msr cpsr_c, {r}` inline
//!   asm (default asm options, so they double as compiler barriers — the
//!   `*ptr` update cannot be hoisted out of the masked window), and
//!   `irq_save`/the atomics compile to the original instruction sequence.
//! - On host builds no real interrupt masking is possible. The primitives
//!   operate on a simulated cpsr word (`host_cpsr::MOCK_CPSR`), and every
//!   control-field write is appended to `host_cpsr::WRITE_LOG` so tests
//!   can assert the mask/restore protocol (exactly two writes per atomic:
//!   first with I|F set, then the original bits merged back). This proves
//!   the save/restore arithmetic, NOT real atomicity against interrupts —
//!   that property only exists on target.
//!
//! # Other deviations
//!
//! - The sleep goes through the ported `kobj::waiter_wait` instead of
//!   calling thunk 0x08037ea0 directly: the wrapper performs the identical
//!   zero->1 timeout clamp and returns 1 exactly on RTXC code 5, which is
//!   the exact comparison csem_wait makes, so behavior is unchanged and
//!   the ROM boundary stays the single `KOBJ_HOOKS.rom_waiter_wait` slot.
//! - ROM 0x22004368 (the wake) is a genuinely new ROM entry point (it is
//!   NOT kobj's rom_waiter_signal @ 0x220041cc), so it gets its own
//!   dispatch slot `CSEM_ROM_WAKE` (default: no-op, like kobj's missing
//!   wake stub; volatile read so LLVM cannot fold the stub in).
//! - The original reads `*ptr` twice back to back (`ldr r0; ldr r1`);
//!   with interrupts masked both loads see the same value, so the port
//!   reads once.

use crate::kernel::kobj::{waiter_wait, waiter_wake};

/// The I and F bits of cpsr (0x80 = IRQ disable, 0x40 = FIQ disable) —
/// the `#0xc0` immediate throughout the original sequences.
pub const CPSR_IF_MASK: u32 = 0xc0;

/// Counting semaphore, 8 bytes, original layout: signed count word +
/// waiter-object id (kernel/kobj.rs `waiter_create`).
#[repr(C)]
pub struct CountingSem {
    /// +0x00: token count. Positive = wait takes a token without touching
    /// the ROM; zero/negative = wait parks, signal wakes (see the module
    /// header on the drift semantics).
    pub count: i32,
    /// +0x04: RTXC waiter-object id slept on / woken.
    pub waiter_id: u32,
}

// ---------------------------------------------------------------------------
// cpsr access primitives (the hardware boundary; see the module header).
// ---------------------------------------------------------------------------

/// `mrs {r}, cpsr` (host: reads the simulated word).
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn cpsr_read() -> u32 {
    let value: u32;
    core::arch::asm!("mrs {}, cpsr", out(reg) value, options(nostack, preserves_flags));
    value
}

/// `msr cpsr_c, {r}` — writes the control field only (mode + I/F/T bits),
/// leaving the condition flags alone (host: merges bits 0..7 into the
/// simulated word and logs the write).
#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn cpsr_write_c(value: u32) {
    core::arch::asm!("msr cpsr_c, {}", in(reg) value, options(nostack, preserves_flags));
}

/// Host-side simulated cpsr (see the module header: the host build cannot
/// mask real interrupts; tests assert the protocol against this state).
#[cfg(not(target_arch = "arm"))]
pub(crate) mod host_cpsr {
    /// The simulated cpsr word.
    pub static mut MOCK_CPSR: u32 = 0;
    /// Every value passed to `cpsr_write_c`, in order.
    pub static mut WRITE_LOG: [u32; 8] = [0; 8];
    /// Number of valid entries in [`WRITE_LOG`].
    pub static mut WRITE_COUNT: usize = 0;
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn cpsr_read() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(host_cpsr::MOCK_CPSR))
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn cpsr_write_c(value: u32) {
    use core::ptr::{addr_of, addr_of_mut};
    // `msr cpsr_c` only writes the control field (bits 0..7).
    let merged = (cpsr_read() & !0xff) | (value & 0xff);
    core::ptr::write_volatile(addr_of_mut!(host_cpsr::MOCK_CPSR), merged);
    let count = core::ptr::read_volatile(addr_of!(host_cpsr::WRITE_COUNT));
    if count < 8 {
        (*addr_of_mut!(host_cpsr::WRITE_LOG))[count] = value;
        core::ptr::write_volatile(addr_of_mut!(host_cpsr::WRITE_COUNT), count + 1);
    }
}

/// irq_save — original: helper @ 0x081b02b8 (24 bytes).
///
/// Disables IRQ and FIQ and stores the previous I/F bits (cpsr & 0xc0)
/// through `saved` — an out-pointer, exactly like the original's r0 (the
/// function returns nothing in r0). Restore is the inline sequence
/// [`irq_restore`], which the original duplicates in each atomic.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn irq_save(saved: *mut u32) {
    let cpsr = cpsr_read();
    *saved = cpsr & CPSR_IF_MASK;
    cpsr_write_c(cpsr | CPSR_IF_MASK);
}

/// The restore sequence the original inlines after each critical section
/// (`mrs; bic #0xc0; orr saved; msr cpsr_c`): merges the saved I/F bits
/// into the current cpsr, leaving every other bit as it is now.
#[inline(always)]
unsafe fn irq_restore(saved: u32) {
    let cpsr = cpsr_read();
    cpsr_write_c((cpsr & !CPSR_IF_MASK) | saved);
}

// ---------------------------------------------------------------------------
// Interrupt-safe atomics.
// ---------------------------------------------------------------------------

/// atomic_add_irqsafe — original: `FUN_08056328` @ 0x08056328 (60 bytes).
///
/// With IRQ/FIQ masked: `old = *ptr; *ptr = old + amount` (wrapping, as
/// ARM `add`), then restores the previous I/F bits and returns `old`.
/// Argument order is the original's (r0 = amount, r1 = ptr).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn atomic_add_irqsafe(amount: i32, ptr: *mut i32) -> i32 {
    let mut saved: u32 = 0;
    irq_save(&mut saved);
    let old = *ptr;
    *ptr = old.wrapping_add(amount);
    irq_restore(saved);
    old
}

/// atomic_sub_irqsafe — original: `FUN_08056364` @ 0x08056364 (60 bytes).
///
/// Twin of [`atomic_add_irqsafe`] with `*ptr = old - amount`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn atomic_sub_irqsafe(amount: i32, ptr: *mut i32) -> i32 {
    let mut saved: u32 = 0;
    irq_save(&mut saved);
    let old = *ptr;
    *ptr = old.wrapping_sub(amount);
    irq_restore(saved);
    old
}

// ---------------------------------------------------------------------------
// The counting semaphore.
// ---------------------------------------------------------------------------

/// ROM wake @ 0x22004368 (thunk 0x08037ea8): wakes the sleeper of the
/// waiter object `id`. A different ROM entry from kobj's rom_waiter_signal
/// (0x220041cc); its exact RTXC service is unidentified beyond "wake" —
/// pairing with the 0x220043c0 sleep is what the call sites record.
pub static mut CSEM_ROM_WAKE: unsafe extern "C" fn(id: u32) = missing_rom_csem_wake;

/// Default stub: waking into a nonexistent kernel is a harmless no-op
/// (same contract as kobj's missing wake stub).
unsafe extern "C" fn missing_rom_csem_wake(_id: u32) {}

/// Reads the wake slot (volatile — see the module header).
#[inline(always)]
fn rom_wake() -> unsafe extern "C" fn(id: u32) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CSEM_ROM_WAKE)) }
}

/// csem_wait — original: `FUN_08056904` @ 0x08056904 (88 bytes).
///
/// P operation: takes a token with [`atomic_sub_irqsafe`]; when none was
/// available (the count went negative — signed check on `old - 1`,
/// wrapping like the original's `subs`) it sleeps on the waiter id for up
/// to `timeout` ticks (zero clamped to 1). A timed-out sleep (RTXC code
/// 5) undoes the decrement and returns 1; a wakeup returns 0, leaving the
/// decrement in place.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn csem_wait(csem: *mut CountingSem, timeout: u32) -> u32 {
    let old = atomic_sub_irqsafe(1, core::ptr::addr_of_mut!((*csem).count));
    if old.wrapping_sub(1) < 0 {
        if waiter_wait((*csem).waiter_id, timeout) == 1 {
            atomic_add_irqsafe(1, core::ptr::addr_of_mut!((*csem).count));
            return 1;
        }
    }
    0
}

/// csem_signal — original: `FUN_0805697c` @ 0x0805697c (40 bytes).
///
/// Wake side: decrements the count (sic — binary-verified, see the module
/// header's naming correction) and, when it went negative (a sleeper may
/// be parked), wakes the waiter object via ROM 0x22004368.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn csem_signal(csem: *mut CountingSem) {
    let old = atomic_sub_irqsafe(1, core::ptr::addr_of_mut!((*csem).count));
    if old.wrapping_sub(1) < 0 {
        (rom_wake())((*csem).waiter_id);
    }
}

/// csem_wake — original: `thunk_EXT_FUN_22004368` @ 0x080569a4 (4 bytes).
///
/// Bare tail branch onto the ROM wake with a raw waiter id — no count
/// bookkeeping.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn csem_wake(id: u32) {
    (rom_wake())(id);
}

/// csem_post — original: `FUN_080567a8` @ 0x080567a8 (40 bytes).
///
/// The classic V operation: returns a token with
/// [`atomic_add_irqsafe`] and, when the count was exactly -1 (the
/// original's `adds r0, r0, #1` + EQ — one sleeper may be parked),
/// wakes the waiter object via thunk 0x08037e78 -> ROM 0x220041cc.
/// The wake goes through the ported [`waiter_wake`] (kobj's waiter
/// signal), NOT the [`CSEM_ROM_WAKE`] slot — binary-verified, see the
/// module header's correction note.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn csem_post(csem: *mut CountingSem) {
    let old = atomic_add_irqsafe(1, core::ptr::addr_of_mut!((*csem).count));
    if old.wrapping_add(1) == 0 {
        waiter_wake((*csem).waiter_id);
    }
}

/// csem_post_deferred — original: (no Ghidra name; absent from
/// functions.csv, extent verified from osos.asm) @ 0x080567d0 (40 bytes).
///
/// Instruction-for-instruction twin of [`csem_post`]: returns a token
/// with [`atomic_add_irqsafe`] and, when the count was exactly -1 (the
/// original's `adds r0, r0, #1` + EQ — one sleeper may be parked),
/// wakes the waiter object. The only difference is the wake target:
/// thunk 0x08037e80 -> ROM 0x22001cbc, a full ROM function that under
/// the kernel lock appends the waiter id to a pending-id table
/// (mirror 0x08001cbc) instead of the gateway signal stub — a
/// deferred-wake flavor, routed through the ported
/// [`crate::kernel::task_lock::rom_svc_22001cbc`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn csem_post_deferred(csem: *mut CountingSem) {
    let old = atomic_add_irqsafe(1, core::ptr::addr_of_mut!((*csem).count));
    if old.wrapping_add(1) == 0 {
        crate::kernel::task_lock::rom_svc_22001cbc((*csem).waiter_id as usize);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::kobj::{KobjHooks, DEFAULT_KOBJ_HOOKS, KOBJ_HOOKS};
    use crate::kernel::task_lock::{self, RomThunkOps};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::MutexGuard;
    use std::vec;
    use std::vec::Vec;

    // Mock ROM sleep/wake state (guarded by kobj's HOOKS_LOCK, which also
    // serializes the KOBJ_HOOKS swap against kobj's own tests).
    static mut SLEEP_LOG: Vec<(u32, u32)> = Vec::new();
    static mut SLEEP_RC: u32 = 0;
    static mut WAKE_LOG: Vec<u32> = Vec::new();
    // Mock of ROM 0x22001cbc (csem_post_deferred's wake), riding
    // task_lock's ROM_KERNEL table (its OPS_LOCK serializes the swap
    // against task_lock's own tests).
    static mut DEFERRED_WAKE_LOG: Vec<u32> = Vec::new();

    unsafe extern "C" fn mock_rom_sleep(id: u32, timeout: u32) -> u32 {
        (*addr_of_mut!(SLEEP_LOG)).push((id, timeout));
        *addr_of!(SLEEP_RC)
    }

    unsafe extern "C" fn mock_wake(id: u32) {
        (*addr_of_mut!(WAKE_LOG)).push(id);
    }

    unsafe extern "C" fn mock_deferred_wake(id: usize) -> usize {
        (*addr_of_mut!(DEFERRED_WAKE_LOG)).push(id as u32);
        0
    }

    /// RTXC return code 5 — the ROM sleep timed out.
    const RC_TIMEOUT: u32 = 5;
    /// Any non-5 code — the sleeper was woken.
    const RC_WOKEN: u32 = 0;

    /// Installs the cpsr simulation + mock ROM sleep/wake under kobj's
    /// hook lock, plus the deferred-wake mock in task_lock's ROM_KERNEL
    /// under its OPS_LOCK, and returns both guards with the saved table.
    /// Lock order is always HOOKS_LOCK then OPS_LOCK (no other module
    /// takes both, so no cycle).
    fn install(
        initial_cpsr: u32,
        sleep_rc: u32,
    ) -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, RomThunkOps) {
        let guard = crate::kernel::kobj::tests::HOOKS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let task_lock_guard = crate::kernel::task_lock::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            *addr_of_mut!(host_cpsr::MOCK_CPSR) = initial_cpsr;
            *addr_of_mut!(host_cpsr::WRITE_COUNT) = 0;
            (*addr_of_mut!(SLEEP_LOG)).clear();
            *addr_of_mut!(SLEEP_RC) = sleep_rc;
            (*addr_of_mut!(WAKE_LOG)).clear();
            (*addr_of_mut!(DEFERRED_WAKE_LOG)).clear();
            addr_of_mut!(KOBJ_HOOKS).write(KobjHooks {
                rom_waiter_wait: mock_rom_sleep,
                rom_waiter_signal: mock_wake,
                ..DEFAULT_KOBJ_HOOKS
            });
            *addr_of_mut!(CSEM_ROM_WAKE) = mock_wake;
            let saved = core::ptr::read_volatile(addr_of!(task_lock::ROM_KERNEL));
            let mut patched = saved;
            patched.rom_svc_22001cbc = mock_deferred_wake;
            addr_of_mut!(task_lock::ROM_KERNEL).write(patched);
            (guard, task_lock_guard, saved)
        }
    }

    /// Restores the defaults; takes the guards by value so they drop last
    /// (house pattern, see stdio/seek_core.rs).
    fn restore(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>, RomThunkOps)) {
        unsafe {
            addr_of_mut!(KOBJ_HOOKS).write(DEFAULT_KOBJ_HOOKS);
            *addr_of_mut!(CSEM_ROM_WAKE) = missing_rom_csem_wake;
            addr_of_mut!(task_lock::ROM_KERNEL).write(guards.2);
        }
        drop(guards);
    }

    fn cpsr() -> u32 {
        unsafe { *addr_of!(host_cpsr::MOCK_CPSR) }
    }

    fn cpsr_writes() -> Vec<u32> {
        unsafe {
            let log: [u32; 8] = *addr_of!(host_cpsr::WRITE_LOG);
            log[..*addr_of!(host_cpsr::WRITE_COUNT)].to_vec()
        }
    }

    fn sleeps() -> Vec<(u32, u32)> {
        unsafe { (*addr_of!(SLEEP_LOG)).clone() }
    }

    fn wakes() -> Vec<u32> {
        unsafe { (*addr_of!(WAKE_LOG)).clone() }
    }

    fn deferred_wakes() -> Vec<u32> {
        unsafe { (*addr_of!(DEFERRED_WAKE_LOG)).clone() }
    }

    fn csem(count: i32, waiter_id: u32) -> CountingSem {
        CountingSem { count, waiter_id }
    }

    // ---- irq_save / irq_restore ------------------------------------------

    #[test]
    fn irq_save_reports_previous_if_bits_and_masks_both() {
        // SVC mode 0x13 with flags set; sweep all four I/F combinations.
        let guard = install(0, 0);
        for bits in [0x00u32, 0x40, 0x80, 0xc0] {
            let initial = 0x6000_0013 | bits;
            unsafe {
                *addr_of_mut!(host_cpsr::MOCK_CPSR) = initial;
                let mut saved: u32 = 0xdead_beef;
                irq_save(&mut saved);
                assert_eq!(saved, bits, "saved = old cpsr & 0xc0");
            }
            assert_eq!(
                cpsr(),
                0x6000_00d3,
                "I and F both set, flags/mode untouched"
            );
        }
        restore(guard);
    }

    #[test]
    fn atomics_mask_then_restore_the_exact_bits() {
        // Initial: IRQ masked, FIQ open (0x80) — a real mid-boot state.
        let initial = 0x6000_0093u32;
        let guard = install(initial, 0);
        let mut word: i32 = 7;
        unsafe {
            atomic_add_irqsafe(3, &mut word);
        }
        // Exactly two control-field writes: mask (I|F on top of the old
        // word), then the merge of the saved bits into the masked cpsr.
        assert_eq!(cpsr_writes(), vec![initial | 0xc0, initial]);
        assert_eq!(cpsr(), initial, "cpsr fully restored");
        restore(guard);
    }

    #[test]
    fn atomic_restore_keeps_if_bits_saved_not_current() {
        // All-open initial state: after the masked window the restore must
        // drop back to open, not keep the mask.
        let initial = 0x0000_0013u32;
        let guard = install(initial, 0);
        let mut word: i32 = 0;
        unsafe {
            atomic_sub_irqsafe(1, &mut word);
        }
        assert_eq!(cpsr_writes(), vec![initial | 0xc0, initial]);
        assert_eq!(cpsr() & 0xc0, 0, "both interrupt sources reopened");
        restore(guard);
    }

    // ---- the atomics vs a reference model --------------------------------

    #[test]
    fn atomic_add_returns_old_and_stores_wrapping_sum() {
        let guard = install(0x13, 0);
        let cases: &[(i32, i32)] = &[
            (0, 5),
            (1, 0),
            (-1, 3),
            (3, -4),
            (i32::MAX, 1),
            (i32::MIN, -1),
            (100, i32::MAX),
        ];
        for &(value, amount) in cases {
            let mut word = value;
            let old = unsafe { atomic_add_irqsafe(amount, &mut word) };
            assert_eq!(old, value, "returns the pre-add value");
            assert_eq!(word, value.wrapping_add(amount), "wrapping ARM add");
        }
        restore(guard);
    }

    #[test]
    fn atomic_sub_returns_old_and_stores_wrapping_difference() {
        let guard = install(0x13, 0);
        let cases: &[(i32, i32)] = &[
            (0, 5),
            (1, 1),
            (-1, -3),
            (i32::MIN, 1),
            (i32::MAX, -1),
            (0, i32::MIN),
        ];
        for &(value, amount) in cases {
            let mut word = value;
            let old = unsafe { atomic_sub_irqsafe(amount, &mut word) };
            assert_eq!(old, value, "returns the pre-sub value");
            assert_eq!(word, value.wrapping_sub(amount), "wrapping ARM sub");
        }
        restore(guard);
    }

    // ---- csem_wait --------------------------------------------------------

    #[test]
    fn wait_with_tokens_takes_one_without_the_rom() {
        let guard = install(0x13, RC_TIMEOUT);
        let mut sem = csem(2, 0x42);
        unsafe {
            assert_eq!(csem_wait(&mut sem, 100), 0);
        }
        assert_eq!(sem.count, 1);
        assert!(sleeps().is_empty(), "token available: no sleep");
        restore(guard);
    }

    #[test]
    fn wait_boundary_last_token_still_no_sleep() {
        // old = 1 -> old-1 = 0, which is NOT negative (bpl in the
        // original): the last token is taken without sleeping.
        let guard = install(0x13, RC_TIMEOUT);
        let mut sem = csem(1, 0x42);
        unsafe {
            assert_eq!(csem_wait(&mut sem, 100), 0);
        }
        assert_eq!(sem.count, 0);
        assert!(sleeps().is_empty());
        restore(guard);
    }

    #[test]
    fn wait_on_empty_sem_sleeps_and_keeps_decrement_when_woken() {
        let guard = install(0x13, RC_WOKEN);
        let mut sem = csem(0, 0x42);
        unsafe {
            assert_eq!(csem_wait(&mut sem, 250), 0, "woken = success");
        }
        assert_eq!(sem.count, -1, "no undo on wakeup");
        assert_eq!(sleeps(), vec![(0x42, 250)]);
        restore(guard);
    }

    #[test]
    fn wait_timeout_undoes_the_decrement_and_returns_1() {
        let guard = install(0x13, RC_TIMEOUT);
        let mut sem = csem(0, 0x42);
        unsafe {
            assert_eq!(csem_wait(&mut sem, 250), 1, "RTXC code 5 = timeout");
        }
        assert_eq!(sem.count, 0, "decrement undone");
        assert_eq!(sleeps(), vec![(0x42, 250)]);
        restore(guard);
    }

    #[test]
    fn wait_clamps_zero_timeout_to_one_tick() {
        let guard = install(0x13, RC_WOKEN);
        let mut sem = csem(-2, 0x77);
        unsafe {
            assert_eq!(csem_wait(&mut sem, 0), 0);
        }
        assert_eq!(sleeps(), vec![(0x77, 1)], "0 ticks becomes 1");
        assert_eq!(sem.count, -3, "negative counts keep drifting down");
        restore(guard);
    }

    #[test]
    fn wait_timeout_on_drifted_count_restores_it_exactly() {
        let guard = install(0x13, RC_TIMEOUT);
        let mut sem = csem(-5, 0x77);
        unsafe {
            assert_eq!(csem_wait(&mut sem, 10), 1);
        }
        assert_eq!(sem.count, -5, "-6 undone back to -5");
        restore(guard);
    }

    // ---- csem_signal ------------------------------------------------------

    #[test]
    fn signal_with_tokens_only_decrements() {
        let guard = install(0x13, 0);
        let mut sem = csem(2, 0x42);
        unsafe {
            csem_signal(&mut sem);
        }
        assert_eq!(sem.count, 1);
        assert!(wakes().is_empty(), "old-1 = 1 is positive: no wake");
        restore(guard);
    }

    #[test]
    fn signal_boundary_count_one_no_wake() {
        // old = 1 -> old-1 = 0: pl in the original, so still no wake.
        let guard = install(0x13, 0);
        let mut sem = csem(1, 0x42);
        unsafe {
            csem_signal(&mut sem);
        }
        assert_eq!(sem.count, 0);
        assert!(wakes().is_empty());
        restore(guard);
    }

    #[test]
    fn signal_on_empty_sem_wakes_the_sleeper() {
        let guard = install(0x13, 0);
        let mut sem = csem(0, 0x1234);
        unsafe {
            csem_signal(&mut sem);
        }
        assert_eq!(sem.count, -1);
        assert_eq!(wakes(), vec![0x1234], "wake carries the waiter id");
        restore(guard);
    }

    #[test]
    fn signal_on_negative_count_keeps_waking() {
        let guard = install(0x13, 0);
        let mut sem = csem(-4, 0x1234);
        unsafe {
            csem_signal(&mut sem);
        }
        assert_eq!(sem.count, -5);
        assert_eq!(wakes(), vec![0x1234]);
        restore(guard);
    }

    #[test]
    fn wait_then_signal_pair_round_trip() {
        // A parked waiter (count 0 -> -1) is woken by a signal
        // (-1 -> -2): the drift documented in the module header.
        let guard = install(0x13, RC_WOKEN);
        let mut sem = csem(0, 0x99);
        unsafe {
            assert_eq!(csem_wait(&mut sem, 50), 0);
            csem_signal(&mut sem);
        }
        assert_eq!(sem.count, -2);
        assert_eq!(sleeps(), vec![(0x99, 50)]);
        assert_eq!(wakes(), vec![0x99]);
        restore(guard);
    }

    // ---- csem_wake alias ---------------------------------------------------

    #[test]
    fn wake_alias_forwards_the_raw_id() {
        let guard = install(0x13, 0);
        unsafe {
            csem_wake(0xabcd);
        }
        assert_eq!(wakes(), vec![0xabcd], "no count bookkeeping");
        restore(guard);
    }

    // ---- csem_post ---------------------------------------------------------

    #[test]
    fn post_with_tokens_only_increments() {
        let guard = install(0x13, 0);
        let mut sem = csem(1, 0x42);
        unsafe {
            csem_post(&mut sem);
        }
        assert_eq!(sem.count, 2);
        assert!(wakes().is_empty(), "old+1 = 2 is nonzero: no wake");
        restore(guard);
    }

    #[test]
    fn post_on_empty_sem_no_wake() {
        // old = 0 -> count 1: nobody parked (adds result 1, NE).
        let guard = install(0x13, 0);
        let mut sem = csem(0, 0x42);
        unsafe {
            csem_post(&mut sem);
        }
        assert_eq!(sem.count, 1);
        assert!(wakes().is_empty());
        restore(guard);
    }

    #[test]
    fn post_at_minus_one_wakes_the_single_sleeper() {
        // The EQ boundary: old = -1 -> old+1 = 0, wake carries the id.
        let guard = install(0x13, 0);
        let mut sem = csem(-1, 0x1234);
        unsafe {
            csem_post(&mut sem);
        }
        assert_eq!(sem.count, 0);
        assert_eq!(wakes(), vec![0x1234]);
        restore(guard);
    }

    #[test]
    fn post_deeper_negative_does_not_wake() {
        // old = -3 -> -2: adds result nonzero, no wake. EQ only,
        // binary-verified — not the <= 0 of a textbook V op.
        let guard = install(0x13, 0);
        let mut sem = csem(-3, 0x1234);
        unsafe {
            csem_post(&mut sem);
        }
        assert_eq!(sem.count, -2);
        assert!(wakes().is_empty());
        restore(guard);
    }

    #[test]
    fn post_wraps_at_i32_max_without_waking() {
        // old = i32::MAX: ARM adds wraps to i32::MIN (nonzero) — no wake.
        let guard = install(0x13, 0);
        let mut sem = csem(i32::MAX, 0x77);
        unsafe {
            csem_post(&mut sem);
        }
        assert_eq!(sem.count, i32::MIN);
        assert!(wakes().is_empty());
        restore(guard);
    }

    // ---- csem_post_deferred ----------------------------------------------

    #[test]
    fn post_deferred_with_tokens_only_increments() {
        let guard = install(0x13, 0);
        let mut sem = csem(1, 0x42);
        unsafe {
            csem_post_deferred(&mut sem);
        }
        assert_eq!(sem.count, 2);
        assert!(deferred_wakes().is_empty(), "old+1 = 2 is nonzero: no wake");
        assert!(wakes().is_empty());
        restore(guard);
    }

    #[test]
    fn post_deferred_on_empty_sem_no_wake() {
        // old = 0 -> count 1: nobody parked (adds result 1, NE).
        let guard = install(0x13, 0);
        let mut sem = csem(0, 0x42);
        unsafe {
            csem_post_deferred(&mut sem);
        }
        assert_eq!(sem.count, 1);
        assert!(deferred_wakes().is_empty());
        restore(guard);
    }

    #[test]
    fn post_deferred_at_minus_one_wakes_via_rom_22001cbc() {
        // The EQ boundary: old = -1 -> old+1 = 0. The wake rides the
        // rom_svc_22001cbc slot of task_lock's ROM_KERNEL, NOT the
        // waiter_wake / CSEM_ROM_WAKE paths of the sibling ops.
        let guard = install(0x13, 0);
        let mut sem = csem(-1, 0x1234);
        unsafe {
            csem_post_deferred(&mut sem);
        }
        assert_eq!(sem.count, 0);
        assert_eq!(deferred_wakes(), vec![0x1234], "wake carries the waiter id");
        assert!(wakes().is_empty(), "no gateway/kobj wake on this flavor");
        restore(guard);
    }

    #[test]
    fn post_deferred_deeper_negative_does_not_wake() {
        // old = -3 -> -2: adds result nonzero, no wake (EQ only, like the
        // twin — binary-verified shape).
        let guard = install(0x13, 0);
        let mut sem = csem(-3, 0x1234);
        unsafe {
            csem_post_deferred(&mut sem);
        }
        assert_eq!(sem.count, -2);
        assert!(deferred_wakes().is_empty());
        restore(guard);
    }
}
