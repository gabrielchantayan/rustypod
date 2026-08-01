//! ARM926EJ-S CP15 system-control-register helpers.

/// Bit 12 of CP15 c1 (SCTLR): instruction-cache enable.
const SCTLR_INSTRUCTION_CACHE_ENABLE: u32 = 0x1000;
/// Bit 2 of CP15 c1 (SCTLR): data-cache enable.
const SCTLR_DATA_CACHE_ENABLE: u32 = 0x4;
/// Bit 0 of CP15 c1 (SCTLR): MMU enable (the ARM architectural M bit).
const SCTLR_MMU_ENABLE: u32 = 0x1;


/// Enables the ARM926EJ-S instruction cache in SCTLR.
///
/// Original: `FUN_08003150` @ 0x08003150 (20 bytes).
/// Reference: `/home/gabe/Programming/ipod-decomp/decomp/c/000/08003150_FUN_08003150.c`.
/// The firmware loads SCTLR with `MRC p15, 0, r0, c1, c0, 0`
/// (`0xee110f10`), ORs bit 12, stores it with `MCR p15, 0, r0, c1, c0, 0`
/// (`0xee010f10`), and returns that stored word in `r0` per AAPCS.
///
/// On the firmware target this emits that CP15 read/modify/write sequence.
/// Non-firmware builds use a replaceable deterministic SCTLR seam; this is
/// the deliberate host-only deviation that makes the register transition
/// observable in behavioral tests.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn sctlr_enable_instruction_cache() -> u32 {
    let control = read_sctlr() | SCTLR_INSTRUCTION_CACHE_ENABLE;
    write_sctlr(control);
    control
}

/// Enables the ARM926EJ-S data cache in SCTLR.
///
/// Original: `FUN_08003164` @ 0x08003164 (20 bytes).
/// Reference: `/home/gabe/Programming/ipod-decomp/decomp/c/000/08003164_FUN_08003164.c`.
/// The firmware loads SCTLR with `MRC p15, 0, r0, c1, c0, 0`
/// (`0xee110f10`), ORs data-cache-enable bit 2, stores it with
/// `MCR p15, 0, r0, c1, c0, 0` (`0xee010f10`), and returns that stored word
/// in `r0` per AAPCS.
///
/// On the firmware target this emits that CP15 read/modify/write sequence.
/// Non-firmware builds use the deterministic SCTLR seam described above; this
/// is the deliberate host-only deviation that makes the register transition
/// observable in behavioral tests.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn sctlr_enable_data_cache() -> u32 {
    let control = read_sctlr() | SCTLR_DATA_CACHE_ENABLE;
    write_sctlr(control);
    control
}

/// Disables the ARM926EJ-S MMU through SCTLR's architectural M bit.
///
/// Original: `FUN_08003178` @ 0x08003178 (20 bytes).
/// Reference: `/home/gabe/Programming/ipod-decomp/decomp/c/000/08003178_FUN_08003178.c`.
/// The firmware loads SCTLR with `MRC p15, 0, r0, c1, c0, 0`
/// (`0xee110f10`), clears the MMU-enable M bit 0, stores it with
/// `MCR p15, 0, r0, c1, c0, 0` (`0xee010f10`), and returns that stored word
/// in `r0` per AAPCS.
///
/// On the firmware target this emits that CP15 read/modify/write sequence.
/// Non-firmware builds use the deterministic SCTLR seam described above; this
/// is the deliberate host-only deviation that makes the register transition
/// observable in behavioral tests.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn sctlr_disable_mmu() -> u32 {
    let control = read_sctlr() & !SCTLR_MMU_ENABLE;
    write_sctlr(control);
    control
}


#[cfg(all(target_os = "none", target_arch = "arm"))]
#[inline(always)]
fn read_sctlr() -> u32 {
    let control: u32;
    // SAFETY: MRC p15,0,<Rt>,c1,c0,0 is the ARM926EJ-S SCTLR read used by
    // the retail firmware. It has no Rust-visible memory operands.
    unsafe {
        core::arch::asm!(
            "mrc p15, 0, {control}, c1, c0, 0",
            control = out(reg) control,
            options(nomem, nostack),
        );
    }
    control
}

#[cfg(all(target_os = "none", target_arch = "arm"))]
#[inline(always)]
fn write_sctlr(control: u32) {
    // SAFETY: MCR p15,0,<Rt>,c1,c0,0 is the ARM926EJ-S SCTLR write used by
    // the retail firmware. It has no Rust-visible memory operands.
    unsafe {
        core::arch::asm!(
            "mcr p15, 0, {control}, c1, c0, 0",
            control = in(reg) control,
            options(nomem, nostack),
        );
    }
}

/// Host implementation seam for the SCTLR read and write instructions.
///
/// This is available only away from the firmware target. Replacing it is
/// unsafe because the static seam is process-global; callers must serialize
/// replacement with every user of [`sctlr_enable_instruction_cache`].
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[derive(Clone, Copy)]
pub struct HostSctlrHooks {
    /// Replacement for the CP15 `MRC p15,0,<Rt>,c1,c0,0` read.
    pub read: fn() -> u32,
    /// Replacement for the CP15 `MCR p15,0,<Rt>,c1,c0,0` write.
    pub write: fn(u32),
}

#[cfg(not(all(target_os = "none", target_arch = "arm")))]
static mut HOST_SCTLR: u32 = 0;

#[cfg(not(all(target_os = "none", target_arch = "arm")))]
fn default_read_sctlr() -> u32 {
    // SAFETY: access is serialized by the same caller requirement as the
    // replaceable hook table.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HOST_SCTLR)) }
}

#[cfg(not(all(target_os = "none", target_arch = "arm")))]
fn default_write_sctlr(control: u32) {
    // SAFETY: access is serialized by the same caller requirement as the
    // replaceable hook table.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(HOST_SCTLR), control) }
}

#[cfg(not(all(target_os = "none", target_arch = "arm")))]
static mut HOST_SCTLR_HOOKS: HostSctlrHooks = HostSctlrHooks {
    read: default_read_sctlr,
    write: default_write_sctlr,
};

/// Replaces the host SCTLR seam and returns the prior hooks.
///
/// This does not exist on the firmware target, where the function always
/// executes the actual CP15 instructions.
#[cfg(not(all(target_os = "none", target_arch = "arm")))]
pub unsafe fn replace_host_sctlr_hooks(hooks: HostSctlrHooks) -> HostSctlrHooks {
    let previous = core::ptr::read_volatile(core::ptr::addr_of!(HOST_SCTLR_HOOKS));
    core::ptr::write_volatile(core::ptr::addr_of_mut!(HOST_SCTLR_HOOKS), hooks);
    previous
}

#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(always)]
fn read_sctlr() -> u32 {
    // SAFETY: callers of replace_host_sctlr_hooks serialize hook replacement
    // with SCTLR use, as its safety contract requires.
    unsafe { (core::ptr::read_volatile(core::ptr::addr_of!(HOST_SCTLR_HOOKS)).read)() }
}

#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(always)]
fn write_sctlr(control: u32) {
    // SAFETY: callers of replace_host_sctlr_hooks serialize hook replacement
    // with SCTLR use, as its safety contract requires.
    unsafe { (core::ptr::read_volatile(core::ptr::addr_of!(HOST_SCTLR_HOOKS)).write)(control) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{
        replace_host_sctlr_hooks, sctlr_disable_mmu, sctlr_enable_data_cache,
        sctlr_enable_instruction_cache, HostSctlrHooks,
    };
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CONTROL: AtomicU32 = AtomicU32::new(0);
    static READS: AtomicUsize = AtomicUsize::new(0);
    static WRITES: AtomicUsize = AtomicUsize::new(0);

    fn recording_read() -> u32 {
        READS.fetch_add(1, Ordering::SeqCst);
        CONTROL.load(Ordering::SeqCst)
    }

    fn recording_write(control: u32) {
        WRITES.fetch_add(1, Ordering::SeqCst);
        CONTROL.store(control, Ordering::SeqCst);
    }

    struct RestoreHooks(HostSctlrHooks);

    impl Drop for RestoreHooks {
        fn drop(&mut self) {
            // SAFETY: TEST_LOCK remains held for this test's entire scope.
            unsafe { replace_host_sctlr_hooks(self.0) };
        }
    }

    fn install_recording_sctlr(control: u32) -> (MutexGuard<'static, ()>, RestoreHooks) {
        let lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        CONTROL.store(control, Ordering::SeqCst);
        READS.store(0, Ordering::SeqCst);
        WRITES.store(0, Ordering::SeqCst);
        // SAFETY: the returned TEST_LOCK guard serializes every seam swap and
        // every invocation in these focused tests.
        let old = unsafe {
            replace_host_sctlr_hooks(HostSctlrHooks {
                read: recording_read,
                write: recording_write,
            })
        };
        (lock, RestoreHooks(old))
    }

    #[test]
    fn enabling_instruction_cache_sets_bit_and_returns_stored_control() {
        let (_lock, _restore) = install_recording_sctlr(0xfeed_0001);

        let returned = sctlr_enable_instruction_cache();

        assert_eq!(returned, 0xfeed_1001);
        assert_eq!(CONTROL.load(Ordering::SeqCst), returned);
        assert_eq!(READS.load(Ordering::SeqCst), 1);
        assert_eq!(WRITES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn enabling_data_cache_sets_bit_and_returns_stored_control() {
        let (_lock, _restore) = install_recording_sctlr(0xfeed_1001);

        let returned = sctlr_enable_data_cache();

        assert_eq!(returned, 0xfeed_1005);
        assert_eq!(CONTROL.load(Ordering::SeqCst), returned);
        assert_eq!(READS.load(Ordering::SeqCst), 1);
        assert_eq!(WRITES.load(Ordering::SeqCst), 1);
    }


    #[test]
    fn enabling_instruction_cache_is_idempotent_but_still_reads_and_writes() {
        let (_lock, _restore) = install_recording_sctlr(0xabcd_1002);

        let returned = sctlr_enable_instruction_cache();

        assert_eq!(returned, 0xabcd_1002);
        assert_eq!(CONTROL.load(Ordering::SeqCst), 0xabcd_1002);
        assert_eq!(READS.load(Ordering::SeqCst), 1);
        assert_eq!(WRITES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn enabling_data_cache_is_idempotent_but_still_reads_and_writes() {
        let (_lock, _restore) = install_recording_sctlr(0xabcd_1006);

        let returned = sctlr_enable_data_cache();

        assert_eq!(returned, 0xabcd_1006);
        assert_eq!(CONTROL.load(Ordering::SeqCst), 0xabcd_1006);
        assert_eq!(READS.load(Ordering::SeqCst), 1);
        assert_eq!(WRITES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn disabling_mmu_clears_m_bit_and_returns_stored_control() {
        let (_lock, _restore) = install_recording_sctlr(0xfeed_1005);

        let returned = sctlr_disable_mmu();

        assert_eq!(returned, 0xfeed_1004);
        assert_eq!(CONTROL.load(Ordering::SeqCst), returned);
        assert_eq!(READS.load(Ordering::SeqCst), 1);
        assert_eq!(WRITES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn disabling_mmu_is_idempotent_but_still_reads_and_writes() {
        let (_lock, _restore) = install_recording_sctlr(0xabcd_1002);

        let returned = sctlr_disable_mmu();

        assert_eq!(returned, 0xabcd_1002);
        assert_eq!(CONTROL.load(Ordering::SeqCst), 0xabcd_1002);
        assert_eq!(READS.load(Ordering::SeqCst), 1);
        assert_eq!(WRITES.load(Ordering::SeqCst), 1);
    }
}
