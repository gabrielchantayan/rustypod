//! Demo-mode snapshot refresh — FUN_08188510 @ 0x08188510.
//! True extent: 52 bytes, [0x08188510,0x08188544): 44 executable bytes
//! and two literal words. Next function is bx lr at 0x08188544.
//! Whole-image raw A32 scan: zero incoming plain BLs, two BLNEs at
//! 0x081a5950/0x081a6230. Body: one plain BL, zero predicated BLs,
//! and one tail B. Copy global word 0x089cc634 to 0x089cc638 before
//! resident demo-mode refresh 0x08187544, then rearm its timer through
//! the ported demo_mode_rearm_timer @ 0x08187d00.
//! The first resident refresh updates calendar/resources; its precise
//! identity remains unresolved. No NULL guard exists in the original.
//! Deviations: fixed-address calls lower to BLX; tail B becomes a Rust
//! call/return. Host-only dependency injection substitutes RAM and refresh.

use crate::app::demo_mode_rearm_timer::demo_mode_rearm_timer;

pub type ResidentRefresh = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct DemoModeSnapshotOps {
    pub current: *const u32,
    pub snapshot: *mut u32,
    pub refresh: ResidentRefresh,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resident(_: *mut u8) {
    panic!("demo_mode_snapshot_refresh requires resident firmware dependencies")
}

#[cfg(not(target_os = "none"))]
pub static mut DEMO_MODE_SNAPSHOT_OPS: DemoModeSnapshotOps = DemoModeSnapshotOps {
    current: core::ptr::null(), snapshot: core::ptr::null_mut(),
    refresh: missing_resident,
};

#[inline(always)]
unsafe fn refresh_snapshot(
    demo: *mut u8, current: *const u32, snapshot: *mut u32,
    refresh: ResidentRefresh, rearm: ResidentRefresh,
) {
    snapshot.write_volatile(current.read_volatile());
    refresh(demo);
    rearm(demo);
}

/// Snapshot the demo-mode global, refresh its resources, then rearm its timer.
/// # Safety
/// `demo` and retailOS RAM/resident dependencies must be valid and initialized.
/// Host callers must supply valid RAM and resident equivalents in the ops table.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn demo_mode_snapshot_refresh(demo: *mut u8) {
    #[cfg(target_os = "none")]
    refresh_snapshot(demo, 0x089c_c634 as *const u32, 0x089c_c638 as *mut u32,
        core::mem::transmute::<usize, ResidentRefresh>(0x0818_7544),
        demo_mode_rearm_timer);
    #[cfg(not(target_os = "none"))]
    {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(DEMO_MODE_SNAPSHOT_OPS));
        refresh_snapshot(demo, ops.current, ops.snapshot, ops.refresh, demo_mode_rearm_timer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture { current: u32, snapshot: u32, expected: u32, phase: u32 }

    unsafe extern "C" fn update(demo: *mut u8) {
        let f = &mut *demo.cast::<Fixture>();
        assert_eq!(f.snapshot, f.expected); // Store must precede resident mutation.
        assert_eq!(f.phase, 0);
        f.current = !f.current;
        f.phase = 1;
    }
    unsafe extern "C" fn rearm(demo: *mut u8) {
        let f = &mut *demo.cast::<Fixture>();
        assert_eq!(f.phase, 1);
        assert_eq!(f.snapshot, f.expected); // Must not copy the refreshed value.
        f.phase = 2;
    }

    #[test]
    fn snapshot_retains_pre_refresh_word_across_repeated_updates() {
        for initial in [0, 1, 0x8000_0000, 0xffff_ffff, 0x1234_5678] {
            let mut f = Fixture { current: initial, snapshot: !initial,
                expected: initial, phase: 0 };
            for _ in 0..3 {
                f.expected = f.current;
                f.phase = 0;
                unsafe {
                    refresh_snapshot((&mut f as *mut Fixture).cast(),
                        core::ptr::addr_of!(f.current), core::ptr::addr_of_mut!(f.snapshot),
                        update, rearm);
                }
                assert_eq!(f.snapshot, f.expected);
                assert_eq!(f.current, !f.expected);
                assert_eq!(f.phase, 2);
            }
        }
    }
}
