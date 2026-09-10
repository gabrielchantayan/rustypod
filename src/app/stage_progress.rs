//! Stage-progress counter updates for the database commit and copy paths.
//!
//! A tracker is a 0x2c-byte object with its active stage in byte 0, a
//! per-stage progress word at +0x04, accumulated completed-stage work at +0x08,
//! and seven stage budgets at +0x10..+0x28. The deadline setter remains in
//! retailOS, so the target implementation calls its local veneer; host tests
//! replace that dependency through [`STAGE_PROGRESS_OPS`].

/// The 0x2c-byte stage-progress tracker constructed by `FUN_081fa440`.
#[repr(C)]
pub struct StageProgressTracker {
    /// +0x00: active stage (the valid values are 0..=6).
    pub current_stage: u8,
    _padding_01: [u8; 3],
    /// +0x04: work completed in the active stage.
    pub progress: u32,
    /// +0x08: work completed by earlier stages.
    pub completed_base: u32,
    /// +0x0c: sum of all seven stage budgets.
    pub total_budget: u32,
    /// +0x10..+0x28: budgets for stages 0 through 6.
    pub stage_budgets: [u32; 7],
}

const _: () = assert!(core::mem::size_of::<StageProgressTracker>() == 0x2c);
const _: () = assert!(core::mem::offset_of!(StageProgressTracker, progress) == 0x04);
const _: () = assert!(core::mem::offset_of!(StageProgressTracker, completed_base) == 0x08);
const _: () = assert!(core::mem::offset_of!(StageProgressTracker, total_budget) == 0x0c);
const _: () = assert!(core::mem::offset_of!(StageProgressTracker, stage_budgets) == 0x10);

/// The unported running-deadline setter reached through its local veneer at
/// 0x081b9154. It stores the supplied deadline into the keeper when present.
pub type SetRunningDeadline = unsafe extern "C" fn(u32);

#[derive(Clone, Copy)]
pub struct StageProgressOps {
    pub set_running_deadline: SetRunningDeadline,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_set_running_deadline(deadline: u32) {
    let setter: SetRunningDeadline = core::mem::transmute(0x081b9154usize);
    setter(deadline);
}

#[cfg(target_os = "none")]
pub const DEFAULT_STAGE_PROGRESS_OPS: StageProgressOps = StageProgressOps {
    set_running_deadline: retail_set_running_deadline,
};

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_set_running_deadline(_: u32) {
    panic!("install stage progress host operations before incrementing")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_STAGE_PROGRESS_OPS: StageProgressOps = StageProgressOps {
    set_running_deadline: missing_set_running_deadline,
};

/// Host-side dependency seam for the unported deadline-keeper setter.
#[cfg(not(target_os = "none"))]
pub static mut STAGE_PROGRESS_OPS: StageProgressOps = DEFAULT_STAGE_PROGRESS_OPS;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn ops() -> StageProgressOps {
    DEFAULT_STAGE_PROGRESS_OPS
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn ops() -> StageProgressOps {
    STAGE_PROGRESS_OPS
}

/// stage_progress_increment — original: `FUN_081fa36c` @ **0x081fa36c**
/// (**12 bytes**; **11 `bl` call sites, all unconditional — 0 predicated and
/// 0 plain `b`** — verified by decoding every ARM B/BL word in `osos.dec`).
///
/// Increments `tracker.progress` only when `stage` is the active stage and the
/// increment remains within that stage's budget. On success it calls the
/// running-deadline setter with `tracker.completed_base + progress`. The three
/// instructions at this entry compute `progress + 1` then deliberately fall
/// through into the separately linked sibling `FUN_081fa378` @ 0x081fa378,
/// which performs those checks and the deadline update; this port implements
/// the complete fall-through path.
///
/// Like the ARM entry, this has no NULL or stage-range guard: callers must pass
/// a valid tracker whose active stage is 0..=6. `wrapping_add` preserves the
/// ARM `add` behavior: a `u32::MAX` progress wraps to zero, fails the original
/// unsigned `progress <= progress + 1` check, and produces no update.
///
/// Deviation: `FUN_0815940c` is not ported, so the final setter call reaches
/// the retail veneer `0x081b9154` on device and a deterministic operation-table
/// fixture on the host.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stage_progress_increment(
    tracker: *mut StageProgressTracker,
    stage: u32,
) {
    let next_progress = (*tracker).progress.wrapping_add(1);

    if (*tracker).current_stage as u32 != stage {
        return;
    }

    // The retail code indexes `tracker + 0x10 + stage * 4` after comparing
    // stage against current_stage; valid trackers keep that byte in 0..=6.
    let budget = core::ptr::addr_of!((*tracker).stage_budgets)
        .cast::<u32>()
        .add(stage as usize)
        .read();
    if budget < next_progress {
        return;
    }

    if (*tracker).progress > next_progress {
        return;
    }

    (*tracker).progress = next_progress;
    let operations = ops();
    (operations.set_running_deadline)((*tracker).completed_base.wrapping_add(next_progress));
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    static OPS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static mut DEADLINE: u32 = 0;
    static mut DEADLINE_CALLS: u32 = 0;

    unsafe extern "C" fn record_deadline(deadline: u32) {
        DEADLINE = deadline;
        DEADLINE_CALLS += 1;
    }

    fn tracker(stage: u8, progress: u32, base: u32, budgets: [u32; 7]) -> StageProgressTracker {
        StageProgressTracker {
            current_stage: stage,
            _padding_01: [0; 3],
            progress,
            completed_base: base,
            total_budget: budgets.iter().copied().sum(),
            stage_budgets: budgets,
        }
    }

    unsafe fn install_recording_ops() -> StageProgressOps {
        let saved = STAGE_PROGRESS_OPS;
        STAGE_PROGRESS_OPS = StageProgressOps {
            set_running_deadline: record_deadline,
        };
        DEADLINE = 0;
        DEADLINE_CALLS = 0;
        saved
    }

    #[test]
    fn increments_active_stage_and_sets_absolute_deadline() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install_recording_ops();
            let mut value = tracker(4, 8, 0xffff_fff8, [0, 0, 0, 0, 9, 0, 0]);

            stage_progress_increment(&mut value, 4);

            assert_eq!(value.progress, 9);
            assert_eq!(DEADLINE_CALLS, 1);
            assert_eq!(DEADLINE, 1, "base + progress wraps as the ARM add");
            STAGE_PROGRESS_OPS = saved;
        }
    }

    #[test]
    fn inactive_stage_does_not_touch_progress_or_deadline() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install_recording_ops();
            let mut value = tracker(3, 4, 10, [0, 0, 0, 99, 0, 0, 0]);

            stage_progress_increment(&mut value, 2);

            assert_eq!(value.progress, 4);
            assert_eq!(DEADLINE_CALLS, 0);
            STAGE_PROGRESS_OPS = saved;
        }
    }

    #[test]
    fn stage_budget_is_an_inclusive_cap() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install_recording_ops();
            let mut value = tracker(1, 4, 12, [0, 4, 0, 0, 0, 0, 0]);

            stage_progress_increment(&mut value, 1);

            assert_eq!(value.progress, 4);
            assert_eq!(DEADLINE_CALLS, 0);
            STAGE_PROGRESS_OPS = saved;
        }
    }

    #[test]
    fn progress_wrap_is_rejected_after_budget_check() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install_recording_ops();
            let mut value = tracker(6, u32::MAX, 0, [0, 0, 0, 0, 0, 0, u32::MAX]);

            stage_progress_increment(&mut value, 6);

            assert_eq!(value.progress, u32::MAX);
            assert_eq!(DEADLINE_CALLS, 0);
            STAGE_PROGRESS_OPS = saved;
        }
    }
}
