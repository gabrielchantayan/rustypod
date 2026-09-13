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

/// Waits until the active stage has consumed its current budget.
pub type WaitForCurrentStage = unsafe extern "C" fn(*mut StageProgressTracker);

#[derive(Clone, Copy)]
pub struct StageProgressOps {
    pub set_running_deadline: SetRunningDeadline,
    pub wait_for_current_stage: WaitForCurrentStage,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_set_running_deadline(deadline: u32) {
    let setter: SetRunningDeadline = core::mem::transmute(0x081b9154usize);
    setter(deadline);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_wait_for_current_stage(tracker: *mut StageProgressTracker) {
    let wait: WaitForCurrentStage = core::mem::transmute(0x081fa3ecusize);
    wait(tracker);
}

#[cfg(target_os = "none")]
pub const DEFAULT_STAGE_PROGRESS_OPS: StageProgressOps = StageProgressOps {
    set_running_deadline: retail_set_running_deadline,
    wait_for_current_stage: retail_wait_for_current_stage,
};

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_set_running_deadline(_: u32) {
    panic!("install stage progress host operations before updating the deadline")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_wait_for_current_stage(_: *mut StageProgressTracker) {
    panic!("install stage progress host operations before advancing the stage")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_STAGE_PROGRESS_OPS: StageProgressOps = StageProgressOps {
    set_running_deadline: missing_set_running_deadline,
    wait_for_current_stage: missing_wait_for_current_stage,
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
/// stage_progress_advance — original: `FUN_081fa2e8` @ **0x081fa2e8**
/// (**84 bytes**; **7 `bl` call sites, all unconditional — 0 predicated and
/// 0 plain `b`** — verified by decoding every ARM B/BL word in `osos.dec`).
///
/// Waits for the active stage to finish, sets `stage` as the active byte,
/// clears its progress and accumulated base, then sums every earlier stage
/// budget into the base. The tail call into `FUN_081fa378` publishes that
/// base as the running deadline when the new stage's signed budget is
/// non-negative. The next sibling starts at 0x081fa33c, confirming the
/// assigned extent 0x081fa2e8..0x081fa33c.
///
/// Like the ARM entry, this has no NULL or stage-range guard. `stage` remains
/// a `u32`: the original writes only its low byte to `current_stage`, but uses
/// the full signed value for the preceding-budget loop and the tail call.
///
/// Deviation: `FUN_081fa3ec` and `FUN_0815940c` are unported, so the wait and
/// deadline publication respectively use their retail entry/veneer on device
/// and deterministic operation-table fixtures on the host.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stage_progress_advance(
    tracker: *mut StageProgressTracker,
    stage: u32,
) {
    let operations = ops();
    (operations.wait_for_current_stage)(tracker);

    (*tracker).current_stage = stage as u8;
    (*tracker).progress = 0;
    (*tracker).completed_base = 0;

    let budgets = core::ptr::addr_of!((*tracker).stage_budgets).cast::<u32>();
    let mut prior_stage = 0i32;
    while prior_stage < stage as i32 {
        (*tracker).completed_base = (*tracker)
            .completed_base
            .wrapping_add(budgets.wrapping_add(prior_stage as usize).read());
        prior_stage = prior_stage.wrapping_add(1);
    }

    // This is the tail-called `FUN_081fa378` path with a freshly cleared
    // progress word. It deliberately retains the original signed budget test.
    if (*tracker).current_stage as u32 != stage {
        return;
    }
    if (budgets.wrapping_add(stage as usize).read() as i32) < 0 {
        return;
    }
    (operations.set_running_deadline)((*tracker).completed_base);
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

    static mut WAIT_CALLS: u32 = 0;
    static mut WAIT_STAGE: u8 = 0;
    static mut WAIT_PROGRESS: u32 = 0;

    unsafe extern "C" fn record_wait(tracker: *mut StageProgressTracker) {
        WAIT_CALLS += 1;
        WAIT_STAGE = (*tracker).current_stage;
        WAIT_PROGRESS = (*tracker).progress;
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
            wait_for_current_stage: record_wait,
        };
        DEADLINE = 0;
        DEADLINE_CALLS = 0;
        WAIT_CALLS = 0;
        WAIT_STAGE = 0;
        WAIT_PROGRESS = 0;
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

    #[test]
    fn advance_waits_then_resets_stage_and_publishes_prior_budget_total() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install_recording_ops();
            let mut value = tracker(1, 7, 99, [2, 3, 4, 5, 6, 7, 8]);

            stage_progress_advance(&mut value, 2);

            assert_eq!((WAIT_CALLS, WAIT_STAGE, WAIT_PROGRESS), (1, 1, 7));
            assert_eq!((value.current_stage, value.progress, value.completed_base), (2, 0, 5));
            assert_eq!(value.total_budget, 35, "advance leaves the total budget intact");
            assert_eq!((DEADLINE_CALLS, DEADLINE), (1, 5));
            STAGE_PROGRESS_OPS = saved;
        }
    }

    #[test]
    fn advance_to_zero_publishes_zero_after_discarding_existing_progress() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install_recording_ops();
            let mut value = tracker(6, 8, 21, [0, 3, 4, 5, 6, 7, 8]);

            stage_progress_advance(&mut value, 0);

            assert_eq!(WAIT_CALLS, 1);
            assert_eq!((value.current_stage, value.progress, value.completed_base), (0, 0, 0));
            assert_eq!((DEADLINE_CALLS, DEADLINE), (1, 0));
            STAGE_PROGRESS_OPS = saved;
        }
    }

    #[test]
    fn advance_with_negative_new_budget_resets_but_skips_deadline() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install_recording_ops();
            let mut value = tracker(0, 1, 0, [4, 0x8000_0000, 0, 0, 0, 0, 0]);

            stage_progress_advance(&mut value, 1);

            assert_eq!(WAIT_CALLS, 1);
            assert_eq!((value.current_stage, value.progress, value.completed_base), (1, 0, 4));
            assert_eq!(DEADLINE_CALLS, 0, "the ARM `bxlt` rejects negative budgets");
            STAGE_PROGRESS_OPS = saved;
        }
    }
}
