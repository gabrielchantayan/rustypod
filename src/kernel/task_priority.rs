//! RTXC task-priority gateway wrapper.
//!
//! `thunk_EXT_FUN_22003bcc` is the eight-byte literal veneer at load address
//! `0x08037ed0`: `e51ff004` (`ldr pc, [pc, #-4]`) followed by the target
//! `0x22003bcc`. The boot relocator at `0x080046e0` mirrors that target from
//! osos `0x08003bcc`, whose 28-byte body prepares RTXC service `0x1b`.
//!
//! The sibling getter veneer `thunk_EXT_FUN_22003e44` sits one slot earlier
//! at `0x08037ec8` and is ported here as [`task_priority_get`].

use crate::heap::rom_task_start::gateway_dispatch;

/// RTXC task-record table in osos RAM: 52-byte records indexed by task id.
/// Mirror of the literal loaded by the ROM getter body at `0x08003e68`.
#[cfg(target_os = "none")]
const TASK_RECORD_TABLE: *const u8 = 0x08a2_4570 as *const u8;

/// Location of the current task-record pointer in the IRAM kernel mirror.
/// Mirror of the literal loaded by the ROM getter body at `0x08003e6c`.
#[cfg(target_os = "none")]
const CURRENT_TASK_RECORD_SLOT: *const u32 = 0x2200_acf4 as *const u32;

/// Task-record stride, in bytes (`movne r1, #13; mulne; lsl #2` in the ROM).
const TASK_RECORD_STRIDE: usize = 13 * 4;

/// Offset of the priority word inside a task record.
const TASK_PRIORITY_OFFSET: usize = 0x24;

/// Host counterpart to [`TASK_RECORD_TABLE`]. It deliberately retains the
/// target's 32-bit pointer representation, so mapped test tables must
/// remain below 4 GiB.
#[cfg(not(target_os = "none"))]
static mut HOST_TASK_RECORD_TABLE_WORD: u32 = 0;

/// Host counterpart to [`CURRENT_TASK_RECORD_SLOT`], same-width for the
/// same reason as [`HOST_TASK_RECORD_TABLE_WORD`].
#[cfg(not(target_os = "none"))]
static mut HOST_CURRENT_TASK_RECORD_WORD: u32 = 0;

/// Four-word request received by RTXC `KS_defpriority` (service `0x1b`).
///
/// The ARM save area is six words wide. Its dispatch prefix overwrites saved
/// `r0..r3` with `{ selector, priority, task, priority }`; saved `r4` and
/// `lr` remain outside this request and are restored by the epilogue.
pub type TaskPriorityRequest = [u32; 4];

/// RTXC selector for `KS_defpriority(TASK task, PRIORITY priority)`.
pub const TASK_PRIORITY_SERVICE: u32 = 0x1b;

/// task_priority_set — original: `thunk_EXT_FUN_22003bcc` @ `0x08037ed0`
/// (8-byte veneer), targeting the 28-byte IRAM mirror body @ `0x08003bcc`.
///
/// Raw ARM builds `{ 0x1b, priority, task, priority }`, dispatches it through
/// `FUN_08003660`, and restores the incoming `r0` as its return word. The RTXC
/// catalogue identifies selector `0x1b` as `KS_defpriority`; callers use
/// `(0, 2)` to set the current task's priority and later restore a saved
/// priority. Decoding every ARM B/BL word in osos.dec finds eight direct
/// callers: seven plain `bl` (0x08067fa8, 0x0806802c, 0x08104fec,
/// 0x0810500c, 0x081e1d1c, 0x082e85c8, 0x08393f04) and one caller-gated
/// `blne` (0x081e1d5c). The veneer has no guard and no data-word reference.
///
/// Deliberate deviation: the literal tail branch and its foreign dispatcher
/// are represented by the existing volatile gateway seam. Rust cannot expose
/// the original's incidental restoration of caller-saved `r2`/`r3`; neither is
/// a C ABI result, and both are absent from the dispatched record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_priority_set(task: u32, priority: u32) -> u32 {
    let mut request: TaskPriorityRequest = [TASK_PRIORITY_SERVICE, priority, task, priority];
    gateway_dispatch()(request.as_mut_ptr());
    task
}
/// current_task_priority_set — original: `FUN_080e4300` @ `0x080e4300`
/// (12 bytes; next real function begins at `0x080e430c`).
///
/// Raw words `e1a01000 e3a00000 eafd4ef0` move the requested priority from
/// `r0` to `r1`, replace `r0` with the RTXC current-task selector zero, then
/// tail-branch through the `task_priority_set` veneer at `0x08037ed0`.
/// Decoding every ARM B/BL word in osos.dec finds three inbound plain `bl`
/// calls (0x080935c4, 0x080f5540, 0x081f4974), zero predicated `bl`; the
/// function body has zero `bl` and one unconditional tail `b`.
///
/// Deliberate deviation: Rust makes the veneer target an ordinary call to the
/// existing volatile gateway seam rather than preserving the literal tail
/// branch. Its observable result remains the selector zero returned by
/// `task_priority_set`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn current_task_priority_set(priority: u32) -> u32 {
    task_priority_set(0, priority)
}


/// task_priority_get — original: `thunk_EXT_FUN_22003e44` @ `0x08037ec8`
/// (Ghidra reports 4 bytes; verified extent 8 bytes: `ldr pc, [pc, #-4]`
/// word `0xe51ff004` at `0x08037ec8` plus the target word `0x22003e44` at
/// `0x08037ecc`; the next veneer, `task_priority_set`'s, starts at
/// `0x08037ed0`). A pure ADS literal veneer onto the RTXC task-priority
/// getter at ROM `0x22003e44`; r0 = task id, 0 meaning the current task.
/// The ROM body is recoverable through the boot-relocator IRAM mirror
/// (ROM `0x2200XXXX` == osos `0x0800XXXX`): mirror @ `0x08003e44`, 36
/// bytes (the sibling gateway stub body starts at `0x08003e70`):
///
/// ```text
/// cmp r0, #0
/// movne r1, #13
/// mulne r0, r1, r0          @ id * 13
/// ldrne r1, [pc, #16]       @ 0x08a24570: task-record table
/// addne r0, r1, r0, lsl #2  @ table + 52*id
/// ldreq r0, [pc, #12]       @ 0x2200acf4: current-task-record slot
/// ldreq r0, [r0]
/// ldr r0, [r0, #0x24]       @ priority word
/// bx lr
/// ```
///
/// Call sites: 5 unconditional `bl` (0x08067f98, 0x080a3dd4, 0x080ccc14,
/// 0x08104fdc, 0x081e1d0c), binary-verified by decoding every ARM B/BL word
/// in osos.dec for every condition code — Ghidra's asm listing shows only
/// 4 because it mislabels the 0x08104fdc site. Zero predicated `bl`, zero
/// tail `b`; no data word in osos holds 0x08037ec8, so the veneer is never
/// dispatched virtually. The priority reading rests on caller evidence:
/// every observed caller passes r0 = 0, saves the result, brackets work in
/// `task_priority_set(0, {2, 3})` (0x08067fa8, 0x081e1d1c), and later
/// restores the saved word with `task_priority_set(0, saved)`
/// (0x0806802c, 0x081e1d5c) — a classic temporary priority boost; the
/// sibling record getter `current_task_id` returns the id at record +0x20,
/// so +0x24 is the adjacent scalar attribute the set service consumes.
///
/// Deliberate deviations: the literal tail branch is represented by a real
/// Rust function body performing the same pointer chase; device builds load
/// the IRAM global and osos table directly, host builds substitute the
/// same-width [`HOST_TASK_RECORD_TABLE_WORD`] /
/// [`HOST_CURRENT_TASK_RECORD_WORD`] so the chase can be exercised without
/// mapping 0x08a24570 / 0x2200acf4. The original has no NULL guard and none
/// is added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn task_priority_get(task: u32) -> u32 {
    let record = if task == 0 {
        let record_word = {
            #[cfg(target_os = "none")]
            {
                CURRENT_TASK_RECORD_SLOT.read_volatile()
            }
            #[cfg(not(target_os = "none"))]
            {
                core::ptr::addr_of!(HOST_CURRENT_TASK_RECORD_WORD).read_volatile()
            }
        };
        record_word as usize as *const u8
    } else {
        let table_word = {
            #[cfg(target_os = "none")]
            {
                TASK_RECORD_TABLE as usize as u32
            }
            #[cfg(not(target_os = "none"))]
            {
                core::ptr::addr_of!(HOST_TASK_RECORD_TABLE_WORD).read_volatile()
            }
        };
        (table_word as usize as *const u8).add(task as usize * TASK_RECORD_STRIDE)
    };
    record.add(TASK_PRIORITY_OFFSET).cast::<u32>().read_volatile()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::rom_task_start::{RomGatewayOps, DEFAULT_ROM_GATEWAY_OPS, ROM_GATEWAY_OPS};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn record_and_clobber(request: *mut u32) {
        let call = addr_of!(CALLS).read();
        let words = core::slice::from_raw_parts_mut(request, 4);
        match call {
            0 => assert_eq!(words, &[0x1b, 2, 0, 2]),
            1 => assert_eq!(words, &[0x1b, u32::MAX, u32::MAX, u32::MAX]),
            2 => assert_eq!(words, &[0x1b, 0, 0, 0]),
            3 => assert_eq!(words, &[0x1b, u32::MAX, 0, u32::MAX]),
            _ => panic!("unexpected gateway dispatch"),
        }
        words.copy_from_slice(&[0xa5a5_a5a5; 4]);
        addr_of_mut!(CALLS).write(call + 1);
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CALLS).write(0);
            addr_of_mut!(ROM_GATEWAY_OPS).write(RomGatewayOps {
                dispatch: record_and_clobber,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(ROM_GATEWAY_OPS).write(DEFAULT_ROM_GATEWAY_OPS) };
        drop(guard);
    }

    fn forwards_priority_record_and_preserves_task_return_word() {
        let guard = install_recorder();
        unsafe {
            assert_eq!(task_priority_set(0, 2), 0);
            assert_eq!(task_priority_set(u32::MAX, u32::MAX), u32::MAX);
            assert_eq!(current_task_priority_set(0), 0);
            assert_eq!(current_task_priority_set(u32::MAX), 0);
            assert_eq!(addr_of!(CALLS).read(), 4);
        }
        restore(guard);
    }

    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    /// One slab backs both the task-record table (base) and the current
    /// task record (base + 0x1000); both must round-trip through u32.
    const PRIORITY_FIXTURE_LEN: usize = 0x2000;
    static PRIORITY_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TASK_PRIORITY_GET, PRIORITY_FIXTURE_LEN).map(|p| p as usize)
    });
    static PRIORITY_GET_LOCK: Mutex<()> = Mutex::new(());

    /// The chase is two exact dereferences with no fallback: id 0 loads the
    /// current-task record through the slot word and reads +0x24; a nonzero
    /// id strides 52 bytes per record into the table. Zero and all-ones
    /// priority words are observable, and an id whose record lies inside the
    /// table reads its own slot, not a neighbour's.
    #[test]
    fn task_priority_get_reads_record_word_24() {
        let _guard = PRIORITY_GET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = *PRIORITY_FIXTURE else {
            assert!(note_missing_u32_fixture("kernel::task_priority::task_priority_get"));
            return;
        };
        unsafe {
            let base = base as *mut u8;
            core::ptr::write_bytes(base, 0, PRIORITY_FIXTURE_LEN);
            let current = base.add(0x1000);
            addr_of_mut!(HOST_TASK_RECORD_TABLE_WORD).write(base as u32);
            addr_of_mut!(HOST_CURRENT_TASK_RECORD_WORD).write(current as u32);

            // id 0: current-task record.
            for priority in [0, 2, u32::MAX] {
                current.add(TASK_PRIORITY_OFFSET).cast::<u32>().write(priority);
                assert_eq!(task_priority_get(0), priority);
            }
            // A nonzero id must NOT touch the current-task record.
            current.add(TASK_PRIORITY_OFFSET).cast::<u32>().write(0xdead_beef);

            // Nonzero ids: 52-byte stride into the table.
            for id in [1u32, 2, 0x3f] {
                let slot = base.add(id as usize * TASK_RECORD_STRIDE + TASK_PRIORITY_OFFSET);
                slot.cast::<u32>().write(id ^ 0x5a00_0000);
            }
            for id in [1u32, 2, 0x3f] {
                assert_eq!(task_priority_get(id), id ^ 0x5a00_0000);
            }
            // Stride proof: neighbouring word offsets stay untouched.
            assert_eq!(
                base.add(TASK_RECORD_STRIDE + TASK_PRIORITY_OFFSET - 4)
                    .cast::<u32>()
                    .read(),
                0
            );

            addr_of_mut!(HOST_TASK_RECORD_TABLE_WORD).write(0);
            addr_of_mut!(HOST_CURRENT_TASK_RECORD_WORD).write(0);
        }
    }
}
