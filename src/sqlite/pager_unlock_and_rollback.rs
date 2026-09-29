//! SQLite pager unlock-and-rollback — `pager_unlock_and_rollback`.
//!
//! RetailOS `FUN_082dd800` at load address `0x082dd800` is 68 bytes
//! (`0x082dd800..0x082dd844`): the `push {r4,lr}` begins its body and the
//! next separately linked function begins with `mov r2,r0` at `0x082dd844`.
//! Raw A32 decoding finds two inbound plain `bl` call sites (`0x0837ddfc` and
//! `0x0837ef4c`) and no predicated `bl` call sites. Its body contains three
//! unconditional `bl` calls: `fault_begin_benign`, `pager_rollback`, and
//! `fault_end_benign`; it then tail-branches to the still-retail
//! `context_recover` at `0x082de814`.
//!
//! If there is no pager error and its state is at least reader, it brackets
//! `sqlite3PagerRollback` in SQLite's benign-fault scope. It always transfers
//! the pager to `context_recover` afterwards. Deliberate deviation: the tail
//! target remains retailOS-owned; host tests use a callback boundary for it.

use crate::sqlite::mem::{fault_begin_benign, fault_end_benign};

const ERROR_CODE: usize = 0x20;
const STATE: usize = 0x0e;

type PagerOperation = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_rollback(pager: *mut u8) {
    let operation: PagerOperation = core::mem::transmute(0x0837_ea84usize);
    operation(pager);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn context_recover(pager: *mut u8) {
    let operation: PagerOperation = core::mem::transmute(0x082d_e814usize);
    operation(pager);
}

#[cfg(not(target_os = "none"))]
pub(crate) struct PagerUnlockAndRollbackHostOps {
    pub pager_rollback: PagerOperation,
    pub context_recover: PagerOperation,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_pager_operation(_pager: *mut u8) {}

#[cfg(not(target_os = "none"))]
const DEFAULT_HOST_OPS: PagerUnlockAndRollbackHostOps = PagerUnlockAndRollbackHostOps {
    pager_rollback: unavailable_pager_operation,
    context_recover: unavailable_pager_operation,
};

#[cfg(not(target_os = "none"))]
pub(crate) static mut PAGER_UNLOCK_AND_ROLLBACK_HOST_OPS: PagerUnlockAndRollbackHostOps = DEFAULT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> PagerUnlockAndRollbackHostOps {
    core::ptr::read_volatile(core::ptr::addr_of!(PAGER_UNLOCK_AND_ROLLBACK_HOST_OPS))
}

/// `pager_unlock_and_rollback` — original `FUN_082dd800` @ `0x082dd800`
/// (68 bytes; two inbound plain `bl` sites and no predicated `bl` sites).
///
/// # Safety
/// `pager` must designate a writable target-layout SQLite Pager.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.pager_unlock_and_rollback")]
#[inline(never)]
pub unsafe extern "C" fn pager_unlock_and_rollback(pager: *mut u8) {
    if pager.add(ERROR_CODE).cast::<u32>().read_volatile() == 0 && pager.add(STATE).read_volatile() >= 2 {
        fault_begin_benign(-1);
        #[cfg(target_os = "none")]
        pager_rollback(pager);
        #[cfg(not(target_os = "none"))]
        (host_ops().pager_rollback)(pager);
        fault_end_benign(-1);
    }
    #[cfg(target_os = "none")]
    context_recover(pager);
    #[cfg(not(target_os = "none"))]
    (host_ops().context_recover)(pager);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static mut ROLLBACKS: usize = 0;
    static mut RECOVERS: usize = 0;

    unsafe extern "C" fn rollback(_pager: *mut u8) { ROLLBACKS += 1; }
    unsafe extern "C" fn recover(_pager: *mut u8) { RECOVERS += 1; }

    #[test]
    fn rolls_back_only_clean_reader_or_higher_pagers_then_always_recovers() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_PAGER_UNLOCK_AND_ROLLBACK, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!())); return;
        };
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(PAGER_UNLOCK_AND_ROLLBACK_HOST_OPS),
                PagerUnlockAndRollbackHostOps { pager_rollback: rollback, context_recover: recover },
            );
            ROLLBACKS = 0;
            RECOVERS = 0;
            let pager = slab.add(0x100);

            pager.add(ERROR_CODE).cast::<u32>().write(1);
            pager.add(STATE).write(3);
            pager_unlock_and_rollback(pager);
            pager.add(ERROR_CODE).cast::<u32>().write(0);
            pager.add(STATE).write(1);
            pager_unlock_and_rollback(pager);
            pager.add(STATE).write(2);
            pager_unlock_and_rollback(pager);

            assert_eq!(ROLLBACKS, 1);
            assert_eq!(RECOVERS, 3);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(PAGER_UNLOCK_AND_ROLLBACK_HOST_OPS), DEFAULT_HOST_OPS);
        }
    }
}
