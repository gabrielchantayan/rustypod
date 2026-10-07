use crate::kernel::sync_mutex::{Mutex, mutex_lock, mutex_unlock};

/// Prefix of the state object: target mutex at +0, state at +0x14.
/// Native pointer fields keep host fixtures valid without truncating pointers.
#[repr(C)]
pub struct LockedState {
    pub mutex: Mutex,
    pub reserved: [u32; 3],
    pub state: i32,
}

/// `locked_state_cancel` — original `FUN_0813b414` @ 0x0813b414.
/// True extent [0x0813b414, 0x0813b434): 32 bytes, no literals.
/// Whole-image aligned A32 decoding finds two inbound plain BL sites
/// (0x0814bf84, 0x0814bfd4), zero predicated BL sites. The body contains
/// one plain BL to mutex_lock and a tail B to mutex_unlock.
/// Acquires the leading mutex, overwrites state at +0x14 with -2, then
/// releases the mutex. No object NULL guard; all other fields are preserved.
/// Deliberate deviations: a Rust return-position call represents the tail
/// branch; repr(C) expands the mutex pointer on hosts, not on the ARM target.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn locked_state_cancel(object: *mut LockedState) {
    let mutex = core::ptr::addr_of_mut!((*object).mutex);
    mutex_lock(mutex);
    core::ptr::addr_of_mut!((*object).state).write_volatile(-2);
    mutex_unlock(mutex);
}
