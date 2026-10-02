//! Reset the application's mutex-protected word pair.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// Target layout of the owner prefix through its embedded mutex.
/// Native host pointers widen only the mutex, not the preceding word offsets.
#[repr(C)]
pub struct LockedWordPairOwner {
    pub prefix: [u32; 0x29c / 4],
    pub first: u32,
    pub second: u32,
    pub mutex: Mutex,
}

/// Original: `FUN_08296504` @ 0x08296504, 44 bytes, ending at the
/// next function's push @ 0x08296530. Raw ARM decoding verifies two inbound
/// unconditional BL callers (0x082960fc, 0x08296344), zero predicated BLs;
/// one outbound BL to mutex_lock and one tail B to mutex_unlock.
/// Lock the mutex at +0x2a4, zero the aligned words at +0x29c and +0x2a0,
/// then unlock. Both initialization and cleanup callers use this reset.
/// Deliberate deviation: express the tail branch as a return-position call
/// to the existing Rust mutex port; host mutex pointers have native width.
///
/// # Safety
/// `owner` must point to a writable owner with a valid mutex semaphore cell
/// (or a NULL cell), and the kernel semaphore operations must be installed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn locked_word_pair_reset(owner: *mut LockedWordPairOwner) {
    let mutex = core::ptr::addr_of_mut!((*owner).mutex);
    mutex_lock(mutex);
    core::ptr::addr_of_mut!((*owner).first).write(0);
    core::ptr::addr_of_mut!((*owner).second).write(0);
    mutex_unlock(mutex);
}
