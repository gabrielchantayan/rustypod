//! Mutex-protected state-byte snapshot from a retailOS state collection.

use super::sync_mutex::{Mutex, mutex_lock, mutex_unlock};

/// Prefix of the state collection constructed at 0x081612a4. The three
/// opaque words retain target widths so the embedded mutex stays at +0x10
/// even on hosts with eight-byte pointers. The collection's storage is not
/// dereferenced by this getter.
#[repr(C)]
pub struct GuardedStateByte {
    pub state: u8,
    pub padding: [u8; 3],
    pub storage_words: [u32; 3],
    pub mutex: Mutex,
}

/// Original: `FUN_081610d0` @ 0x081610d0, 36 bytes, extent
/// [0x081610d0,0x081610f4); the next function begins with its own push.
/// Two outbound plain BLs (mutex_lock and mutex_unlock), no predicated
/// BLs; two inbound plain BLs at 0x0806b9f4 and 0x0825aa08, none predicated.
/// Lock the embedded mutex at +0x10, read the unsigned state byte at +0,
/// unlock that same mutex, and return the saved byte without normalization.
/// No NULL check, as in stock. Deliberate deviations: the byte load is
/// volatile to preserve its position between calls; host mutex pointers
/// widen, but the mutex offset remains +0x10. Existing mutex dispatch and
/// semaphore guards are reused without a new callee seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn guarded_state_byte_get(collection: *mut GuardedStateByte) -> u8 {
    let mutex = core::ptr::addr_of_mut!((*collection).mutex);
    mutex_lock(mutex);
    let state = core::ptr::addr_of!((*collection).state).read_volatile();
    mutex_unlock(mutex);
    state
}
