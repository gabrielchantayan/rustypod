//! Global status-flag reset.
//!
//! `global_status_flags_reset` — original: `FUN_0804b3e4` @ `0x0804b3e4`
//! (24 bytes, including the literal at `0x0804b3fc`).
//!
//! Raw A32 words establish the true extent: `ldr r0, [pc, #16]` loads the
//! literal `0x089ca864`; `strb r1, [r0, #1]` stores one; `strb r1, [r0]`
//! stores zero; `bx lr` ends the body at `0x0804b3f8`; and `0x0804b400`
//! begins the next `stmdb` prologue. The leaf has no outbound plain or
//! predicated `bl`; whole-image A32 decoding finds two inbound plain `bl`
//! calls and no predicated inbound `bl` calls.
//!
//! # Algorithm
//! Mark the second byte of the two-byte global status state, then clear its
//! first byte. The store order is deliberate. Target builds use the verified
//! live address directly; host tests use a private backing object.

/// Two adjacent status bytes at the target global `0x089ca864`.
#[repr(C)]
pub struct GlobalStatusFlags {
    pub active: u8,
    pub reset_marked: u8,
}

/// Host/test backing for the target global `0x089ca864`.
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_STATUS_FLAGS: GlobalStatusFlags = GlobalStatusFlags {
    active: 0,
    reset_marked: 0,
};

/// `global_status_flags_reset` — original: `FUN_0804b3e4` @ `0x0804b3e4`
/// (24 bytes including literal; no outbound `bl`, two inbound plain `bl`,
/// and no predicated `bl` calls).
///
/// Writes `reset_marked` before clearing `active`, exactly matching the two
/// byte stores in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_status_flags_reset() {
    #[cfg(target_os = "none")]
    let flags = core::ptr::without_provenance_mut::<u8>(0x089c_a864);
    #[cfg(not(target_os = "none"))]
    let flags = core::ptr::addr_of_mut!(GLOBAL_STATUS_FLAGS).cast::<u8>();

    flags.add(1).write_volatile(1);
    flags.write_volatile(0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::Mutex;

    use super::*;

    static GLOBAL_STATUS_FLAGS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn marks_reset_and_clears_active_for_every_initial_flag_combination() {
        let _lock = GLOBAL_STATUS_FLAGS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        unsafe {
            let flags = core::ptr::addr_of_mut!(GLOBAL_STATUS_FLAGS);
            for active in 0..=1 {
                for reset_marked in 0..=1 {
                    (*flags).active = active;
                    (*flags).reset_marked = reset_marked;
                    global_status_flags_reset();
                    assert_eq!((*flags).active, 0);
                    assert_eq!((*flags).reset_marked, 1);
                }
            }
        }
    }
}
