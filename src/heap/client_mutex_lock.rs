//! `client_mutex_lock` — retailOS `FUN_081fbe3c` at `0x081fbe3c`.
//!
//! Raw ARM words `e2800024 ea0198d8` establish the complete 8-byte body
//! `add r0, r0, #0x24; b 0x082621a8`. The next separately linked function
//! begins at 0x081fbe44. There are three verified inbound plain `bl` call
//! sites (0x0814bb18, 0x0818a860, and 0x08207c78) and no predicated `bl`
//! call sites. This helper derives the block-manager client's mutex at +0x24,
//! then tail-branches to the `posix_mutex_lock` veneer.
//!
//! # Deliberate deviations
//!
//! The target tail branch is represented by the existing `REGION_MUTEX_OPS`
//! seam, which makes a host fixture observable and emits an indirect call
//! instead of the retail direct branch.

use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::heap::client_erase::CLIENT_MUTEX_OFFSET;

/// Acquires the C++ mutex embedded at +0x24 in `client`.
///
/// `client` must point to the block-manager client object, as required by the
/// original unchecked address calculation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.client_mutex_lock")]
#[inline(never)]
pub unsafe extern "C" fn client_mutex_lock(client: *mut u8) -> u32 {
    let lock = core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.lock));
    lock(client.add(CLIENT_MUTEX_OFFSET))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::block_region::RegionMutexOps;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut LOCK_ARG: usize = 0;

    unsafe extern "C" fn record_lock(mutex: *mut u8) -> u32 {
        LOCK_ARG = mutex as usize;
        0x5a
    }
    unsafe extern "C" fn unused_unlock(_mutex: *mut u8) -> u32 { 0 }

    struct Reset {
        _guard: MutexGuard<'static, ()>,
        ops: RegionMutexOps,
    }
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(REGION_MUTEX_OPS).write(self.ops); }
        }
    }
    fn install() -> Reset {
        let guard = LOCK.lock();
        unsafe {
            let ops = addr_of!(REGION_MUTEX_OPS).read();
            REGION_MUTEX_OPS = RegionMutexOps { lock: record_lock, unlock: unused_unlock };
            LOCK_ARG = 0;
            Reset { _guard: guard, ops }
        }
    }

    #[test]
    fn locks_the_client_mutex_at_the_target_offset() {
        let _reset = install();
        let mut client = [0_u8; CLIENT_MUTEX_OFFSET + 1];
        unsafe {
            assert_eq!(client_mutex_lock(client.as_mut_ptr()), 0x5a);
            assert_eq!(LOCK_ARG, client.as_mut_ptr().add(CLIENT_MUTEX_OFFSET) as usize);
        }
    }
}
