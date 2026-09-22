//! Returns the client-visible number of blocks still available.
//!
//! `client_available_blocks` — original: `FUN_081fc578` @ 0x081fc578
//! (**168 bytes**; **5 plain `bl` instructions and no predicated `bl`**).
//! Raw ARM establishes the exact extent `0x081fc578..0x081fc620`, followed by
//! `FUN_081fc620`. Under the client's mutex at +0x24, it selects either the
//! remaining reservation (`+0x50 - +0x18`) when state flags contain 0x40000
//! but not 0x10000, or the signed produced-to-expected count (`+0x1c - +0x18`).
//! A nonnegative latter count is capped by the manager's cached availability at
//! +0x14 while the manager mutex is held.
//!
//! # Deliberate deviations
//!
//! The two C++ recursive-mutex thunks are the existing
//! [`REGION_MUTEX_OPS`](crate::heap::block_region::REGION_MUTEX_OPS) seam.
//! Their return values are deliberately discarded, as are the original's.

use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::util::state_flags::state_flags_contain;

const HEADROOM_FLAG: u32 = 0x40000;
const SPECIAL_CAPACITY_FLAG: u32 = 0x10000;

#[repr(C)]
struct Client {
    _header: u32,
    manager: u32,
    _before_produced: [u32; 4],
    produced: u32,
    expected: u32,
    _before_mutex: [u32; 1],
    mutex: [u32; 7],
    _before_state_flags: u32,
    state_flags: u32,
    _before_capacity_end: [u32; 2],
    capacity_end: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(Client, manager)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(Client, produced)];
const _: [u8; 0x1c] = [0; core::mem::offset_of!(Client, expected)];
const _: [u8; 0x24] = [0; core::mem::offset_of!(Client, mutex)];
const _: [u8; 0x44] = [0; core::mem::offset_of!(Client, state_flags)];
const _: [u8; 0x50] = [0; core::mem::offset_of!(Client, capacity_end)];

#[repr(C)]
struct BlockManager {
    _before_available: [u32; 5],
    available_blocks: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(BlockManager, available_blocks)];

macro_rules! mutex_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) }
    };
}

/// client_available_blocks — original: `FUN_081fc578` @ 0x081fc578 (168 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn client_available_blocks(client: *mut u8) -> i32 {
    let client = client.cast::<Client>();
    let mutex = core::ptr::addr_of_mut!((*client).mutex).cast::<u8>();
    (mutex_op!(lock))(mutex);

    let result = if state_flags_contain(client.cast(), HEADROOM_FLAG) != 0
        && state_flags_contain(client.cast(), SPECIAL_CAPACITY_FLAG) == 0
    {
        ((*client).capacity_end.wrapping_sub((*client).produced)) as i32
    } else {
        let available = ((*client).expected.wrapping_sub((*client).produced)) as i32;
        if available < 0 {
            available
        } else {
            let manager = (*client).manager as usize as *mut BlockManager;
            let manager_mutex = manager.cast::<u8>().add(0x148);
            (mutex_op!(lock))(manager_mutex);
            let capped = available.min((*manager).available_blocks as i32);
            (mutex_op!(unlock))(manager_mutex);
            capped
        }
    };

    (mutex_op!(unlock))(mutex);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::block_region::{RegionMutexOps, DEFAULT_REGION_MUTEX_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;
    const CLIENT_AT: usize = 0x100;
    const MANAGER_AT: usize = 0x400;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CLIENT_AVAILABLE_BLOCKS, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: Vec<(bool, usize)> = Vec::new();

    fn events() -> Vec<(bool, usize)> {
        unsafe { (*addr_of!(EVENTS)).clone() }
    }

    unsafe extern "C" fn lock(mutex: *mut u8) -> u32 {
        (*addr_of_mut!(EVENTS)).push((true, mutex as usize));
        0
    }

    unsafe extern "C" fn unlock(mutex: *mut u8) -> u32 {
        (*addr_of_mut!(EVENTS)).push((false, mutex as usize));
        0
    }

    fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            (*addr_of_mut!(EVENTS)).clear();
            addr_of_mut!(REGION_MUTEX_OPS).write(RegionMutexOps { lock, unlock });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS) }
        drop(guard);
    }

    unsafe fn fixture() -> Option<(*mut Client, *mut BlockManager)> {
        let slab = (*SLAB)? as *mut u8;
        core::ptr::write_bytes(slab, 0, SLAB_LEN);
        let client = slab.add(CLIENT_AT).cast::<Client>();
        let manager = slab.add(MANAGER_AT).cast::<BlockManager>();
        (*client).manager = manager as u32;
        Some((client, manager))
    }

    #[test]
    fn caps_nonnegative_expected_remaining_at_manager_availability() {
        let guard = install();
        unsafe {
            let Some((client, manager)) = fixture() else {
                assert!(note_missing_u32_fixture("heap/client_available_blocks"));
                restore(guard);
                return;
            };
            (*client).produced = 10;
            (*client).expected = 18;
            (*manager).available_blocks = 6;
            assert_eq!(client_available_blocks(client.cast()), 6);
            assert_eq!(
                events(),
                std::vec![
                    (true, addr_of_mut!((*client).mutex) as usize),
                    (true, (manager as *mut u8).add(0x148) as usize),
                    (false, (manager as *mut u8).add(0x148) as usize),
                    (false, addr_of_mut!((*client).mutex) as usize),
                ]
            );
        }
        restore(guard);
    }

    #[test]
    fn negative_expected_remaining_skips_manager_mutex() {
        let guard = install();
        unsafe {
            let Some((client, _manager)) = fixture() else {
                assert!(note_missing_u32_fixture("heap/client_available_blocks"));
                restore(guard);
                return;
            };
            (*client).produced = 9;
            (*client).expected = 4;
            assert_eq!(client_available_blocks(client.cast()), -5);
            assert_eq!(events().len(), 2);
        }
        restore(guard);
    }

    #[test]
    fn headroom_without_special_flag_uses_reservation_remaining() {
        let guard = install();
        unsafe {
            let Some((client, _manager)) = fixture() else {
                assert!(note_missing_u32_fixture("heap/client_available_blocks"));
                restore(guard);
                return;
            };
            (*client).state_flags = HEADROOM_FLAG;
            (*client).produced = 7;
            (*client).capacity_end = 31;
            assert_eq!(client_available_blocks(client.cast()), 24);
            assert_eq!(events().len(), 2);
        }
        restore(guard);
    }
}
