//! Port of the block-manager client's **reservation** operation.
//!
//! `client_reserve` — original: `FUN_081fbe4c` @ 0x081fbe4c (132 bytes;
//! 6 verified plain `bl` call sites at 0x0814bcc0, 0x081a7e84, 0x081f7390,
//! 0x08213fc4, 0x082234d4, and 0x08235fc4; no predicated calls). Under the
//! client's C++ mutex at +0x24, it records the caller's byte limit at +0x48
//! and request kind at +0x40. If the 0x40000 state flag is absent, it sets
//! 0x20000 and, only on that bit's first transition, queries the manager's
//! available-block count. A count below the manager's +0x34 low-capacity
//! limit notifies the manager with event code 10 and returns 1. On the
//! first transition only, a count at or above that limit returns 0; all
//! other paths return 1. It always unlocks before returning.
//!
//! # Deliberate deviations
//!
//! The manager helpers are unported: block-count materialization
//! `FUN_0818aca8` @ 0x0818aca8 and event enqueue `FUN_0818a3b4` @ 0x0818a3b4.
//! They dispatch through [`CLIENT_RESERVE_OPS`]. The default count is
//! `u32::MAX`: after the real, non-NULL manager field is loaded, it prevents
//! a false low-capacity event until the materializer is ported.

use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::util::state_flags::{state_flags_contain, state_flags_set};

const HEADROOM_FLAG: u32 = 0x40000;
const RESERVATION_FLAG: u32 = 0x20000;
const LOW_CAPACITY_EVENT: u32 = 10;

/// Target-width prefix through the fields this operation owns. The manager is
/// a u32 target pointer: on-device it is four bytes wide even when host tests
/// run on a 64-bit process.
#[repr(C)]
struct Client {
    _header: u32,
    manager: u32,
    _before_mutex: [u32; 7],
    mutex: [u32; 7],
    request_kind: u32,
    state_flags: u32,
    byte_limit: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(Client, manager)];
const _: [u8; 0x24] = [0; core::mem::offset_of!(Client, mutex)];
const _: [u8; 0x40] = [0; core::mem::offset_of!(Client, request_kind)];
const _: [u8; 0x44] = [0; core::mem::offset_of!(Client, state_flags)];
const _: [u8; 0x48] = [0; core::mem::offset_of!(Client, byte_limit)];

/// Target-width prefix through the manager's low-capacity limit read before
/// `FUN_0818aca8`.
#[repr(C)]
struct BlockManager {
    _before_low_capacity_limit: [u32; 13],
    low_capacity_limit: u32,
}

const _: [u8; 0x34] = [0; core::mem::offset_of!(BlockManager, low_capacity_limit)];

/// Indirect dispatch table for the two unported manager helpers.
#[derive(Clone, Copy)]
pub struct ClientReserveOps {
    /// Available-block materialization @ 0x0818aca8 `(manager)`. It returns
    /// the manager's cached total, populating its +0x1bc cache when -1.
    pub available_blocks: unsafe extern "C" fn(manager: *mut u8) -> u32,
    /// Manager notification @ 0x0818a3b4 `(manager, 10)`.
    pub notify: unsafe extern "C" fn(manager: *mut u8, event: u32) -> i32,
}

/// The manager helper is unported; the largest possible count suppresses a
/// spurious low-capacity notification.
unsafe extern "C" fn stub_available_blocks(_manager: *mut u8) -> u32 {
    u32::MAX
}

/// Notification is unreachable with the default count.
unsafe extern "C" fn stub_notify(_manager: *mut u8, _event: u32) -> i32 {
    0
}

/// Wired defaults until the manager helpers are ported.
pub(crate) const DEFAULT_CLIENT_RESERVE_OPS: ClientReserveOps = ClientReserveOps {
    available_blocks: stub_available_blocks,
    notify: stub_notify,
};

/// Active manager boundary. Target initialization may replace it; host tests
/// install recorders and restore the default.
pub static mut CLIENT_RESERVE_OPS: ClientReserveOps = DEFAULT_CLIENT_RESERVE_OPS;

macro_rules! reserve_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CLIENT_RESERVE_OPS.$field)) }
    };
}

macro_rules! mutex_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) }
    };
}

/// client_reserve — original: `FUN_081fbe4c` @ 0x081fbe4c (132 bytes).
///
/// Records `byte_limit` and `request_kind`, raising a single low-capacity
/// event when the first reservation observes fewer available blocks than the
/// manager's +0x34 limit. That event path returns 1; only an at-or-above
/// limit result on this first transition returns 0.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn client_reserve(
    client: *mut u8,
    byte_limit: usize,
    request_kind: usize,
) -> i32 {
    let client = client.cast::<Client>();
    let mutex = core::ptr::addr_of_mut!((*client).mutex).cast::<u8>();
    (mutex_op!(lock))(mutex);

    core::ptr::addr_of_mut!((*client).byte_limit).write_volatile(byte_limit as u32);
    let mut result = 1;
    core::ptr::addr_of_mut!((*client).request_kind).write_volatile(request_kind as u32);
    if state_flags_contain(client.cast(), HEADROOM_FLAG) == 0
        && state_flags_set(client.cast(), RESERVATION_FLAG) != RESERVATION_FLAG
    {
        let manager = (*client).manager as usize as *mut BlockManager;
        let low_capacity_limit = (*manager).low_capacity_limit;
        if (reserve_op!(available_blocks))(manager.cast()) >= low_capacity_limit {
            result = 0;
        } else {
            (reserve_op!(notify))(manager.cast(), LOW_CAPACITY_EVENT);
        }
    }

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
    const MANAGER_AT: usize = 0x300;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CLIENT_RESERVE, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Lock(usize),
        Available(usize),
        Notify { manager: usize, event: u32 },
        Unlock(usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();
    static mut AVAILABLE: u32 = 0;

    fn push(event: Event) {
        unsafe { (*addr_of_mut!(EVENTS)).push(event) }
    }

    fn events() -> Vec<Event> {
        unsafe { (*addr_of!(EVENTS)).clone() }
    }

    unsafe extern "C" fn mock_lock(mutex: *mut u8) -> u32 {
        push(Event::Lock(mutex as usize));
        0
    }

    unsafe extern "C" fn mock_unlock(mutex: *mut u8) -> u32 {
        push(Event::Unlock(mutex as usize));
        0
    }

    unsafe extern "C" fn mock_available(manager: *mut u8) -> u32 {
        push(Event::Available(manager as usize));
        unsafe { addr_of!(AVAILABLE).read() }
    }

    unsafe extern "C" fn mock_notify(manager: *mut u8, event: u32) -> i32 {
        push(Event::Notify {
            manager: manager as usize,
            event,
        });
        0
    }

    fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            (*addr_of_mut!(EVENTS)).clear();
            addr_of_mut!(AVAILABLE).write(0);
            addr_of_mut!(CLIENT_RESERVE_OPS).write(ClientReserveOps {
                available_blocks: mock_available,
                notify: mock_notify,
            });
            addr_of_mut!(REGION_MUTEX_OPS).write(RegionMutexOps {
                lock: mock_lock,
                unlock: mock_unlock,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(CLIENT_RESERVE_OPS).write(DEFAULT_CLIENT_RESERVE_OPS);
            addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS);
        }
        drop(guard);
    }

    unsafe fn client_fixture() -> Option<(*mut Client, *mut BlockManager)> {
        let slab = (*SLAB)? as *mut u8;
        core::ptr::write_bytes(slab, 0, SLAB_LEN);
        let client = slab.add(CLIENT_AT).cast::<Client>();
        let manager = slab.add(MANAGER_AT).cast::<BlockManager>();
        (*client).manager = manager as u32;
        Some((client, manager))
    }

    #[test]
    fn first_reservation_below_capacity_notifies_and_returns_one() {
        let guard = install();
        unsafe {
            let Some((client, manager)) = client_fixture() else {
                assert!(note_missing_u32_fixture("heap/client_reserve"));
                restore(guard);
                return;
            };
            (*manager).low_capacity_limit = 6;
            addr_of_mut!(AVAILABLE).write(5);

            assert_eq!(client_reserve(client.cast(), 0x200, 0x77), 1);
            assert_eq!((*client).byte_limit, 0x200);
            assert_eq!((*client).request_kind, 0x77);
            assert_eq!((*client).state_flags, RESERVATION_FLAG);
            let mutex = core::ptr::addr_of_mut!((*client).mutex) as usize;
            assert_eq!(
                events(),
                std::vec![
                    Event::Lock(mutex),
                    Event::Available(manager as usize),
                    Event::Notify { manager: manager as usize, event: LOW_CAPACITY_EVENT },
                    Event::Unlock(mutex),
                ]
            );
        }
        restore(guard);
    }

    #[test]
    fn headroom_or_a_prior_reservation_skips_manager_callbacks() {
        let guard = install();
        unsafe {
            let Some((client, _manager)) = client_fixture() else {
                assert!(note_missing_u32_fixture("heap/client_reserve"));
                restore(guard);
                return;
            };
            (*client).state_flags = HEADROOM_FLAG;
            assert_eq!(client_reserve(client.cast(), 9, 3), 1);
            assert_eq!((*client).byte_limit, 9);
            assert_eq!((*client).request_kind, 3);
            assert_eq!(events().len(), 2, "headroom branch only locks and unlocks");

            (*addr_of_mut!(EVENTS)).clear();
            (*client).state_flags = RESERVATION_FLAG;
            assert_eq!(client_reserve(client.cast(), 11, 4), 1);
            assert_eq!((*client).byte_limit, 11);
            assert_eq!((*client).request_kind, 4);
            assert_eq!(events().len(), 2, "existing 0x20000 skips the manager");
        }
        restore(guard);
    }

    #[test]
    fn capacity_at_or_above_limit_returns_zero_without_notification() {
        let guard = install();
        unsafe {
            let Some((client, manager)) = client_fixture() else {
                assert!(note_missing_u32_fixture("heap/client_reserve"));
                restore(guard);
                return;
            };
            (*manager).low_capacity_limit = 12;
            addr_of_mut!(AVAILABLE).write(12);
            assert_eq!(client_reserve(client.cast(), 0x200, 0), 0);
            assert_eq!((*client).state_flags, RESERVATION_FLAG);
            assert_eq!(
                events(),
                std::vec![
                    Event::Lock(core::ptr::addr_of_mut!((*client).mutex) as usize),
                    Event::Available(manager as usize),
                    Event::Unlock(core::ptr::addr_of_mut!((*client).mutex) as usize),
                ],
                "the original uses unsigned bls: equality returns zero without code 10"
            );
        }
        restore(guard);
    }
}
