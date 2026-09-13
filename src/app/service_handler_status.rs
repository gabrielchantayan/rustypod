//! Service-handler status query.
//!
//! `service_handler_status` — original: `FUN_0818f8a0` @ **0x0818f8a0**
//! (96 bytes, `0x0818f8a0..0x0818f900`; the next separately linked function
//! begins at `0x0818f908`). Ghidra's extent is exact. A complete decode of
//! every ARM `B`/`BL` word in `osos.dec` finds **six direct, unconditional
//! `bl` call sites** (0x08163b88, 0x0818e430, 0x0818e91c, 0x081917e0,
//! 0x0819205c, and 0x081956fc), with no predicated calls or tail branches.
//!
//! Algorithm: begin with status `INT_MAX`. Selectors below three lock their
//! 28-byte table entry at 0x08a25650, load that selector's optional query
//! object from the 0x08a255e4 pointer table, and invoke the unported query
//! routine at 0x081637fc with a stack status word. A zero query return makes
//! that written word the result; any nonzero return restores `INT_MAX`. The
//! mutex release is unconditional once acquired, and both mutex return values
//! are deliberately ignored as in the raw ARM body.
//!
//! Deliberate deviation: host builds use writable stand-ins for the firmware
//! tables and a volatile query seam, allowing the unported callee's return and
//! status-write contract to be tested. Target builds call 0x081637fc directly.

#[cfg(test)]
extern crate std;

#[cfg(not(target_os = "none"))]
use core::ptr;

use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

const SERVICE_HANDLER_COUNT: u32 = 3;
const STATUS_QUERY_TABLE_ADDRESS: usize = 0x08a2_55e4;
const STATUS_LOCK_TABLE_ADDRESS: usize = 0x08a2_5650;
const STATUS_LOCK_WORDS: usize = 7;
const UNAVAILABLE_STATUS: i32 = i32::MAX;

type StatusQuery = unsafe extern "C" fn(*mut u8, *mut i32) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct ServiceHandlerStatusOps {
    query: StatusQuery,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_status_query(object: *mut u8, status: *mut i32) -> u32 {
    let query: StatusQuery = core::mem::transmute(0x0816_37fcusize);
    query(object, status)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_status_query(_object: *mut u8, _status: *mut i32) -> u32 {
    1
}


#[cfg(not(target_os = "none"))]
static mut SERVICE_HANDLER_STATUS_OPS: ServiceHandlerStatusOps = ServiceHandlerStatusOps {
    query: unavailable_status_query,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn status_query_table() -> *const u32 {
    STATUS_QUERY_TABLE_ADDRESS as *const u32
}

#[cfg(not(target_os = "none"))]
static mut HOST_STATUS_QUERY_TABLE: [u32; SERVICE_HANDLER_COUNT as usize] = [0; SERVICE_HANDLER_COUNT as usize];

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn status_query_table() -> *const u32 {
    ptr::addr_of!(HOST_STATUS_QUERY_TABLE).cast()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn status_lock_table() -> *mut [u32; STATUS_LOCK_WORDS] {
    STATUS_LOCK_TABLE_ADDRESS as *mut [u32; STATUS_LOCK_WORDS]
}

#[cfg(not(target_os = "none"))]
static mut HOST_STATUS_LOCK_TABLE: [[u32; STATUS_LOCK_WORDS]; SERVICE_HANDLER_COUNT as usize] =
    [[0; STATUS_LOCK_WORDS]; SERVICE_HANDLER_COUNT as usize];

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn status_lock_table() -> *mut [u32; STATUS_LOCK_WORDS] {
    ptr::addr_of_mut!(HOST_STATUS_LOCK_TABLE).cast()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn status_ops() -> ServiceHandlerStatusOps {
    ptr::read_volatile(ptr::addr_of!(SERVICE_HANDLER_STATUS_OPS))
}

/// Returns a selector's optional service-handler status.
///
/// # Safety
///
/// On target, the status-query and lock tables at 0x08a255e4 and 0x08a25650
/// must be initialized. `selector` is an opaque service-handler selector.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_handler_status(selector: u32) -> i32 {
    let mut status = UNAVAILABLE_STATUS;

    if selector < SERVICE_HANDLER_COUNT {
        let lock = status_lock_table().add(selector as usize).cast::<PosixMutex>();
        posix_mutex_lock(lock);

        let object = status_query_table().add(selector as usize).read();
        if object != 0 {
            #[cfg(target_os = "none")]
            let query_status = firmware_status_query(object as usize as *mut u8, &mut status);
            #[cfg(not(target_os = "none"))]
            let query_status = (status_ops().query)(object as usize as *mut u8, &mut status);
            if query_status != 0 {
                status = UNAVAILABLE_STATUS;
            }
        }

        posix_mutex_unlock(lock);
    }

    status
}

#[cfg(test)]
pub(crate) static SERVICE_HANDLER_STATUS_OPS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::posix_mutex::{DEFAULT_POSIX_MUTEX_OPS, POSIX_MUTEX_OPS, PRE_KERNEL_THREAD};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, POSIX_MUTEX_OPS_TEST_LOCK};

    static mut EXPECTED_OBJECT: *mut u8 = ptr::null_mut();
    static mut EXPECTED_LOCK: *mut PosixMutex = ptr::null_mut();
    static mut QUERY_STATUS: i32 = 0;
    static mut QUERY_RETURN: u32 = 0;
    static mut QUERY_CALLS: u32 = 0;

    unsafe extern "C" fn mock_status_query(object: *mut u8, status: *mut i32) -> u32 {
        assert_eq!(object, EXPECTED_OBJECT);
        assert_eq!((*EXPECTED_LOCK).owner, PRE_KERNEL_THREAD, "the query runs with its selector lock held");
        QUERY_CALLS += 1;
        status.write(QUERY_STATUS);
        QUERY_RETURN
    }

    unsafe fn install(selector: usize, object: *mut u8, status: i32, query_return: u32) -> ServiceHandlerStatusOps {
        let previous = ptr::read_volatile(ptr::addr_of!(SERVICE_HANDLER_STATUS_OPS));
        SERVICE_HANDLER_STATUS_OPS = ServiceHandlerStatusOps { query: mock_status_query };
        HOST_STATUS_QUERY_TABLE = [0; SERVICE_HANDLER_COUNT as usize];
        HOST_STATUS_LOCK_TABLE = [[0; STATUS_LOCK_WORDS]; SERVICE_HANDLER_COUNT as usize];
        HOST_STATUS_QUERY_TABLE[selector] = object as usize as u32;
        EXPECTED_OBJECT = object;
        EXPECTED_LOCK = status_lock_table().add(selector).cast();
        QUERY_STATUS = status;
        QUERY_RETURN = query_return;
        QUERY_CALLS = 0;
        previous
    }

    unsafe fn restore(previous: ServiceHandlerStatusOps) {
        SERVICE_HANDLER_STATUS_OPS = previous;
        HOST_STATUS_QUERY_TABLE = [0; SERVICE_HANDLER_COUNT as usize];
        HOST_STATUS_LOCK_TABLE = [[0; STATUS_LOCK_WORDS]; SERVICE_HANDLER_COUNT as usize];
        EXPECTED_OBJECT = ptr::null_mut();
        EXPECTED_LOCK = ptr::null_mut();
    }

    #[test]
    fn returns_unavailable_for_out_of_range_absent_and_failed_queries() {
        let _ops_guard = SERVICE_HANDLER_STATUS_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _mutex_guard = POSIX_MUTEX_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slab) = try_map_u32_slab(hints::SERVICE_HANDLER_STATUS_QUERY, 4096) else {
            note_missing_u32_fixture("service_handler_status");
            return;
        };

        unsafe {
            let previous_mutex_ops = ptr::read_volatile(ptr::addr_of!(POSIX_MUTEX_OPS));
            ptr::addr_of_mut!(POSIX_MUTEX_OPS).write(DEFAULT_POSIX_MUTEX_OPS);

            let object = slab.add(128);
            let previous = install(2, object, -17, 0);
            assert_eq!(service_handler_status(3), UNAVAILABLE_STATUS);
            assert_eq!(QUERY_CALLS, 0, "out-of-range selectors do not lock or query");

            assert_eq!(service_handler_status(2), -17);
            assert_eq!(QUERY_CALLS, 1);
            assert_eq!((*EXPECTED_LOCK).owner, 0, "the selector lock is released after a successful query");

            QUERY_RETURN = 9;
            QUERY_STATUS = 42;
            assert_eq!(service_handler_status(2), UNAVAILABLE_STATUS, "a query failure overrides its output word");
            assert_eq!(QUERY_CALLS, 2);
            assert_eq!((*EXPECTED_LOCK).owner, 0);

            HOST_STATUS_QUERY_TABLE[1] = 0;
            assert_eq!(service_handler_status(1), UNAVAILABLE_STATUS);
            assert_eq!(QUERY_CALLS, 2, "an absent query object is not invoked");

            restore(previous);
            ptr::addr_of_mut!(POSIX_MUTEX_OPS).write(previous_mutex_ops);
        }
    }
}
