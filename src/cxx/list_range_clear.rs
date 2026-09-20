//! `list_range_clear` — retailOS `FUN_083dbc04` @ `0x083dbc04`.
//!
//! Raw ARM is exactly 64 bytes, from `push {lr}` at `0x083dbc04` through
//! `pop {r0,r1,r2,r3,r12,pc}` at `0x083dbc40`; `0x083dbc44` begins the next
//! separately entered function. Whole-image decoding finds three incoming
//! plain `bl` calls and no predicated calls. The body has one plain `bl`, to
//! `0x083cd1fc`, and no predicated calls.
//!
//! It loads the target-width list pointer at `this + 0x10`, snapshots that
//! list's word at `+0x08`, and passes both snapshots by address with `this`
//! to the unresolved range worker. The worker's return is deliberately
//! ignored. `0x083cd1fc` has no established identity in `names.yaml`, so the
//! call remains a fixed-address dispatch boundary rather than naming an
//! invented list operation. Deliberate deviation: the direct ARM `bl` becomes
//! a dispatch-boundary `blx`; argument values and stack-local lifetimes are
//! preserved.

use core::ptr::addr_of;

const RETAIL_LIST_RANGE_WORKER_ADDRESS: usize = 0x083c_d1fc;
const LIST_HANDLE_OFFSET: usize = 0x10;
const LIST_RANGE_BOUND_OFFSET: usize = 0x08;

/// ABI of unresolved `FUN_083cd1fc`, as established by the call at
/// `0x083dbc3c`. Its return registers are ignored by this wrapper.
pub type ListRangeWorker = unsafe extern "C" fn(*mut u32, *mut u8, *mut u32, *mut u32);

#[derive(Clone, Copy)]
pub struct ListRangeClearOps {
    pub worker: ListRangeWorker,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_list_range_worker(
    out: *mut u32,
    this: *mut u8,
    range_bound: *mut u32,
    list_handle: *mut u32,
) {
    let worker: ListRangeWorker = unsafe { core::mem::transmute(RETAIL_LIST_RANGE_WORKER_ADDRESS) };
    unsafe { worker(out, this, range_bound, list_handle) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_list_range_worker(
    _out: *mut u32,
    _this: *mut u8,
    _range_bound: *mut u32,
    _list_handle: *mut u32,
) {
    panic!("list_range_clear requires unresolved FUN_083cd1fc")
}

#[cfg(target_os = "none")]
pub const DEFAULT_LIST_RANGE_CLEAR_OPS: ListRangeClearOps = ListRangeClearOps {
    worker: retail_list_range_worker,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_LIST_RANGE_CLEAR_OPS: ListRangeClearOps = ListRangeClearOps {
    worker: missing_list_range_worker,
};

/// Active direct-callee boundary. Host tests install recorders.
pub static mut LIST_RANGE_CLEAR_OPS: ListRangeClearOps = DEFAULT_LIST_RANGE_CLEAR_OPS;

#[inline(always)]
unsafe fn clear_ops() -> ListRangeClearOps {
    unsafe { core::ptr::read_volatile(addr_of!(LIST_RANGE_CLEAR_OPS)) }
}

/// Dispatches the observed list range snapshots to the unresolved worker.
///
/// # Safety
/// `this + 0x10` must contain a valid target-width pointer to an object
/// readable through `+0x08`; the selected worker must accept the four observed
/// arguments and may mutate the pointed-to objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_range_clear(this: *mut u8) {
    let mut list_handle = unsafe { this.add(LIST_HANDLE_OFFSET).cast::<u32>().read() };
    let mut range_bound = unsafe {
        ((list_handle as usize as *mut u8).add(LIST_RANGE_BOUND_OFFSET) as *const u32).read()
    };
    let mut out = list_handle;
    unsafe { (clear_ops().worker)(&mut out, this, &mut range_bound, &mut list_handle) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN: (*mut u8, u32, u32, u32) = (ptr::null_mut(), 0, 0, 0);

    unsafe extern "C" fn record_worker(
        out: *mut u32,
        this: *mut u8,
        range_bound: *mut u32,
        list_handle: *mut u32,
    ) {
        unsafe { SEEN = (this, *out, *range_bound, *list_handle) };
        unsafe { *out = 0xface_cafe };
    }

    #[test]
    fn snapshots_list_handle_and_bound_for_worker() {
        let _lock = OPS_LOCK.lock();
        let Some(list) = try_map_u32_slab(hints::LIST_RANGE_CLEAR, 0x1000) else {
            note_missing_u32_fixture("cxx/list_range_clear");
            return;
        };
        unsafe { ptr::write_bytes(list, 0, 0x1000) };
        unsafe { list.add(LIST_RANGE_BOUND_OFFSET).cast::<u32>().write(0x1234_5678) };
        let mut object = [0u32; 5];
        object[4] = list as usize as u32;

        unsafe {
            SEEN = (ptr::null_mut(), 0, 0, 0);
            let saved = LIST_RANGE_CLEAR_OPS;
            LIST_RANGE_CLEAR_OPS = ListRangeClearOps { worker: record_worker };
            list_range_clear(object.as_mut_ptr().cast());
            LIST_RANGE_CLEAR_OPS = saved;
            assert_eq!(SEEN, (object.as_mut_ptr().cast(), object[4], 0x1234_5678, object[4]));
        }
    }
}
