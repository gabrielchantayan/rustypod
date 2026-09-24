//! `status_value_set` — original: `FUN_0811a200` @ 0x0811a200
//! (88 bytes, 0x0811a200..0x0811a258: 84 bytes of code plus the literal
//! `0x4c737453` at 0x0811a254). The next real function begins with `push
//! {r4, r5, r6, lr}` at 0x0811a258. Raw A32 decoding finds **5 direct
//! unconditional `bl` instructions**; binary-wide decoding finds **3
//! unconditional plain `bl` callers** and zero predicated `bl` callers.
//!
//! # Algorithm
//!
//! If the status word at +0xb4 differs from `value`, stores `value`, allocates
//! a 28-byte kind-0x1f message from the message-kind arena, initializes it
//! with literal first payload `0x4c737453`, zero second and byte payloads,
//! `value` as the fourth payload, and zero fifth payload. It dispatches the
//! message with a NULL explicit target, then calls the unported no-argument
//! notifier at 0x0806e488 with `1`. Equal values do nothing.
//!
//! # Deliberate deviations
//!
//! `FUN_08110e4c` is the existing target-only `message_dispatch` seam.
//! `FUN_0806e488` has no established semantic name or Rust port, so its
//! address is exposed only as an explicit target/host-test notifier seam.

use crate::app::kind_0x1f_message::{kind_0x1f_message_construct, Kind0x1fMessage, KIND_0X1F_MESSAGE_SIZE};
use crate::app::message_kind_arena::message_kind_arena_pool;
use crate::app::three_word_message_post::{message_dispatch, MessageDispatch};
use crate::heap::fixed_block_pool::{fixed_block_pool_alloc, FixedBlockPool};

/// `ldr r0, [r0, #0xb4]` / `str r1, [r4, #0xb4]`: the changed status value.
pub const STATUS_VALUE_OFFSET: usize = 0xb4;
/// `ldr r1, [pc, #28]` at 0x0811a230.
pub const STATUS_VALUE_MESSAGE_FIRST_PAYLOAD: u32 = 0x4c73_7453;
/// RetailOS address of the unported `FUN_0806e488` notifier.
pub const STATUS_VALUE_NOTIFIER_ADDRESS: usize = 0x0806_e488;

/// The prefix of the owning object touched by this function.
#[repr(C)]
pub struct StatusValueOwner {
    pub unused_000: [u32; STATUS_VALUE_OFFSET / 4],
    pub status_value: u32,
}

const _: [u8; STATUS_VALUE_OFFSET] = [0; core::mem::offset_of!(StatusValueOwner, status_value)];
const _: [u8; STATUS_VALUE_OFFSET + 4] = [0; core::mem::size_of::<StatusValueOwner>()];

pub type StatusValueNotifier = unsafe extern "C" fn(u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_status_value_notifier(value: u32) {
    let notifier: StatusValueNotifier = unsafe { core::mem::transmute(STATUS_VALUE_NOTIFIER_ADDRESS) };
    unsafe { notifier(value) }
}

unsafe extern "C" fn default_dispatch(message: *mut crate::app::message_kind::MessageKind, target: *mut u8) -> u32 {
    unsafe { message_dispatch()(message, target) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_status_value_notifier(_value: u32) {
    panic!("status value notifier requires retailOS 0x0806e488")
}

#[derive(Clone, Copy)]
pub struct StatusValueSetOps {
    pub pool: unsafe extern "C" fn() -> *mut FixedBlockPool,
    pub alloc: unsafe extern "C" fn(*mut FixedBlockPool, usize) -> *mut u8,
    pub construct: unsafe extern "C" fn(*mut Kind0x1fMessage, u32, u32, u32, u32, u32) -> *mut Kind0x1fMessage,
    pub dispatch: MessageDispatch,
    pub notify: StatusValueNotifier,
}

pub const DEFAULT_STATUS_VALUE_SET_OPS: StatusValueSetOps = StatusValueSetOps {
    pool: message_kind_arena_pool,
    dispatch: default_dispatch,
    alloc: fixed_block_pool_alloc,
    construct: kind_0x1f_message_construct,
    notify: {
        #[cfg(target_os = "none")]
        { retail_status_value_notifier }
        #[cfg(not(target_os = "none"))]
        { missing_status_value_notifier }
    },
};

/// Active callees; host tests replace these target boundaries with recorders.
pub static mut STATUS_VALUE_SET_OPS: StatusValueSetOps = DEFAULT_STATUS_VALUE_SET_OPS;

#[inline(always)]
unsafe fn ops() -> StatusValueSetOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STATUS_VALUE_SET_OPS)) }
}

/// status_value_set — original: `FUN_0811a200` @ 0x0811a200
/// (88 bytes; **5 direct unconditional `bl` instructions; 3 unconditional
/// `bl` callers, 0 predicated**).
///
/// Updates the owner's +0xb4 status word and announces a changed value through
/// the exact kind-0x1f message and notifier sequence used by retailOS.
/// # Safety
///
/// `owner` must cover its writable +0xb4 word. The changed path has the
/// original's unchecked allocation and dispatcher preconditions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn status_value_set(owner: *mut StatusValueOwner, value: u32) {
    if unsafe { (*owner).status_value } == value {
        return;
    }
    unsafe { (*owner).status_value = value };
    let ops = unsafe { ops() };
    let storage = unsafe { (ops.alloc)((ops.pool)(), KIND_0X1F_MESSAGE_SIZE) };
    let message = unsafe {
        (ops.construct)(storage.cast(), STATUS_VALUE_MESSAGE_FIRST_PAYLOAD, 0, 0, value, 0)
    };
    unsafe { (ops.dispatch)(message.cast(), core::ptr::null_mut()) };
    unsafe { (ops.notify)(1) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call { Pool, Alloc(usize, usize), Construct(usize, u32, u32, u32, u32, u32), Dispatch(usize, usize), Notify(u32) }
    static mut CALLS: std::vec::Vec<Call> = std::vec::Vec::new();
    static mut ALLOC_RESULT: *mut u8 = ptr::null_mut();
    static mut CONSTRUCT_RESULT: *mut Kind0x1fMessage = ptr::null_mut();

    unsafe extern "C" fn pool() -> *mut FixedBlockPool { unsafe { (*ptr::addr_of_mut!(CALLS)).push(Call::Pool) }; 0x1020usize as *mut FixedBlockPool }
    unsafe extern "C" fn alloc(pool: *mut FixedBlockPool, size: usize) -> *mut u8 { unsafe { (*ptr::addr_of_mut!(CALLS)).push(Call::Alloc(pool as usize, size)); ALLOC_RESULT } }
    unsafe extern "C" fn construct(storage: *mut Kind0x1fMessage, a: u32, b: u32, c: u32, d: u32, e: u32) -> *mut Kind0x1fMessage { unsafe { (*ptr::addr_of_mut!(CALLS)).push(Call::Construct(storage as usize, a, b, c, d, e)); CONSTRUCT_RESULT } }
    unsafe extern "C" fn dispatch(message: *mut crate::app::message_kind::MessageKind, target: *mut u8) -> u32 { unsafe { (*ptr::addr_of_mut!(CALLS)).push(Call::Dispatch(message as usize, target as usize)) }; 0 }
    unsafe extern "C" fn notify(value: u32) { unsafe { (*ptr::addr_of_mut!(CALLS)).push(Call::Notify(value)) } }

    fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            STATUS_VALUE_SET_OPS = StatusValueSetOps { pool, alloc, construct, dispatch, notify };
            (*ptr::addr_of_mut!(CALLS)).clear();
            ALLOC_RESULT = 0x3040usize as *mut u8;
            CONSTRUCT_RESULT = 0x5060usize as *mut Kind0x1fMessage;
        }
        guard
    }
    fn restore(guard: MutexGuard<'static, ()>) { unsafe { STATUS_VALUE_SET_OPS = DEFAULT_STATUS_VALUE_SET_OPS }; drop(guard) }
    fn calls() -> std::vec::Vec<Call> { unsafe { (*ptr::addr_of!(CALLS)).clone() } }
    fn owner(value: u32) -> StatusValueOwner { StatusValueOwner { unused_000: [0; STATUS_VALUE_OFFSET / 4], status_value: value } }

    #[test]
    fn equal_value_does_not_announce() {
        let guard = install();
        let mut owner = owner(0x1122_3344);
        unsafe { status_value_set(&mut owner, 0x1122_3344) };
        assert_eq!(owner.status_value, 0x1122_3344);
        assert!(calls().is_empty());
        restore(guard);
    }

    #[test]
    fn changed_value_stores_and_announces_exact_message() {
        let guard = install();
        let mut owner = owner(7);
        unsafe { status_value_set(&mut owner, 0xaabb_ccdd) };
        assert_eq!(owner.status_value, 0xaabb_ccdd);
        assert_eq!(calls(), [
            Call::Pool,
            Call::Alloc(0x1020, KIND_0X1F_MESSAGE_SIZE),
            Call::Construct(0x3040, STATUS_VALUE_MESSAGE_FIRST_PAYLOAD, 0, 0, 0xaabb_ccdd, 0),
            Call::Dispatch(0x5060, 0),
            Call::Notify(1),
        ]);
        restore(guard);
    }
}
