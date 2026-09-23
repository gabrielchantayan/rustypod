//! Action-context readiness gate.
//!
//! `action_context_is_ready` — original: `FUN_0812cd08` @ `0x0812cd08`
//! (96 bytes; true extent `0x0812cd08..0x0812cd68`; the next function starts
//! with `push {r2-r8,lr}` at `0x0812cd68`). A full raw-image A32 branch decode
//! finds three direct, unconditional `bl` callers (0x0821d824, 0x0821e9e4,
//! and 0x0821ec40), with no predicated `bl` callers.
//!
//! Algorithm: require a nonzero result from an opaque primary object's vtable
//! slot `+0x90`, then from an action context's slot `+0x08`, then require the
//! context's slot `+0x164` 64-bit result to be nonzero. The called methods are
//! virtual and remain deliberately unnamed; their identities are not implied
//! by their slots. Host builds use replaceable ABI seams because ARM vtables
//! contain four-byte function-address words while host function pointers are
//! wider. Deliberate deviation: the stock final `cmp`/conditional return is
//! expressed as a Rust boolean normalization.

type ObjectReadyQuery = unsafe extern "C" fn(*mut u8) -> u32;
type ContextValueQuery = unsafe extern "C" fn(*mut u8) -> u64;

const PRIMARY_READY_SLOT: usize = 0x90;
const CONTEXT_READY_SLOT: usize = 0x08;
const CONTEXT_VALUE_SLOT: usize = 0x164;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_ready_query(_object: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_context_value_query(_context: *mut u8) -> u64 { 0 }

#[cfg(not(target_os = "none"))]
pub static mut PRIMARY_READY_QUERY: ObjectReadyQuery = missing_object_ready_query;
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_READY_QUERY: ObjectReadyQuery = missing_object_ready_query;
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_VALUE_QUERY: ContextValueQuery = missing_context_value_query;

#[cfg(target_os = "none")]
unsafe fn vtable_object_ready_query(object: *mut u8, slot: usize) -> u32 {
    let vtable = unsafe { object.cast::<u32>().read() as *const u8 };
    let query = unsafe {
        core::mem::transmute::<usize, ObjectReadyQuery>(vtable.add(slot).cast::<u32>().read() as usize)
    };
    unsafe { query(object) }
}

#[cfg(target_os = "none")]
unsafe fn vtable_context_value_query(context: *mut u8) -> u64 {
    let vtable = unsafe { context.cast::<u32>().read() as *const u8 };
    let query = unsafe {
        core::mem::transmute::<usize, ContextValueQuery>(vtable.add(CONTEXT_VALUE_SLOT).cast::<u32>().read() as usize)
    };
    unsafe { query(context) }
}

/// Checks the three virtual readiness conditions used before an action starts.
///
/// Original: `FUN_0812cd08` @ `0x0812cd08` (96 bytes). Both pointers are
/// unchecked ARM-layout objects whose first word is their vtable address.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn action_context_is_ready(primary: *mut u8, context: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    if unsafe { vtable_object_ready_query(primary, PRIMARY_READY_SLOT) } == 0 {
        return 0;
    }
    #[cfg(not(target_os = "none"))]
    if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PRIMARY_READY_QUERY))(primary) } == 0 {
        return 0;
    }

    #[cfg(target_os = "none")]
    if unsafe { vtable_object_ready_query(context, CONTEXT_READY_SLOT) } == 0 {
        return 0;
    }
    #[cfg(not(target_os = "none"))]
    if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONTEXT_READY_QUERY))(context) } == 0 {
        return 0;
    }

    #[cfg(target_os = "none")]
    let value = unsafe { vtable_context_value_query(context) };
    #[cfg(not(target_os = "none"))]
    let value = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONTEXT_VALUE_QUERY))(context) };
    (value != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut PRIMARY_RESULT: u32 = 0;
    static mut CONTEXT_RESULT: u32 = 0;
    static mut VALUE_RESULT: u64 = 0;
    static mut CONTEXT_QUERY_CALLS: u32 = 0;
    static mut VALUE_QUERY_CALLS: u32 = 0;

    unsafe extern "C" fn primary_query(_primary: *mut u8) -> u32 { PRIMARY_RESULT }
    unsafe extern "C" fn context_query(_context: *mut u8) -> u32 {
        CONTEXT_QUERY_CALLS += 1;
        CONTEXT_RESULT
    }
    unsafe extern "C" fn value_query(_context: *mut u8) -> u64 {
        VALUE_QUERY_CALLS += 1;
        VALUE_RESULT
    }

    unsafe fn install_queries() {
        PRIMARY_READY_QUERY = primary_query;
        CONTEXT_READY_QUERY = context_query;
        CONTEXT_VALUE_QUERY = value_query;
        CONTEXT_QUERY_CALLS = 0;
        VALUE_QUERY_CALLS = 0;
    }

    #[test]
    fn accepts_only_when_each_virtual_result_is_nonzero() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            install_queries();
            PRIMARY_RESULT = 1;
            CONTEXT_RESULT = 1;
            VALUE_RESULT = 1u64 << 32;
            assert_eq!(action_context_is_ready(core::ptr::null_mut(), core::ptr::null_mut()), 1);
            assert_eq!(CONTEXT_QUERY_CALLS, 1);
            assert_eq!(VALUE_QUERY_CALLS, 1);
        }
    }

    #[test]
    fn short_circuits_failed_queries_and_rejects_zero_u64() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            install_queries();
            PRIMARY_RESULT = 0;
            CONTEXT_RESULT = 1;
            VALUE_RESULT = 1;
            assert_eq!(action_context_is_ready(core::ptr::null_mut(), core::ptr::null_mut()), 0);
            assert_eq!(CONTEXT_QUERY_CALLS, 0);
            assert_eq!(VALUE_QUERY_CALLS, 0);

            PRIMARY_RESULT = 1;
            CONTEXT_RESULT = 0;
            assert_eq!(action_context_is_ready(core::ptr::null_mut(), core::ptr::null_mut()), 0);
            assert_eq!(CONTEXT_QUERY_CALLS, 1);
            assert_eq!(VALUE_QUERY_CALLS, 0);

            CONTEXT_RESULT = 1;
            VALUE_RESULT = 0;
            assert_eq!(action_context_is_ready(core::ptr::null_mut(), core::ptr::null_mut()), 0);
            assert_eq!(VALUE_QUERY_CALLS, 1);
        }
    }
}
