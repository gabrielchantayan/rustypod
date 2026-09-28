//! Registers a callback-produced context scope for an element-table entry.
//!
//! `element_callback_scope_register` — original: `FUN_0839bd20` @
//! `0x0839bd20` (**148 bytes**, `0x0839bd20..0x0839bdb3`; the next real
//! function starts at `0x0839bdb4`). Raw A32 decoding finds **2 inbound plain
//! `bl` calls** (`0x082c7a7c`, `0x082c7bac`) and no predicated inbound `bl`.
//! Its body contains six plain direct `bl` instructions, no predicated direct
//! `bl`, and one unconditional indirect `blx` callback.
//!
//! It looks up `element_index` in element array 0, allocates a 20-byte context
//! scope, invokes either the supplied callback or a tagged callback-table
//! entry to fill that scope, then constructs a second scope around the filled
//! scope's subject and registers it in element table array 5. A missing element
//! returns `-1` before allocating or invoking anything.
//!
//! Deliberate deviations: the unported array-5 insertion at `0x083d5040` has
//! no invented identity and remains a fixed retailOS call on target; host tests
//! replace it, allocation, lookup, and callback dispatch with structural seams.


use core::mem::MaybeUninit;

#[cfg(target_os = "none")]
use crate::app::{context_scope::{context_scope_drop, context_scope_init}, element_table::element_array0_at};
use crate::app::context_scope::CONTEXT_SCOPE_SIZE;
#[cfg(target_os = "none")]
use crate::heap::veneers::operator_new;

const ELEMENT_TABLE_ARRAY5_OFFSET: usize = 0x78;
const RETAIL_ELEMENT_ARRAY5_INSERT: usize = 0x083d_5040;
type ScopeCallback = unsafe extern "C" fn(*mut u8, *mut u8, u32);
type ArrayInsert = unsafe extern "C" fn(*mut u8, *mut u8) -> i32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn register_scope(scope: *mut u8) -> i32 {
    let table = crate::app::element_table::element_table();
    let insert: ArrayInsert = unsafe { core::mem::transmute(RETAIL_ELEMENT_ARRAY5_INSERT) };
    unsafe { insert(table.add(ELEMENT_TABLE_ARRAY5_OFFSET), scope) }
}

/// # Safety
///
/// `callback_target` must be a code pointer when `callback_selector` is even.
/// When it is odd, its low two bits are ignored and the selected word at
/// `callback_target + (callback_selector as i32 >> 1)` must be a code pointer.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_callback_scope_register(
    _out: *mut u32,
    element_index: i32,
    callback_argument: u32,
    callback_target: u32,
    callback_selector: u32,
) -> i32 {
    let element = unsafe { element_array0_at(element_index) };
    if element.is_null() {
        return -1;
    }

    let mut callback_scope = MaybeUninit::<[u8; CONTEXT_SCOPE_SIZE]>::uninit();
    let callback_scope = callback_scope.as_mut_ptr().cast::<u8>();
    let scope = unsafe { operator_new(CONTEXT_SCOPE_SIZE) }.cast::<u8>();
    let callback_word = if callback_selector & 1 == 0 {
        callback_target
    } else {
        let offset = (callback_selector as i32 >> 1) as isize;
        unsafe { ((callback_target & !3) as *const u8).offset(offset).cast::<u32>().read() }
    };
    let callback: ScopeCallback = unsafe { core::mem::transmute(callback_word as usize) };
    unsafe { callback(callback_scope, element, callback_argument) };

    let subject = unsafe { callback_scope.add(4).cast::<u32>().read() } as usize as *mut u8;
    let registered_scope = unsafe { context_scope_init(scope, subject, 0) };
    unsafe { context_scope_drop(callback_scope) };
    unsafe { register_scope(registered_scope) }
}

#[cfg(not(target_os = "none"))]
pub type ElementLookup = unsafe extern "C" fn(i32) -> *mut u8;
#[cfg(not(target_os = "none"))]
pub type ScopeAllocate = unsafe extern "C" fn(usize) -> *mut u8;
#[cfg(not(target_os = "none"))]
pub type ScopeInitialize = unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8;
#[cfg(not(target_os = "none"))]
pub type ScopeDrop = unsafe extern "C" fn(*mut u8);
#[cfg(not(target_os = "none"))]
pub type ScopeRegister = unsafe extern "C" fn(*mut u8) -> i32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ElementCallbackScopeRegisterOps {
    pub lookup: ElementLookup,
    pub allocate: ScopeAllocate,
    pub initialize: ScopeInitialize,
    pub drop: ScopeDrop,
    pub register: ScopeRegister,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_: i32) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate(_: usize) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initialize(scope: *mut u8, _: *mut u8) -> *mut u8 { scope }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_drop(_: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_register(_: *mut u8) -> i32 { 0 }

#[cfg(not(target_os = "none"))]
pub const DEFAULT_ELEMENT_CALLBACK_SCOPE_REGISTER_OPS: ElementCallbackScopeRegisterOps = ElementCallbackScopeRegisterOps {
    lookup: missing_lookup,
    allocate: missing_allocate,
    initialize: missing_initialize,
    drop: missing_drop,
    register: missing_register,
};
#[cfg(not(target_os = "none"))]
pub static mut ELEMENT_CALLBACK_SCOPE_REGISTER_OPS: ElementCallbackScopeRegisterOps = DEFAULT_ELEMENT_CALLBACK_SCOPE_REGISTER_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn ops() -> ElementCallbackScopeRegisterOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ELEMENT_CALLBACK_SCOPE_REGISTER_OPS)) }
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn element_callback_scope_register(
    _out: *mut u32,
    element_index: i32,
    callback_argument: u32,
    callback_target: usize,
    callback_selector: u32,
) -> i32 {
    let operations = unsafe { ops() };
    let element = unsafe { (operations.lookup)(element_index) };
    if element.is_null() {
        return -1;
    }

    let mut callback_scope = MaybeUninit::<[u8; CONTEXT_SCOPE_SIZE]>::uninit();
    let callback_scope = callback_scope.as_mut_ptr().cast::<u8>();
    let scope = unsafe { (operations.allocate)(CONTEXT_SCOPE_SIZE) };
    let callback_address = if callback_selector & 1 == 0 {
        callback_target
    } else {
        let offset = (callback_selector as i32 >> 1) as isize;
        unsafe { ((callback_target & !3) as *const u8).offset(offset).cast::<usize>().read() }
    };
    let callback: ScopeCallback = unsafe { core::mem::transmute(callback_address) };
    unsafe { callback(callback_scope, element, callback_argument) };

    let subject = unsafe { callback_scope.add(4).cast::<u32>().read() } as usize as *mut u8;
    let registered_scope = unsafe { (operations.initialize)(scope, subject) };
    unsafe { (operations.drop)(callback_scope) };
    unsafe { (operations.register)(registered_scope) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ELEMENT: u8 = 0;
    static mut SCOPE: [u8; CONTEXT_SCOPE_SIZE] = [0; CONTEXT_SCOPE_SIZE];
    static mut CALLBACK: (usize, usize, u32) = (0, 0, 0);
    static mut INITIALIZED_SUBJECT: usize = 0;
    static mut DROPS: u32 = 0;
    static mut REGISTERED: usize = 0;

    unsafe extern "C" fn lookup(index: i32) -> *mut u8 {
        if index == 7 { core::ptr::addr_of_mut!(ELEMENT) } else { core::ptr::null_mut() }
    }
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        assert_eq!(size, CONTEXT_SCOPE_SIZE);
        core::ptr::addr_of_mut!(SCOPE).cast()
    }
    unsafe extern "C" fn initialize(scope: *mut u8, subject: *mut u8) -> *mut u8 {
        INITIALIZED_SUBJECT = subject as usize;
        scope
    }
    unsafe extern "C" fn drop(_: *mut u8) { DROPS += 1; }
    unsafe extern "C" fn register(scope: *mut u8) -> i32 { REGISTERED = scope as usize; 0x51 }
    unsafe extern "C" fn callback(scope: *mut u8, element: *mut u8, argument: u32) {
        CALLBACK = (scope as usize, element as usize, argument);
        scope.add(4).cast::<u32>().write(0x1234_5678);
    }

    fn install() {
        unsafe {
            ELEMENT_CALLBACK_SCOPE_REGISTER_OPS = ElementCallbackScopeRegisterOps { lookup, allocate, initialize, drop, register };
            SCOPE = [0; CONTEXT_SCOPE_SIZE]; CALLBACK = (0, 0, 0); INITIALIZED_SUBJECT = 0; DROPS = 0; REGISTERED = 0;
        }
    }

    #[test]
    fn missing_element_returns_minus_one_without_side_effects() {
        let _guard = LOCK.lock(); install();
        let result = unsafe { element_callback_scope_register(core::ptr::null_mut(), -1, 1, callback as usize, 0) };
        assert_eq!(result, -1);
        unsafe { assert_eq!(CALLBACK, (0, 0, 0)); assert_eq!(DROPS, 0); }
    }

    #[test]
    fn direct_callback_fills_then_registers_scope() {
        let _guard = LOCK.lock(); install();
        let result = unsafe { element_callback_scope_register(core::ptr::null_mut(), 7, 0xaabb_ccdd, callback as usize, 0) };
        assert_eq!(result, 0x51);
        unsafe {
            assert_ne!(CALLBACK.0, core::ptr::addr_of_mut!(SCOPE).cast::<u8>() as usize);
            assert_eq!(CALLBACK.1, core::ptr::addr_of_mut!(ELEMENT) as usize);
            assert_eq!(CALLBACK.2, 0xaabb_ccdd);
            assert_eq!(INITIALIZED_SUBJECT, 0x1234_5678);
            assert_eq!(DROPS, 1);
            assert_eq!(REGISTERED, core::ptr::addr_of_mut!(SCOPE).cast::<u8>() as usize);
        }
    }

    #[test]
    fn tagged_callback_uses_signed_half_selector_byte_offset() {
        let _guard = LOCK.lock(); install();
        let table = [callback as usize];
        let result = unsafe { element_callback_scope_register(core::ptr::null_mut(), 7, 3, table.as_ptr() as usize, 1) };
        assert_eq!(result, 0x51);
        unsafe { assert_eq!(CALLBACK.2, 3); }
    }
}
