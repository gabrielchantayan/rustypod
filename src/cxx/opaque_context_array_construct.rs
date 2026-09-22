//! `opaque_context_array_construct` — original: `FUN_08261c48` @
//! **0x08261c48** (88 bytes; six plain `bl` instructions, zero predicated
//! calls; three inbound plain-`bl` call sites).
//!
//! Raw `osos.dec` establishes the complete extent from the `push` at
//! 0x08261c48 through the `pop {r3,r4,r5,pc}` at 0x08261c9c. The following
//! `push {r4,lr}` at 0x08261ca0 starts a separately linked sibling.
//!
//! The constructor builds a 0x38-byte mutex/opaque-context base, then two
//! 0x64-byte child contexts at +0x38 and +0x9c. It clears words +0x100 and
//! +0x108, stores `element_count` at +0x104, then delegates allocation and
//! element initialization to 0x08261934. The child constructor and array
//! initializer have no recovered class identity; target builds call their
//! verified entries, while host tests replace only those boundaries. No
//! deliberate behavioral deviation: the target calls retain retailOS order.

use core::ptr;

use super::mutex::cxx_mutex_construct;
use super::opaque_context_initialize::initialize_opaque_context;

const RETAIL_CHILD_CONTEXT_CONSTRUCT: usize = 0x0826_1b70;
const RETAIL_ARRAY_INITIALIZE: usize = 0x0826_1934;
const BASE_SIZE: usize = 0x38;
const CHILD_SIZE: usize = 0x64;
const ARRAY_POINTER_WORD: usize = 0x100 / 4;
const ELEMENT_COUNT_WORD: usize = 0x104 / 4;
const ARRAY_STATUS_WORD: usize = 0x108 / 4;

type ChildContextConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;
type ArrayInitialize = unsafe extern "C" fn(*mut u8, i32, *mut u8, usize);

#[derive(Clone, Copy)]
pub struct OpaqueContextArrayConstructOps {
    pub child_construct: ChildContextConstruct,
    pub array_initialize: ArrayInitialize,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_child_construct(this: *mut u8) -> *mut u8 { this }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_array_initialize(_this: *mut u8, _count: i32, _scope: *mut u8, _seed: usize) {}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_ARRAY_CONSTRUCT_OPS: OpaqueContextArrayConstructOps = OpaqueContextArrayConstructOps {
    child_construct: missing_child_construct,
    array_initialize: missing_array_initialize,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_child(this: *mut u8) -> *mut u8 {
    core::mem::transmute::<usize, ChildContextConstruct>(RETAIL_CHILD_CONTEXT_CONSTRUCT)(this)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_child(this: *mut u8) -> *mut u8 {
    ptr::read_volatile(ptr::addr_of!(OPAQUE_CONTEXT_ARRAY_CONSTRUCT_OPS.child_construct))(this)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn initialize_array(this: *mut u8, count: i32, scope: *mut u8) {
    core::mem::transmute::<usize, ArrayInitialize>(RETAIL_ARRAY_INITIALIZE)(this, count, scope, 0)
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn initialize_array(this: *mut u8, count: i32, scope: *mut u8) {
    ptr::read_volatile(ptr::addr_of!(OPAQUE_CONTEXT_ARRAY_CONSTRUCT_OPS.array_initialize))(this, count, scope, 0)
}

/// Constructs the fixed-layout context owner and its `element_count` array.
///
/// # Safety
///
/// `this` must point to at least 0x10c writable bytes, and each target callee
/// must receive the object layout it expects. There are no NULL guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_context_array_construct(this: *mut u8, element_count: i32) -> *mut u8 {
    cxx_mutex_construct(this, 0, 0, 0);
    initialize_opaque_context(this.add(0x1c).cast::<u32>());
    construct_child(this.add(BASE_SIZE));
    construct_child(this.add(BASE_SIZE + CHILD_SIZE));
    let words = this.cast::<u32>();
    words.add(ARRAY_POINTER_WORD).write(0);
    words.add(ELEMENT_COUNT_WORD).write(element_count as u32);
    words.add(ARRAY_STATUS_WORD).write(0);
    let mut scope = 0usize;
    initialize_array(this, element_count, ptr::addr_of_mut!(scope).cast());
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CHILD_CALLS: [usize; 2] = [0; 2];
    static mut ARRAY_CALL: (usize, i32, usize, usize) = (0, 0, 0, 1);

    unsafe extern "C" fn record_child(this: *mut u8) -> *mut u8 {
        let calls = core::ptr::addr_of_mut!(CHILD_CALLS);
        if (*calls)[0] == 0 { (*calls)[0] = this as usize; } else { (*calls)[1] = this as usize; }
        this
    }
    unsafe extern "C" fn record_array(this: *mut u8, count: i32, scope: *mut u8, seed: usize) {
        *core::ptr::addr_of_mut!(ARRAY_CALL) = (this as usize, count, scope as usize, seed);
    }

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            OPAQUE_CONTEXT_ARRAY_CONSTRUCT_OPS = OpaqueContextArrayConstructOps {
                child_construct: missing_child_construct, array_initialize: missing_array_initialize,
            };
        }}
    }

    #[test]
    fn constructs_children_and_preserves_signed_zero_count() {
        let _lock = LOCK.lock();
        let _restore = Restore;
        unsafe {
            OPAQUE_CONTEXT_ARRAY_CONSTRUCT_OPS = OpaqueContextArrayConstructOps { child_construct: record_child, array_initialize: record_array };
            CHILD_CALLS = [0; 2]; ARRAY_CALL = (0, 0, 0, 1);
            let mut object = [0xa5a5_a5a5u32; 0x10c / 4];
            let this = object.as_mut_ptr().cast::<u8>();
            assert_eq!(opaque_context_array_construct(this, 0), this);
            assert_eq!(CHILD_CALLS, [this.add(0x38) as usize, this.add(0x9c) as usize]);
            assert_eq!(object[ARRAY_POINTER_WORD], 0);
            assert_eq!(object[ELEMENT_COUNT_WORD], 0);
            assert_eq!(object[ARRAY_STATUS_WORD], 0);
            assert_eq!(ARRAY_CALL.0, this as usize);
            assert_eq!(ARRAY_CALL.1, 0);
            assert_ne!(ARRAY_CALL.2, 0);
            assert_eq!(ARRAY_CALL.3, 0);
        }
    }

    #[test]
    fn forwards_negative_count_without_a_rust_range_check() {
        let _lock = LOCK.lock();
        let _restore = Restore;
        unsafe {
            OPAQUE_CONTEXT_ARRAY_CONSTRUCT_OPS = OpaqueContextArrayConstructOps { child_construct: record_child, array_initialize: record_array };
            let mut object = [0u32; 0x10c / 4];
            let this = object.as_mut_ptr().cast::<u8>();
            opaque_context_array_construct(this, -1);
            assert_eq!(object[ELEMENT_COUNT_WORD], u32::MAX);
            assert_eq!(ARRAY_CALL.1, -1);
        }
    }
}
