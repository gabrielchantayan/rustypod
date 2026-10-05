//! Controller-holder preparation and first-slot lookup.
//!
//! `controller_holder_prepare` — `FUN_081a8f40` @ `0x081a8f40`.
//! True extent: 108 bytes, comprising 96 instruction bytes and three literal
//! words; the next real function starts at `0x081a8fac`. Raw decoding verifies
//! two plain BLs (operator_new @ 0x082aadd4 and the resident initializer @
//! 0x08283a7c), zero predicated BLs, and two plain inbound BLs.
//!
//! If the first holder slot is NULL, allocate 92 bytes, initialize the free/
//! lock tags, selected zero fields, sentinel byte and vtable, invoke the
//! resident initializer, then publish the ORIGINAL allocation in slot +16.
//! Return the reloaded FIRST slot, even when it remains NULL. A non-NULL first
//! slot skips all initialization. Entry r1 is unused by the raw function.
//!
//! Deliberate deviations: repr(C) pointer fields widen on hosts, but retain
//! exact target offsets. Object fields remain aligned 32-bit words. The
//! unported initializer has only a structural identity; target builds call
//! its verified address, while hosts require an explicitly installed seam.
//! LLVM may reorder independent stores; no extra object bytes are cleared.

use core::ptr;

/// Only the accessed prefix of the target holder (published is at +16).
#[repr(C)]
pub struct ControllerHolder {
    pub first: *mut u32,
    pub reserved: [u32; 3],
    pub published: *mut u32,
}

pub type ControllerInitialize = unsafe extern "C" fn(*mut u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initialize(_object: *mut u32) -> u32 {
    panic!("resident controller initializer must be installed on hosts")
}

/// Host-only dependencies; target allocation always uses the existing heap port.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ControllerHolderOps {
    pub allocate: unsafe extern "C" fn(usize) -> *mut u8,
    pub initialize: ControllerInitialize,
}

#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_HOLDER_OPS: ControllerHolderOps = ControllerHolderOps {
    allocate: crate::heap::veneers::operator_new,
    initialize: missing_initialize,
};

/// # Safety
/// `holder` must be writable and valid. Allocation must return 92 writable,
/// word-aligned bytes; the resident initializer's platform preconditions must
/// hold. Host seam replacement must not race with calls.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_holder_prepare(holder: *mut ControllerHolder) -> *mut u32 {
    if ptr::addr_of!((*holder).first).read().is_null() {
        #[cfg(target_os = "none")]
        let object = crate::heap::veneers::operator_new(0x5c).cast::<u32>();
        #[cfg(not(target_os = "none"))]
        let object = (ptr::addr_of!(CONTROLLER_HOLDER_OPS).read().allocate)(0x5c).cast::<u32>();
        object.add(5).write(0x6672_6565);
        object.add(4).write(0);
        object.cast::<u8>().add(0x20).write(0xff);
        object.add(10).write(0);
        object.add(6).write(0x216c_636b);
        object.add(11).write(0);
        object.write(0x089a_652c);
        #[cfg(target_os = "none")]
        let initialize: ControllerInitialize = core::mem::transmute(0x0828_3a7cusize);
        #[cfg(not(target_os = "none"))]
        let initialize = ptr::addr_of!(CONTROLLER_HOLDER_OPS).read().initialize;
        initialize(object);
        ptr::addr_of_mut!((*holder).published).write(object);
    }
    ptr::addr_of!((*holder).first).read()
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut OBJECT: [u32; 23] = [0; 23];
    static mut HOLDER: *mut ControllerHolder = ptr::null_mut();
    static mut SET_FIRST: bool = false;
    static mut ALLOCATIONS: usize = 0;

    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        assert_eq!(size, 92);
        ALLOCATIONS += 1;
        ptr::addr_of_mut!(OBJECT).cast()
    }
    unsafe extern "C" fn initialize(object: *mut u32) -> u32 {
        let mut expected = [0xa5a5_a5a5; 23];
        expected[0] = 0x089a_652c;
        expected[4] = 0;
        expected[5] = 0x6672_6565;
        expected[6] = 0x216c_636b;
        expected[8] = 0xa5a5_a5ff;
        expected[10] = 0;
        expected[11] = 0;
        assert_eq!(core::slice::from_raw_parts(object, 23), &expected);
        // The allocation must not be published before initialization.
        assert_eq!((*HOLDER).published, 0x1234usize as *mut u32);
        object.add(22).write(0x55aa_aa55);
        if SET_FIRST { (*HOLDER).first = object.add(22); }
        0 // Return value must not replace the allocation.
    }
    struct Restore(ControllerHolderOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { CONTROLLER_HOLDER_OPS = self.0; } }
    }

    #[test]
    fn preserves_distinct_slots_reload_and_partial_initialization() {
        let _lock = LOCK.lock();
        unsafe {
            let _restore = Restore(ptr::addr_of!(CONTROLLER_HOLDER_OPS).read());
            CONTROLLER_HOLDER_OPS = ControllerHolderOps { allocate, initialize };
            let mut holder = ControllerHolder {
                first: ptr::null_mut(), reserved: [7, 8, 9], published: 0x1234usize as *mut u32,
            };
            HOLDER = &mut holder;
            ALLOCATIONS = 0;
            SET_FIRST = false;
            OBJECT = [0xa5a5_a5a5; 23];
            assert!(controller_holder_prepare(&mut holder).is_null());
            assert_eq!(holder.published, ptr::addr_of_mut!(OBJECT).cast::<u32>());
            assert_eq!((*holder.published.add(22)), 0x55aa_aa55);
            assert_eq!(holder.reserved, [7, 8, 9]);
            // A NULL first slot allocates again even with a published object.
            holder.published = 0x1234usize as *mut u32;
            OBJECT = [0xa5a5_a5a5; 23];
            SET_FIRST = true;
            let first = controller_holder_prepare(&mut holder);
            assert_eq!(first, holder.published.add(22));
            assert_eq!(ALLOCATIONS, 2);
            let published = holder.published;
            OBJECT = [0xdead_beef; 23];
            assert_eq!(controller_holder_prepare(&mut holder), first);
            assert_eq!(holder.published, published);
            assert_eq!(ptr::addr_of!(OBJECT).read(), [0xdead_beef; 23]);
            assert_eq!(ALLOCATIONS, 2);
        }
    }
}
