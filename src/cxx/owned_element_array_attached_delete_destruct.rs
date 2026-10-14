//! `owned_element_array_attached_delete_destruct` — `FUN_083d0618` @ 0x083d0618.
//!
//! Raw osos.dec proves **60 bytes** to the next function at 0x083d0654:
//! 56 bytes of code ending in tail B at 0x083d064c, then vtable literal
//! 0x089a4200 at 0x083d0650. Whole-image immediate-branch decoding finds one
//! inbound plain BL (0x0826b4f0), zero predicated BLs and zero tail Bs.
//! The body has one plain BL to owned_element_array_delete_cells (0x083d0568),
//! zero predicated BLs, one BLXNE through attached->vtable[+0x1c], and a tail B
//! to observable_array_destruct (0x08271d2c).
//!
//! Install the derived vtable, release the optional +0x14 attached object,
//! delete enabled indexed cells, then destroy the observable-array base and
//! return this. The caller NULL-guards and deletes the returned allocation.
//! Deliberate deviations: ordinary Rust control flow replaces predication and
//! tail chaining; hosts substitute virtual release and cell cleanup because
//! the existing cell-cleanup host layout widens the vtable pointer, whereas
//! this port preserves target u32 fields. Firmware calls the existing ports.

const VTABLE: u32 = 0x089a_4200;
type Cleanup = unsafe extern "C" fn(*mut u32);
type Release = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cleanup(_: *mut u32) {
    panic!("install owned-element attached destructor host cleanup")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_: *mut u8) {
    panic!("install owned-element attached destructor host release")
}

/// Host replacements for target-width dispatch and the widened cleanup layout.
#[cfg(not(target_os = "none"))]
pub static mut OWNED_ELEMENT_ARRAY_ATTACHED_DELETE_DESTRUCT_OPS: (Cleanup, Release) =
    (missing_cleanup, missing_release);

/// # Safety
/// `this` must be a live target-layout array with six readable/writable words;
/// its attached object, cells and base resources must support their destructors.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_element_array_attached_delete_destruct(this: *mut u32) -> *mut u32 {
    this.write_volatile(VTABLE);
    let attached = this.add(5).read_volatile() as usize as *mut u8;
    #[cfg(target_os = "none")]
    {
        if !attached.is_null() {
            let table = attached.cast::<u32>().read_volatile() as usize as *const u32;
            let release: Release = core::mem::transmute(table.add(7).read_volatile() as usize);
            release(attached);
        }
        super::owned_element_array_delete_cells::owned_element_array_delete_cells(this.cast());
    }
    #[cfg(not(target_os = "none"))]
    {
        let (cleanup, release) = core::ptr::read_volatile(core::ptr::addr_of!(OWNED_ELEMENT_ARRAY_ATTACHED_DELETE_DESTRUCT_OPS));
        if !attached.is_null() {
            release(attached);
        }
        cleanup(this);
    }
    super::observable_array::observable_array_destruct(this.cast()).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut TRACE: [usize; 2] = [0; 2];

    unsafe extern "C" fn release(object: *mut u8) {
        TRACE[0] = object as usize;
    }
    unsafe extern "C" fn cleanup(this: *mut u32) {
        assert_eq!(this.read(), VTABLE);
        assert_eq!(TRACE[0], this.add(5).read() as usize);
        assert_eq!(this.add(1).read(), 7);
        TRACE[1] = this as usize;
        // Base teardown must run after this derived stage, and clear count.
        this.add(1).write(9);
    }

    #[test]
    fn optional_attachment_precedes_cell_cleanup_and_real_base_teardown() {
        let _lock = LOCK.lock();
        unsafe {
            let old = core::ptr::read(core::ptr::addr_of!(OWNED_ELEMENT_ARRAY_ATTACHED_DELETE_DESTRUCT_OPS));
            core::ptr::addr_of_mut!(OWNED_ELEMENT_ARRAY_ATTACHED_DELETE_DESTRUCT_OPS).write((cleanup, release));
            for attached in [0, 0x1234_5000] {
                TRACE = [0; 2];
                let mut guarded = [0xfeed_face, 0, 7, 0, 0, 0xdead_beef, attached, 0xcafe_babe];
                let this = guarded.as_mut_ptr().add(1);
                let result = owned_element_array_attached_delete_destruct(this);
                assert_eq!(result, this);
                assert_eq!(TRACE, [attached as usize, this as usize]);
                assert_eq!(guarded, [0xfeed_face, super::super::observable_array::OBSERVABLE_ARRAY_VTABLE,
                    0, 0, 0, 0xdead_beef, attached, 0xcafe_babe]);
            }
            core::ptr::addr_of_mut!(OWNED_ELEMENT_ARRAY_ATTACHED_DELETE_DESTRUCT_OPS).write(old);
        }
    }
}
