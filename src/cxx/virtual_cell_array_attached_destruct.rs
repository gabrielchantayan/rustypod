//! Attached virtual-cell array destructor — `FUN_083cfabc` @ **0x083cfabc**.
//! True extent: 60 bytes (56 code bytes through tail B at 0x083cfaf0,
//! vtable literal 0x089a37e0 at 0x083cfaf4); next function starts at 0x083cfaf8.
//! Raw aligned A32 decoding verifies one inbound plain BL (0x0826b3d0),
//! zero predicated inbound BLs; body: one plain BL to 0x083cf9fc, zero
//! predicated BLs, one BLXNE through attachment slot +0x1c, and tail B
//! to observable_array_destruct @ 0x08271d2c.
//!
//! Installs the derived vtable, releases a non-NULL attachment at +0x14,
//! releases enabled virtual cells, then destroys the base array and returns
//! the original receiver (the caller subsequently deletes it).
//! Deliberate deviations: Rust expresses predication and tail chaining as
//! ordinary control flow; host seams replace only target-width virtual dispatch
//! and virtual-cell cleanup, whose existing host layout differs from the target.

use super::observable_array::{observable_array_destruct, ObservableArray};
#[cfg(target_os = "none")]
use super::observable_array_release_virtual_cells::observable_array_release_virtual_cells;

const DERIVED_VTABLE: u32 = 0x089a_37e0;
type Release = unsafe extern "C" fn(u32);
type Cleanup = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_: u32) { panic!("install virtual-cell destructor host release"); }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cleanup(_: *mut u8) { panic!("install virtual-cell destructor host cleanup"); }

/// Host boundaries for attachment release and the target-layout cell cleanup.
#[cfg(not(target_os = "none"))]
pub static mut VIRTUAL_CELL_ARRAY_ATTACHED_DESTRUCT_OPS: (Release, Cleanup) =
    (missing_release, missing_cleanup);

/// # Safety
/// `array` is a writable, word-aligned derived array of at least 24 bytes.
/// Its attachment, when nonzero, supports virtual release at +0x1c; enabled
/// cells support the existing virtual-cell cleanup contract, and its base
/// storage and observers satisfy `observable_array_destruct`'s contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn virtual_cell_array_attached_destruct(array: *mut u8) -> *mut u8 {
    unsafe {
        array.cast::<u32>().write_volatile(DERIVED_VTABLE);
        let attachment = array.cast::<u32>().add(5).read_volatile();
        #[cfg(target_os = "none")]
        {
            if attachment != 0 {
                let object = attachment as usize as *mut u8;
                let vtable = object.cast::<u32>().read_volatile() as usize as *const u32;
                let release: unsafe extern "C" fn(*mut u8) =
                    core::mem::transmute(vtable.add(7).read_volatile() as usize);
                release(object);
            }
            observable_array_release_virtual_cells(array.cast());
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release, cleanup) = core::ptr::read_volatile(core::ptr::addr_of!(
                VIRTUAL_CELL_ARRAY_ATTACHED_DESTRUCT_OPS
            ));
            if attachment != 0 { release(attachment); }
            cleanup(array);
        }
        observable_array_destruct(array.cast::<ObservableArray>()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut ACTIVE: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn release(attachment: u32) {
        unsafe {
            assert_eq!(attachment, 0x1234);
            assert_eq!(ACTIVE.read(), DERIVED_VTABLE);
            // A callback mutation must be visible to the subsequent cleanup.
            ACTIVE.add(4).write(0xabcdef01);
        }
    }
    unsafe extern "C" fn cleanup(array: *mut u8) {
        unsafe {
            let words = array.cast::<u32>();
            assert_eq!(words, ACTIVE);
            assert_eq!(words.read(), DERIVED_VTABLE);
            assert_eq!(words.add(4).read(), if words.add(5).read() == 0 { 0x55 } else { 0xabcdef01 });
            // Base teardown must happen after cleanup, not before it.
            assert_eq!(words.add(1).read(), 3);
            words.add(4).write(0x77);
        }
    }
    #[test]
    fn null_and_nonnull_attachment_preserve_order_and_base_teardown() {
        let _lock = LOCK.lock();
        unsafe {
            let old = VIRTUAL_CELL_ARRAY_ATTACHED_DESTRUCT_OPS;
            VIRTUAL_CELL_ARRAY_ATTACHED_DESTRUCT_OPS = (release, cleanup);
            for attachment in [0, 0x1234] {
                let mut words = [0, 3, 0, 0, 0x55, attachment, 0xfeed];
                ACTIVE = words.as_mut_ptr();
                let result = virtual_cell_array_attached_destruct(ACTIVE.cast());
                assert_eq!(result, words.as_mut_ptr().cast());
                assert_eq!(words, [super::super::observable_array::OBSERVABLE_ARRAY_VTABLE,
                    0, 0, 0, 0x77, attachment, 0xfeed]);
            }
            ACTIVE = core::ptr::null_mut();
            VIRTUAL_CELL_ARRAY_ATTACHED_DESTRUCT_OPS = old;
        }
    }
}
