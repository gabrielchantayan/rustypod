//! `observable_array_cells_attached_destruct` — `FUN_083d06fc` @ `0x083d06fc`.
//!
//! True extent: **60 bytes**, thirteen A32 instructions at `0x083d06fc..0x083d0730`
//! plus vtable literal `0x089a42d8` at `0x083d0734`; the next function starts
//! with push at `0x083d0738`. Raw whole-image branch decoding finds one inbound
//! plain BL (`0x0826b508`) and zero predicated BLs. The body contains one plain
//! BL to cell release at `0x083d0654`, zero predicated BLs, one indirect BLXNE
//! through attached-object slot `+0x1c`, and a tail B to `0x08271d2c`.
//!
//! Installs the derived vtable, releases the non-null attachment at `+0x14`,
//! releases enabled cells, then runs the observable-array base destructor,
//! returning this. Deliberate deviations: Rust uses ordinary control flow for
//! predication and the tail call; host builds substitute the virtual and cell
//! release boundaries because their native pointer layouts differ from ARM.

use crate::cxx::observable_array::observable_array_destruct;

const VTABLE_WORD: u32 = 0x089a_42d8;
const ATTACHED_WORD: usize = 5;

type ReleaseAttached = unsafe extern "C" fn(*mut u8);
type ReleaseCells = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
unsafe fn release_attached(object: *mut u8) {
    let vtable = unsafe { object.cast::<*const u32>().read_volatile() };
    let release: ReleaseAttached = unsafe {
        core::mem::transmute(vtable.add(7).read_volatile() as usize)
    };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_attached(_: *mut u8) {
    panic!("install observable-array cells destructor host seams")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cells(_: *mut u32) {
    panic!("install observable-array cells destructor host seams")
}

/// Host replacements for target-layout virtual dispatch and cell release.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_CELLS_ATTACHED_DESTRUCT_OPS: (ReleaseAttached, ReleaseCells) =
    (missing_attached, missing_cells);

/// Destroys an observable array of owned cells and its optional attachment.
///
/// # Safety
/// `this` must be a writable six-word target-layout array object. Its attachment,
/// when nonzero, must expose a callable virtual release at `+0x1c`; enabled cells
/// and base-array resources must satisfy their respective destructor contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_cells_attached_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                release_attached(attached);
            }
            crate::cxx::observable_array_release_cells_083d0654::observable_array_release_cells_083d0654(this.cast());
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release, cells) = core::ptr::read_volatile(core::ptr::addr_of!(
                OBSERVABLE_ARRAY_CELLS_ATTACHED_DESTRUCT_OPS
            ));
            if !attached.is_null() {
                release(attached);
            }
            cells(this);
        }
        observable_array_destruct(this.cast()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CURRENT: *mut u32 = core::ptr::null_mut();
    static mut STAGE: u32 = 0;

    unsafe extern "C" fn release(object: *mut u8) {
        unsafe {
            assert_eq!(object as usize, 0x1234_5000);
            assert_eq!(CURRENT.read(), VTABLE_WORD);
            assert_eq!(STAGE, 0);
            STAGE = 1;
            // The following stage must observe effects of virtual release.
            CURRENT.add(1).write(9);
        }
    }

    unsafe extern "C" fn cells(array: *mut u32) {
        unsafe {
            assert_eq!(array, CURRENT);
            assert_eq!(array.read(), VTABLE_WORD);
            if array.add(ATTACHED_WORD).read() != 0 {
                assert_eq!(STAGE, 1);
                assert_eq!(array.add(1).read(), 9);
            } else {
                assert_eq!(STAGE, 0);
            }
            STAGE = 2;
            array.add(1).write(7);
        }
    }

    #[test]
    fn attachment_null_guard_order_and_base_cleanup() {
        let _lock = LOCK.lock();
        unsafe {
            let old = core::ptr::addr_of!(OBSERVABLE_ARRAY_CELLS_ATTACHED_DESTRUCT_OPS).read();
            core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_CELLS_ATTACHED_DESTRUCT_OPS).write((release, cells));
            for attachment in [0, 0x1234_5000] {
                let mut object = [0xdead_beef, 3, 0, 0, 0xaabb_cc00, attachment];
                CURRENT = object.as_mut_ptr();
                STAGE = 0;
                let result = observable_array_cells_attached_destruct(CURRENT);
                assert_eq!(result, object.as_mut_ptr());
                assert_eq!(STAGE, 2);
                assert_eq!(object, [crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE,
                    0, 0, 0, 0xaabb_cc00, attachment]);
            }
            core::ptr::addr_of_mut!(OBSERVABLE_ARRAY_CELLS_ATTACHED_DESTRUCT_OPS).write(old);
        }
    }
}
