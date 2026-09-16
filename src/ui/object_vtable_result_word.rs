//! `ui_object_vtable_result_word` — original: `FUN_083d5f5c` @ `0x083d5f5c`
//! (24 bytes).
//!
//! Raw osos.dec establishes the true extent `0x083d5f5c..0x083d5f74`: push
//! `{r4,lr}`; load the object's vtable and its `+0x40` slot; `blx` that slot;
//! load and return the first word through the result pointer; pop `{r4,pc}`.
//! There is one indirect BLX and no direct or predicated BL instructions in the
//! body. The four direct inbound BL calls are unconditional. This invokes the
//! opaque receiver method in vtable slot `+0x40`, then returns the first word
//! of the pointer it produces. The virtual target is not identified or ported;
//! this is deliberately a dispatch seam. Deviations: host builds use native
//! pointers while retaining the target's word indices.

/// ARM word index of the result-producing virtual method in the object's vtable.
const VTABLE_RESULT_WORD_SLOT: usize = 0x40 / 4;

/// ABI of the opaque virtual method called with the original object in `r0`.
type ResultWordMethod = unsafe extern "C" fn(*mut u8) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_result_word(object: *mut u8) -> *mut u32 {
    let vtable = object.cast::<u32>().read_volatile() as usize as *const u32;
    let method: ResultWordMethod =
        core::mem::transmute(vtable.add(VTABLE_RESULT_WORD_SLOT).read_volatile() as usize);
    method(object)
}

/// Host representation of the observed vtable slot.
#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostResultWordVtable {
    unresolved_00_to_3c: [usize; VTABLE_RESULT_WORD_SLOT],
    result_word: ResultWordMethod,
}

/// Host representation of an object whose first word is its vtable pointer.
#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostResultWordObject {
    vtable: *const HostResultWordVtable,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_result_word(object: *mut u8) -> *mut u32 {
    let host_object = &*object.cast::<HostResultWordObject>();
    ((*host_object.vtable).result_word)(object)
}

/// Invokes vtable slot `+0x40` and returns the first word of its result.
///
/// Original: `FUN_083d5f5c` @ `0x083d5f5c` (24 bytes). The unchecked object,
/// vtable, slot, and result pointers use the target's ARM word layout.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_object_vtable_result_word(object: *mut u8) -> u32 {
    unsafe { dispatch_result_word(object).read_volatile() }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVED_OBJECT: *mut u8 = ptr::null_mut();
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn result_word_method(object: *mut u8) -> *mut u32 {
        unsafe {
            RECEIVED_OBJECT = object;
            &raw mut RESULT
        }
    }

    fn fixture() -> (HostResultWordObject, HostResultWordVtable) {
        (
            HostResultWordObject { vtable: ptr::null() },
            HostResultWordVtable {
                unresolved_00_to_3c: [0; VTABLE_RESULT_WORD_SLOT],
                result_word: result_word_method,
            },
        )
    }

    #[test]
    fn calls_slot_40_with_the_object_and_reads_the_result_word() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let (mut object, vtable) = fixture();
        object.vtable = &vtable;
        unsafe {
            RECEIVED_OBJECT = ptr::null_mut();
            RESULT = 0xdec0_adde;
            let object_ptr = ptr::addr_of_mut!(object).cast::<u8>();

            assert_eq!(ui_object_vtable_result_word(object_ptr), 0xdec0_adde);
            assert_eq!(RECEIVED_OBJECT, object_ptr);
        }
    }

    #[test]
    fn reads_the_word_returned_by_the_virtual_method() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let (mut object, vtable) = fixture();
        object.vtable = &vtable;
        unsafe {
            let object_ptr = ptr::addr_of_mut!(object).cast::<u8>();
            RESULT = 0;
            assert_eq!(ui_object_vtable_result_word(object_ptr), 0);
            RESULT = u32::MAX;
            assert_eq!(ui_object_vtable_result_word(object_ptr), u32::MAX);
        }
    }
}
