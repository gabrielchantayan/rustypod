//! Empty cleanup destructor — `FUN_080284d4` @ 0x080284d4 (4 bytes).
//!
//! Raw extent [0x080284d4, 0x080284d8) is one word, 0xe12fff1e (`bx lr`);
//! the next independent return body starts at 0x080284d8. This is not a veneer.
//! Full-image aligned ARM decoding verifies two inbound plain BLs, at
//! 0x082ea25c and 0x082ea43c, zero predicated BLs, and zero outbound calls.
//! No aligned DATA word references this entry. Both callers load the saved
//! object from sp+0x50 during cleanup, then overwrite r0 after the call.
//! The concrete object type is unrecovered; Ghidra's void prototype omits
//! the machine-level r0 passthrough.
//!
//! Algorithm: access no memory and return the incoming object address.
//! Deliberate behavioral deviations: none. LLVM adds balanced frame-pointer
//! stack setup/teardown instead of the stock single return instruction.
//! A dedicated section prevents folding into another identical destructor.

use core::ffi::c_void;

/// Returns even NULL, dangling, and unaligned addresses without dereferencing.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.empty_destructor_080284d4")]
#[inline(never)]
pub unsafe extern "C" fn empty_destructor_080284d4(object: *mut c_void) -> *mut c_void {
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_unaligned_and_dangling_addresses() {
        for address in [0usize, 1, 3, 0x0800_0001, 0xffff_ffff, usize::MAX] {
            let object = address as *mut c_void;
            assert_eq!(unsafe { empty_destructor_080284d4(object) }, object);
        }
    }

    #[test]
    fn preserves_live_object_and_neighboring_bytes() {
        let mut storage = [0xa5u8; 33];
        storage[1] = 0x37;
        let before = storage;
        let object = unsafe { storage.as_mut_ptr().add(1) }.cast();
        assert_eq!(unsafe { empty_destructor_080284d4(object) }, object);
        assert_eq!(storage, before);
    }
}
