//! Replace an owned handle, discarding handles with an empty first word.
//!
//! Original `FUN_081402fc` @ **0x081402fc**, true size **48 bytes**:
//! twelve A32 words ending at pop {r4,pc}, before the independently entered
//! pair-copy function at 0x0814032c. Whole-image decoding finds two inbound
//! plain BLs (0x081dc644, 0x081dcbb4), no predicated inbound BLs. The body
//! has two plain BLs (0x083e73a0, 0x0829bad8), no predicated BLs, and a
//! conditional tail branch to 0x083e73a0.
//!
//! Replace the owned pointer at +0x30 using owned_guarded_slot_04_replace;
//! read the installed handle's first word and, if zero, replace it with NULL.
//! The replacement argument in r1 is missing from Ghidra's signature.
//! Deliberate deviations: inline the verified leaf predicate at 0x0829bad8
//! (ldr r0,[r0]; cmp r0,#0; movne r0,#1; bx lr), rather than create another
//! port or seam. repr(C) retains the 48-byte prefix and uses native-width
//! pointers for host fixtures, matching the existing ownership helper.

use crate::cxx::owned_guarded_slot_04_replace::owned_guarded_slot_04_replace;

#[repr(C)]
pub struct OwnedHandleOwner {
    pub prefix: [u32; 12],
    pub handle: *mut u8,
}

/// Install a handle and discard it if its first word is empty.
///
/// # Safety
/// `owner` must be writable. `replacement` must be non-NULL and contain a
/// readable native pointer word (a four-byte word on target). Both the old
/// handle and replacement must satisfy owned_guarded_slot_04_replace's
/// destruction and allocation contracts when disposal is required.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owned_handle_replace_if_nonempty(
    owner: *mut OwnedHandleOwner,
    replacement: *mut u8,
) {
    let slot = unsafe { core::ptr::addr_of_mut!((*owner).handle) };
    unsafe { owned_guarded_slot_04_replace(slot, replacement) };
    let installed = unsafe { slot.read() };
    if unsafe { installed.cast::<usize>().read() } == 0 {
        unsafe { owned_guarded_slot_04_replace(slot, core::ptr::null_mut()) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use std::vec::Vec;

    static mut FREED: Vec<usize> = Vec::new();
    static mut DESTROYED: Vec<usize> = Vec::new();

    unsafe extern "C" fn destroy(object: *mut u8) {
        unsafe { (*core::ptr::addr_of_mut!(DESTROYED)).push(object as usize) };
    }

    unsafe extern "C" fn free(_heap: *mut HeapDescriptorDescriptor, object: *mut u8, tag: usize) {
        assert_eq!(tag, 2);
        unsafe { (*core::ptr::addr_of_mut!(FREED)).push(object as usize) };
    }

    struct HeapRestore(HeapVeneerOps, *mut HeapDescriptorDescriptor);
    impl Drop for HeapRestore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(HEAP_OPS).write(self.0);
                core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP).write(self.1);
            }
        }
    }

    #[test]
    fn replacement_retention_and_disposal_follow_first_word_not_pointer_identity() {
        unsafe {
            let saved = core::ptr::addr_of!(HEAP_OPS).read();
            let _restore = HeapRestore(saved, core::ptr::addr_of!(crate::heap::types::DEFAULT_HEAP).read());
            let mut ops = saved;
            ops.free = free;
            core::ptr::addr_of_mut!(HEAP_OPS).write(ops);
            core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP).write(1usize as *mut _);
            let vtable = [0usize, destroy as usize];
            let mut payload = [vtable.as_ptr() as usize];
            let mut old_handle = [payload.as_mut_ptr() as usize];
            let mut live_handle = [payload.as_mut_ptr() as usize];
            let mut empty_handle = [0usize];
            for (old, replacement, retained, freed, destroyed) in [
                (core::ptr::null_mut(), live_handle.as_mut_ptr(), true, 0, 0),
                (live_handle.as_mut_ptr(), live_handle.as_mut_ptr(), true, 0, 0),
                (empty_handle.as_mut_ptr(), empty_handle.as_mut_ptr(), false, 1, 0),
                (old_handle.as_mut_ptr(), live_handle.as_mut_ptr(), true, 1, 1),
                (old_handle.as_mut_ptr(), empty_handle.as_mut_ptr(), false, 2, 1),
            ] {
                (*core::ptr::addr_of_mut!(FREED)).clear();
                (*core::ptr::addr_of_mut!(DESTROYED)).clear();
                let mut owner = OwnedHandleOwner { prefix: [0x12345678; 12], handle: old.cast() };
                owned_handle_replace_if_nonempty(&mut owner, replacement.cast());
                assert_eq!(owner.handle, if retained { replacement.cast() } else { core::ptr::null_mut() });
                assert_eq!(owner.prefix, [0x12345678; 12]);
                let expected_freed: Vec<usize> = if freed == 2 {
                    std::vec![old as usize, replacement as usize]
                } else if freed == 1 { std::vec![old as usize] } else { Vec::new() };
                assert_eq!(*core::ptr::addr_of!(FREED), expected_freed);
                let expected_destroyed = if destroyed == 1 { std::vec![payload.as_ptr() as usize] } else { Vec::new() };
                assert_eq!(*core::ptr::addr_of!(DESTROYED), expected_destroyed);
            }
        }
    }
}
