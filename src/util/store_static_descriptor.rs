//! Stores the retailOS static descriptor word used in object tail slots.

/// store_static_descriptor — original: `FUN_080f81ac` @ 0x080f81ac (12
/// instruction bytes; 10 verified unconditional `bl` call sites, no predicated
/// `bl` forms or direct `b` tail branches).
///
/// Raw ARM loads the literal `0x089800ac` from 0x080f81b8, stores it in the
/// aligned destination word, and returns that destination unchanged in `r0`.
/// The ten callers use this to initialize an object-tail slot after allocating
/// an object. The target address is opaque static data, not a function entry.
/// Ghidra declares this function `void`; preserving `r0` is required because
/// callers immediately recover the enclosing object from the returned slot.
/// There is no NULL guard. Deviations: none.
///
/// # Safety
/// `dst` must be valid for one aligned `u32` write.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.store_static_descriptor")]
#[inline(never)]
pub unsafe extern "C" fn store_static_descriptor(dst: *mut u32) -> *mut u32 {
    dst.write(0x0898_00ac);
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::store_static_descriptor;

    #[test]
    fn stores_descriptor_and_returns_destination() {
        let mut descriptor: u32 = 0xdead_beef;
        let dst = &mut descriptor as *mut u32;

        let returned = unsafe { store_static_descriptor(dst) };

        assert_eq!(returned, dst);
        assert_eq!(descriptor, 0x0898_00ac);
    }

    #[test]
    fn stores_only_the_selected_aligned_word() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333];
        let dst = unsafe { words.as_mut_ptr().add(1) };

        unsafe {
            store_static_descriptor(dst);
        }

        assert_eq!(words, [0x1111_1111, 0x0898_00ac, 0x3333_3333]);
    }
}
