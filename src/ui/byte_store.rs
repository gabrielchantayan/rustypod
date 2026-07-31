//! `ui_store_byte` — original: `FUN_0811f7e0` @ `0x0811f7e0` (8 bytes).
//!
//! Stores the low byte of its second ARM ABI argument (`r1`) to the address in
//! its first argument (`r0`), then returns immediately. This is a standalone
//! byte store: it does not impose alignment, validate the pointer, access any
//! adjacent byte, or define a return side effect. Callers pass stack-local
//! storage onward, but no object ownership is established by this leaf.
//!
//! Deviations: none. The caller must provide a valid writable byte; `strb`
//! permits an unaligned address, which this port preserves.

/// Stores `value` in exactly the byte addressed by `destination`.
///
/// Original: `FUN_0811f7e0` @ `0x0811f7e0` (8 bytes): `strb r1, [r0]; bx lr`.
/// The pointer must designate one valid writable byte. No alignment is
/// required, and no other memory is read or written.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_store_byte(destination: *mut u8, value: u8) {
    unsafe { destination.write(value) };
}

/// `ui_copy_byte` — original: `FUN_0811f7e8` @ `0x0811f7e8` (12 bytes).
///
/// Loads exactly one byte from `source`, then stores it at `destination`, as
/// `ldrb r1, [r1]; strb r1, [r0]; bx lr`. Read-before-write order is
/// preserved when the pointers alias. Deviations: none.
///
/// Both pointers are the firmware's unsafe ABI: they must designate valid
/// readable and writable bytes respectively, need no alignment, and are not
/// NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_copy_byte(destination: *mut u8, source: *const u8) {
    let value = unsafe { source.read() };
    unsafe { destination.write(value) };
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_only_the_first_byte_of_unaligned_storage() {
        let mut storage = [0xa5u8; 5];
        let destination = unsafe { storage.as_mut_ptr().add(1) };

        unsafe { ui_store_byte(destination, 0x3c) };

        assert_eq!(storage, [0xa5, 0x3c, 0xa5, 0xa5, 0xa5]);
    }

    #[test]
    fn stores_every_possible_byte_without_a_word_write() {
        for value in 0u8..=u8::MAX {
            let mut storage = [0x5au8; 3];
            let destination = unsafe { storage.as_mut_ptr().add(1) };

            unsafe { ui_store_byte(destination, value) };

            assert_eq!(storage[0], 0x5a, "byte before value={value:#04x}");
            assert_eq!(storage[1], value, "stored value={value:#04x}");
            assert_eq!(storage[2], 0x5a, "byte after value={value:#04x}");
        }
    }

    #[test]
    fn copy_writes_only_the_destination_byte() {
        let mut storage = [0xa5u8, 0x3c, 0xa5, 0x00, 0xa5, 0xa5];
        let source = unsafe { storage.as_ptr().add(1) };
        let destination = unsafe { storage.as_mut_ptr().add(3) };

        unsafe { ui_copy_byte(destination, source) };

        assert_eq!(storage, [0xa5, 0x3c, 0xa5, 0x3c, 0xa5, 0xa5]);
    }

    #[test]
    fn copy_uses_the_provided_source_and_destination_offsets() {
        let mut storage = [0x10u8, 0x21, 0x32, 0x43, 0x54, 0x65];
        let source = unsafe { storage.as_ptr().add(4) };
        let destination = unsafe { storage.as_mut_ptr().add(1) };

        unsafe { ui_copy_byte(destination, source) };

        assert_eq!(storage, [0x10, 0x54, 0x32, 0x43, 0x54, 0x65]);
    }

    #[test]
    fn copy_allows_source_and_destination_to_alias() {
        let mut storage = [0x18u8, 0x27, 0x36];
        let byte = unsafe { storage.as_mut_ptr().add(1) };

        unsafe { ui_copy_byte(byte, byte) };

        assert_eq!(storage, [0x18, 0x27, 0x36]);
    }
}
