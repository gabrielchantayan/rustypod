//! Three-word polymorphic payload record constructor.
//!
//! Original `FUN_08225148` @ load address `0x08225148`: true extent 48
//! bytes (44 instruction bytes and vtable literal @ `0x08225174`), ending
//! at the next real function @ `0x08225178`. Raw-word scan verifies two
//! inbound plain BL sites (`0x081d2110`, `0x081d2138`), zero predicated BL
//! sites; the body has one plain BL @ `0x0822515c`, zero predicated BL.
//!
//! Calls the flag-byte base constructor @ `0x081433a4` with flag zero,
//! installs vtable `0x0899f76c`, and writes three opaque payload words at
//! +8/+12/+16 using the base's returned pointer. The caller @ `0x081d20b0`
//! allocates 20 bytes and dispatches the result through a virtual method.
//! Raw base code chains the ported root @ `0x08275bb8`, installs its own
//! vtable `0x08985d70`, and writes only byte +4, preserving bytes +5..+7.
//!
//! Deliberate deviations: none. The base constructor is now ported and
//! called directly. Fixed-width words preserve target layout on hosts.
//! Payload meanings remain opaque.

use super::flag_byte_base_construct::flag_byte_base_construct;

/// Constructs a 20-byte record; storage must be aligned and writable.
/// Returns the base constructor's result, with no NULL check as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn payload_record_construct(
    storage: *mut u32, payload0: u32, payload1: u32, payload2: u32,
) -> *mut u32 {
    let record = flag_byte_base_construct(storage, 0);
    record.write_volatile(0x0899_f76c);
    record.add(2).write(payload0);
    record.add(3).write(payload1);
    record.add(4).write(payload2);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_base_padding_and_derived_payloads() {
        for payload in [[0, 0, 0], [u32::MAX, 0x8000_0000, 0x0123_4567]] {
            let mut words = [0xa5a5_a5a5u32; 7];
            let storage = unsafe { words.as_mut_ptr().add(1) };
            let result = unsafe {
                payload_record_construct(storage, payload[0], payload[1], payload[2])
            };
            assert_eq!(result, storage);
            assert_eq!(words, [
                0xa5a5_a5a5, 0x0899_f76c, 0xa5a5_a500,
                payload[0], payload[1], payload[2], 0xa5a5_a5a5,
            ]);
        }
    }
}
