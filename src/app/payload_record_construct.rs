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
//! Deliberate deviations: target calls the unported base in place through
//! its verified address; hosts use a replaceable seam. Fixed-width words
//! preserve target layout on 64-bit hosts. Payload meanings remain opaque.

pub type FlagByteBaseConstructor = unsafe extern "C" fn(*mut u32, u32, u32, u32) -> *mut u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_flag_byte_base(
    _storage: *mut u32, _flag: u32, _payload1: u32, _payload2: u32,
) -> *mut u32 {
    panic!("retail flag-byte base constructor is not installed")
}

/// Host seam for the unported constructor at 0x081433a4.
#[cfg(not(target_os = "none"))]
pub static mut FLAG_BYTE_BASE_CONSTRUCTOR: FlagByteBaseConstructor = missing_flag_byte_base;

/// Constructs a 20-byte record; storage must be aligned and writable.
/// Returns the base constructor's result, with no NULL check as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn payload_record_construct(
    storage: *mut u32, payload0: u32, payload1: u32, payload2: u32,
) -> *mut u32 {
    #[cfg(target_os = "none")]
    let base: FlagByteBaseConstructor = core::mem::transmute(0x0814_33a4usize);
    #[cfg(not(target_os = "none"))]
    let base = core::ptr::addr_of!(FLAG_BYTE_BASE_CONSTRUCTOR).read_volatile();
    let record = base(storage, 0, payload1, payload2);
    record.write_volatile(0x0899_f76c);
    record.add(2).write(payload0);
    record.add(3).write(payload1);
    record.add(4).write(payload2);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent model of the verified base, optionally returning a
    // different object to catch accidentally writing the incoming storage.
    unsafe extern "C" fn reference_base(
        storage: *mut u32, flag: u32, _payload1: u32, _payload2: u32,
    ) -> *mut u32 {
        let object = storage.add(storage.read() as usize);
        object.write(0x0898_5d70);
        object.add(1).cast::<u8>().write(flag as u8);
        object
    }

    #[test]
    fn preserves_base_padding_and_uses_returned_object_for_extreme_payloads() {
        unsafe {
            FLAG_BYTE_BASE_CONSTRUCTOR = reference_base;
            for displacement in [0usize, 5] {
                for payload in [[0, 0, 0], [u32::MAX, 0x8000_0000, 0x0123_4567]] {
                    let mut words = [0xa5a5_a5a5u32; 12];
                    words[1] = displacement as u32;
                    let before = words;
                    let storage = words.as_mut_ptr().add(1);
                    let result = payload_record_construct(storage, payload[0], payload[1], payload[2]);
                    assert_eq!(result, storage.add(displacement));
                    let start = 1 + displacement;
                    let mut expected = before;
                    expected[start] = 0x0899_f76c;
                    expected[start + 1] = 0xa5a5_a500;
                    expected[start + 2..start + 5].copy_from_slice(&payload);
                    assert_eq!(words, expected);
                }
            }
            FLAG_BYTE_BASE_CONSTRUCTOR = missing_flag_byte_base;
        }
    }
}
