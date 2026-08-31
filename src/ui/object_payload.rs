//! Flag-gated payload accessor for an unidentified UI object.

/// `object_payload_if_available` — original: `FUN_08054454` @ `0x08054454`
/// (20 bytes; 28 binary-verified direct `bl` call sites, all unconditional).
///
/// Raw ARM: `ldrb r1, [r0, #0x1d]; tst r1, #1; ldreq r0, [r0, #0x20];
/// movne r0, #0; bx lr`. The leaf reads the owner byte at `+0x1d`; when bit
/// zero is clear, it returns the 32-bit payload address in the aligned word
/// at `+0x20`, otherwise it returns zero. The owner type and payload meaning
/// are not recovered. It deliberately has no null or alignment guard, as the
/// original immediately dereferences `object` with `ldrb` and conditionally
/// with `ldr`.
///
/// The payload address remains a `u32`, rather than a Rust pointer, because
/// the retailOS object format stores a 32-bit target address even when host
/// tests run on a 64-bit machine.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_payload_if_available(object: *const u8) -> u32 {
    let availability_flags = object.add(0x1d).read();
    if availability_flags & 1 == 0 {
        (object.add(0x20) as *const u32).read()
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Target-layout fixture: the word at `+0x20` stays four bytes wide on
    /// both ARM and 64-bit hosts.
    #[repr(C)]
    struct Owner {
        before_availability_flags: [u8; 0x1d],
        availability_flags: u8,
        before_payload: [u8; 2],
        payload: u32,
    }

    fn call(availability_flags: u8, payload: u32) -> u32 {
        let owner = Owner {
            before_availability_flags: [0xa5; 0x1d],
            availability_flags,
            before_payload: [0x5a; 2],
            payload,
        };
        unsafe { object_payload_if_available(core::ptr::addr_of!(owner).cast()) }
    }

    #[test]
    fn returns_payload_when_availability_bit_is_clear() {
        assert_eq!(call(0, 0x1234_5678), 0x1234_5678);
        assert_eq!(call(0xfe, 0x89ab_cdef), 0x89ab_cdef);
    }

    #[test]
    fn bit_zero_suppresses_payload_regardless_of_other_bits() {
        for availability_flags in 0u8..=0xff {
            let expected = if availability_flags & 1 == 0 { 0xc001_d00d } else { 0 };
            assert_eq!(
                call(availability_flags, 0xc001_d00d),
                expected,
                "availability_flags={availability_flags:#04x}",
            );
        }
    }

    #[test]
    fn payload_zero_is_preserved_when_available() {
        assert_eq!(call(0, 0), 0);
    }
}
