//! Vtable-bearing object-owner constructor @ 0x081619fc (FUN_081619fc).
//! True extent: 76 bytes [0x081619fc,0x08161a48): 68 code bytes and
//! two literals (vtable 0x08987da0, global byte address 0x089caf72).
//! Whole-image A32 decoding verifies two incoming plain BLs at 0x081492f4
//! and 0x0827de28, zero predicated incoming BLs, and no outgoing calls.
//!
//! Install the owner vtable; clear words +4, +8, +16, +20, +44 and only
//! byte +24. Set word +40 to 0x80000000, then read the global byte and
//! replace that word with 0x01000000 if nonzero. Return the original
//! pointer (raw r0 is unchanged and both callers use the returned subobject).
//! Other fields and padding are untouched; no wider class identity inferred.
//!
//! Deliberate deviations: host execution substitutes an atomic byte for the
//! fixed-address global. Storage uses target-width words on every platform;
//! no host pointer widening or target behavioral deviation.

#[cfg(not(target_os = "none"))]
pub static OWNER_MODE_BYTE: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);

#[inline(always)]
fn owner_mode_byte() -> u8 {
    #[cfg(target_os = "none")]
    unsafe { (0x089c_af72 as *const u8).read_volatile() }
    #[cfg(not(target_os = "none"))]
    { OWNER_MODE_BYTE.load(core::sync::atomic::Ordering::Relaxed) }
}

/// # Safety
/// `owner` must be four-byte aligned and writable for 48 bytes. On target,
/// the firmware global byte at 0x089caf72 must be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_object_owner_construct(owner: *mut u32) -> *mut u32 {
    unsafe {
        owner.write_volatile(0x0898_7da0);
        owner.add(1).write_volatile(0);
        owner.add(2).write_volatile(0);
        owner.add(4).write_volatile(0);
        owner.add(5).write_volatile(0);
        owner.cast::<u8>().add(24).write_volatile(0);
        owner.add(11).write_volatile(0);
        owner.add(10).write_volatile(0x8000_0000);
        if owner_mode_byte() != 0 {
            owner.add(10).write_volatile(0x0100_0000);
        }
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn mode_transitions_preserve_every_untouched_byte_and_return_identity() {
        for mode in [0, 1, 2, 0x80, 0xff, 0] {
            OWNER_MODE_BYTE.store(mode, Ordering::Relaxed);
            let mut storage = [0xa5a5_a5a5u32; 14];
            let mut expected = storage;
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(expected.as_mut_ptr().cast::<u8>(), 56)
            };
            bytes[4..8].copy_from_slice(&0x0898_7da0u32.to_ne_bytes());
            for offset in [4, 8, 16, 20, 44] {
                bytes[4 + offset..8 + offset].fill(0);
            }
            bytes[4 + 24] = 0;
            let state: u32 = if mode == 0 { 0x8000_0000 } else { 0x0100_0000 };
            bytes[44..48].copy_from_slice(&state.to_ne_bytes());
            let owner = unsafe { storage.as_mut_ptr().add(1) };
            assert_eq!(unsafe { vtable_object_owner_construct(owner) }, owner);
            assert_eq!(storage, expected, "mode {mode:#x}");
            // Reinitialization must reset modified fields, not retain prior state.
            unsafe { owner.add(10).write(0xffff_ffff); owner.add(1).write(17); }
            assert_eq!(unsafe { vtable_object_owner_construct(owner) }, owner);
            assert_eq!(storage, expected);
        }
    }
}
