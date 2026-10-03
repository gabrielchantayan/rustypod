//! Constructor for an opaque descriptor-bearing state prefix.
//!
//! `FUN_08277980` @ **0x08277980**, true extent 28 bytes: six ARM
//! instructions (24 bytes), then descriptor literal at 0x08277998; the next
//! real function starts at 0x0827799c (`ldr r0,[r0,#20]; bx lr`). Raw aligned
//! BL-immediate decoding finds two incoming plain BLs (0x08148fe4 and
//! 0x08295074), no incoming predicated BLs, and no outgoing BLs of either kind.
//!
//! Install descriptor 0x089a605c, clear state byte +4, copy the low byte of
//! the supplied mode to +5, and return storage unchanged. The two derived
//! constructors replace the descriptor and pass modes 1 and 0 respectively.
//! Deliberate deviations: none in observable behavior. The concrete class
//! and meanings of the state/mode bytes remain unknown; the descriptor is
//! retained as a firmware identity, not replaced with a host vtable.

pub const OPAQUE_STATE_DESCRIPTOR: u32 = 0x089a_605c;

/// Initializes only bytes +0..+5 of the opaque object prefix.
///
/// # Safety
/// `storage` must be four-byte aligned and writable for at least six bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_state_construct(storage: *mut u8, mode: u32) -> *mut u8 {
    storage.cast::<u32>().write(OPAQUE_STATE_DESCRIPTOR);
    storage.add(4).write(0);
    storage.add(5).write(mode as u8);
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_mode_and_preserves_adjacent_storage() {
        for mode in (0..=255).chain([0x100, 0x1234_5680, u32::MAX]) {
            let mut words = [0xa5a5_a5a5u32; 4];
            let bytes = words.as_mut_ptr().cast::<u8>();
            let storage = unsafe { bytes.add(4) };
            let returned = unsafe { opaque_state_construct(storage, mode) };
            assert_eq!(returned, storage);
            let actual = unsafe { core::slice::from_raw_parts(bytes, 16) };
            let mut expected = [0xa5; 16];
            expected[4..8].copy_from_slice(&0x089a_605cu32.to_le_bytes());
            expected[8] = 0;
            expected[9] = mode as u8;
            assert_eq!(actual, expected);
        }
    }
}
