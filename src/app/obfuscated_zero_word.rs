//! Constant-zero word — `FUN_08027658` @ 0x08027658.
//!
//! True size: 8 bytes, [0x08027658,0x08027660). Raw words are e3a00000
//! e12fff1e (MOV r0,#0; BX LR); the next entry has independent BL callers.
//! Whole-image aligned A32 decoding verifies two plain inbound BLs at
//! 0x08343b84 and 0x08348278, zero predicated BLs, and zero outgoing calls.
//!
//! Return zero without reading memory or interpreting the six opaque ABI
//! words supplied by both obfuscated state-machine callers. Their concrete
//! types are unknown; no callee seams or inferred allocation semantics.
//! No behavioral deviations. A dedicated text section and inline-never keep
//! this independently patchable target distinct from other zero helpers.

/// Discard the caller's opaque words and produce a zero result word.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_zero_word")]
#[inline(never)]
pub extern "C" fn obfuscated_zero_word(
    _first: u32, _second: u32, _third: u32,
    _fourth: u32, _fifth: u32, _sixth: u32,
) -> u32 {
    0
}

/// Obfuscated four-word zero result — `FUN_08027628` @ 0x08027628.
///
/// True size: 8 bytes, [0x08027628,0x08027630). Raw e3a00000 e12fff1e
/// decodes as MOV r0,#0; BX LR. The next real function is the independently
/// called second-word identity at 0x08027630. Whole-image aligned A32
/// decoding verifies two plain inbound BLs (0x082f91f4, 0x08332acc),
/// zero predicated inbound BLs, and zero outgoing calls.
/// Both obfuscated state-machine callers supply four opaque register words
/// and store the returned zero. Ignore every input, access no memory, and
/// return a full-width zero word. No behavioral deviations or callee seams.
/// A dedicated section retains a distinct patch target from other zero bodies.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_four_word_zero")]
#[inline(never)]
pub extern "C" fn obfuscated_four_word_zero(
    _first: u32, _second: u32, _third: u32, _fourth: u32,
) -> u32 {
    0
}

/// Obfuscated six-word zero result — `FUN_08027618` @ 0x08027618.
///
/// True size: 8 bytes, [0x08027618,0x08027620). Raw e3a00000 e12fff1e
/// is MOV r0,#0; BX LR. The next real entry is the independently called
/// second-word identity at 0x08027620. Whole-image aligned A32 decoding
/// verifies two plain inbound BLs (0x08343770, 0x08348664), zero predicated
/// inbound BLs, and zero outgoing calls.
/// Both obfuscated state-machine callers supply six opaque register/stack
/// words and store the returned zero. Ignore all inputs and access no memory.
/// Concrete argument types remain unknown; no callee seams or behavioral
/// deviations. A dedicated section retains an independently patchable symbol.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_six_word_zero")]
#[inline(never)]
pub extern "C" fn obfuscated_six_word_zero(
    _first: u32, _second: u32, _third: u32,
    _fourth: u32, _fifth: u32, _sixth: u32,
) -> u32 {
    0
}

/// Obfuscated state-machine zero result — `FUN_08027608` @ 0x08027608.
///
/// True size: 8 bytes, [0x08027608,0x08027610). Raw e3a00000 e12fff1e
/// is MOV r0,#0; BX LR. The next real entry is the independently called
/// second-word identity at 0x08027610. Whole-image aligned A32 decoding
/// verifies two plain inbound BLs (0x082fa8f0, 0x0831314c), zero predicated
/// inbound BLs, zero outgoing calls, and no aligned address-word references.
/// Both obfuscated state machines supply six opaque register/stack words
/// and store the returned zero. Ignore every input and access no memory.
/// Concrete types and higher-level meaning remain unknown; no callee seams
/// or behavioral deviations. A dedicated section retains a distinct target.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_state_machine_zero")]
#[inline(never)]
pub extern "C" fn obfuscated_state_machine_zero(
    _first: u32, _second: u32, _third: u32,
    _fourth: u32, _fifth: u32, _sixth: u32,
) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_zero_discards_all_six_words_without_dereferencing() {
        let edges = [0, 1, 0xff, 0x100, 0x0800_0001, 0x8000_0000,
                     u32::MAX, 0xaaaa_aaaa, 0x5555_5555];
        for position in 0..6 {
            for word in edges {
                let mut words = [u32::MAX; 6];
                words[position] = word;
                assert_eq!(obfuscated_state_machine_zero(words[0], words[1], words[2],
                                                        words[3], words[4], words[5]), 0);
            }
        }
        assert_eq!(obfuscated_state_machine_zero(0, 0, 0, 0, 0, 0), 0);
    }

    #[test]
    fn six_word_zero_ignores_full_width_register_and_stack_inputs() {
        let edges = [0, 1, 0xff, 0x100, 0x0800_0001, 0x8000_0000,
                     u32::MAX, 0xaaaa_aaaa, 0x5555_5555];
        for position in 0..6 {
            for word in edges {
                let mut words = [u32::MAX; 6];
                words[position] = word;
                assert_eq!(obfuscated_six_word_zero(words[0], words[1], words[2],
                                                   words[3], words[4], words[5]), 0);
            }
        }
        assert_eq!(obfuscated_six_word_zero(0, 0, 0, 0, 0, 0), 0);
    }

    #[test]
    fn four_word_zero_ignores_full_width_and_pointer_like_inputs() {
        let edges = [0, 1, 0xff, 0x100, 0x0800_0001, 0x8000_0000,
                     u32::MAX, 0xaaaa_aaaa, 0x5555_5555];
        for position in 0..4 {
            for word in edges {
                let mut words = [u32::MAX; 4];
                words[position] = word;
                assert_eq!(obfuscated_four_word_zero(words[0], words[1],
                                                    words[2], words[3]), 0);
            }
        }
        assert_eq!(obfuscated_four_word_zero(0, 0, 0, 0), 0);
    }

    #[test]
    fn ignores_every_register_and_stack_argument() {
        let edges = [0, 1, 0xff, 0x100, 0x0800_0001, 0x8000_0000,
                     u32::MAX, 0xaaaa_aaaa, 0x5555_5555];
        for position in 0..6 {
            for word in edges {
                let mut words = [u32::MAX; 6];
                words[position] = word;
                assert_eq!(obfuscated_zero_word(words[0], words[1], words[2],
                                               words[3], words[4], words[5]), 0);
            }
        }
        assert_eq!(obfuscated_zero_word(0, 0, 0, 0, 0, 0), 0);
    }
}
