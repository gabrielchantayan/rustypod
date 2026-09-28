//! `vector_growth_capacity` — original: `FUN_083b69cc` @ `0x083b69cc` (24
//! bytes; true extent `0x083b69cc..0x083b69e4`).
//!
//! Raw `osos.dec` words are `add r1,r0,r0,lsr #1; add r1,r1,r0,lsr #3; add
//! r0,r0,#0x20; cmp r0,r1; movls r0,r1; bx lr`; `0x083b69e4` begins the next
//! separately linked function. The body has zero outbound plain and predicated
//! `bl` calls. Raw ARM branch-immediate decoding finds two inbound unconditional
//! plain `bl` sites and no predicated inbound `bl` sites. It recommends vector
//! capacity as the unsigned maximum of `capacity + 32` and
//! `capacity + capacity / 2 + capacity / 8`, with every addition wrapping at
//! 32 bits. Deliberate deviation: none; the host implementation uses `u32` to
//! retain the target's unsigned wrapping arithmetic.

/// Returns retailOS's next capacity recommendation for a growing vector.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", unsafe(naked))]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vector_growth_capacity")]
pub unsafe extern "C" fn vector_growth_capacity() {
    core::arch::naked_asm!(
        "add r1,r0,r0,lsr #1",
        "add r1,r1,r0,lsr #3",
        "add r0,r0,#0x20",
        "cmp r0,r1",
        "movls r0,r1",
        "bx lr",
    );
}

#[cfg(not(target_os = "none"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn vector_growth_capacity(capacity: u32) -> u32 {
    let scaled = capacity.wrapping_add(capacity >> 1).wrapping_add(capacity >> 3);
    let minimum = capacity.wrapping_add(0x20);
    if minimum <= scaled { scaled } else { minimum }
}

#[cfg(test)]
mod tests {
    use super::vector_growth_capacity;

    fn reference(capacity: u32) -> u32 {
        let scaled = capacity.wrapping_add(capacity >> 1).wrapping_add(capacity >> 3);
        let minimum = capacity.wrapping_add(0x20);
        if minimum <= scaled { scaled } else { minimum }
    }

    #[test]
    fn uses_the_minimum_for_small_capacities_and_the_scaled_value_afterward() {
        for capacity in [0, 1, 19, 20, 21, 31, 32, 0x100] {
            assert_eq!(vector_growth_capacity(capacity), reference(capacity));
        }
        assert_eq!(vector_growth_capacity(19), 51);
        assert_eq!(vector_growth_capacity(20), 52);
        assert_eq!(vector_growth_capacity(21), 53);
    }

    #[test]
    fn preserves_arm_unsigned_comparison_and_wrapping_additions() {
        for capacity in [0x7fff_ffff, 0xffff_ffdf, 0xffff_ffe0, 0xffff_ffff] {
            assert_eq!(vector_growth_capacity(capacity), reference(capacity));
        }
        assert_eq!(vector_growth_capacity(0xffff_ffff), 0x9fff_fffd);
    }
}
