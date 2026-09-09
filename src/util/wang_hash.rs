//! Thomas Wang 64→32 integer hash — `FUN_083d63cc` @ 0x083d63cc (148 bytes;
//! 12 `bl` call sites, all unconditional — verified by decoding every ARM
//! B/BL word in osos.dec, not Ghidra xrefs).
//!
//! A pure leaf mixer: takes a 64-bit key and folds it into a 32-bit hash.
//! The instruction sequence is Thomas Wang's 64→32 integer hash
//! (concentric.net/~Ttwang/tech/inthash.htm) exactly:
//!
//! ```text
//! key += ~(key << 32);   // ADS splits the <<32 complement by word
//! key ^= key >> 22;
//! key += ~(key << 13);
//! key ^= key >> 8;
//! key += key << 3;       // key *= 9
//! key ^= key >> 15;
//! key += ~(key << 27);
//! key ^= key >> 31;
//! return (uint32_t)key;  // high word folded in via the final xor-shift
//! ```
//!
//! Verified equivalent to a word-level simulation of the exact ARM
//! instruction stream (adds/adc carry chaining across the `~` forms) on
//! 20 000 random 64-bit inputs.
//!
//! ABI note: the stock function is called with four register arguments, but
//! the first instruction overwrites r0 and r1 is never read — only r2 (key
//! low word) and r3 (key high word) are inputs. The port keeps the two dead
//! leading parameters so the exported symbol matches the retail calling
//! convention exactly. All callers found (0x0826a030, 0x083d21e4,
//! 0x083d2284, 0x083d241c, 0x083d2524, 0x083d2744, 0x083d284c, 0x083d2a6c,
//! 0x083d2b74, 0x083d2d94, 0x083d2e9c, 0x083d6cc4) feed a hash table with
//! 64-bit keys: they pass the key bytes by value in r2:r3 and divide the
//! result by the bucket count via `__rt_udiv` (0x08036f14).

/// wang_hash_64_to_32 — original: `FUN_083d63cc` @ 0x083d63cc (148 bytes).
///
/// Mixes the 64-bit key `key_hi:key_lo` down to a 32-bit hash with Thomas
/// Wang's 64→32 integer hash. `_dead0`/`_dead1` occupy r0/r1 to match the
/// retail ABI; the original ignores both.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn wang_hash_64_to_32(
    _dead0: u32,
    _dead1: u32,
    key_lo: u32,
    key_hi: u32,
) -> u32 {
    let mut key = ((key_hi as u64) << 32) | key_lo as u64;
    key = key.wrapping_add(!(key << 32));
    key ^= key >> 22;
    key = key.wrapping_add(!(key << 13));
    key ^= key >> 8;
    key = key.wrapping_add(key << 3);
    key ^= key >> 15;
    key = key.wrapping_add(!(key << 27));
    key ^= key >> 31;
    key as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden outputs produced by a word-level simulation of the exact ARM
    /// instruction stream at 0x083d63cc (adds/adc carry chaining included),
    /// cross-checked against the u64 formula on 20 000 random inputs.
    fn hash(key: u64) -> u32 {
        wang_hash_64_to_32(0, 0, key as u32, (key >> 32) as u32)
    }

    #[test]
    fn golden_vectors_from_retail_instruction_stream() {
        assert_eq!(hash(0x0000_0000_0000_0000), 0x9c35_2659);
        assert_eq!(hash(0x0000_0000_0000_0001), 0xb09b_c659);
        assert_eq!(hash(0x0000_0000_0000_0002), 0x32c5_de12);
        assert_eq!(hash(0x0000_0000_ffff_ffff), 0xa6ad_b111);
        assert_eq!(hash(0x0000_0001_0000_0000), 0xa25e_fb3b);
        assert_eq!(hash(0xffff_ffff_ffff_ffff), 0x3258_2c16);
        assert_eq!(hash(0x8000_0000_0000_0000), 0xd714_812c);
        assert_eq!(hash(0xdead_beef_cafe_babe), 0x7a41_a6fb);
        assert_eq!(hash(0x0123_4567_89ab_cdef), 0x5be8_90c4);
        assert_eq!(hash(0x0000_0000_0000_3039), 0x61c2_d2b1);
    }

    /// Independent reference: the step sequence written as pure u64 ops.
    fn reference(mut key: u64) -> u32 {
        key = key.wrapping_add(!(key << 32));
        key ^= key >> 22;
        key = key.wrapping_add(!(key << 13));
        key ^= key >> 8;
        key = key.wrapping_add(key << 3);
        key ^= key >> 15;
        key = key.wrapping_add(!(key << 27));
        key ^= key >> 31;
        key as u32
    }

    #[test]
    fn dead_arguments_do_not_affect_the_result() {
        let key = 0x1234_5678_9abc_def0u64;
        let base = hash(key);
        assert_eq!(wang_hash_64_to_32(1, 0, key as u32, (key >> 32) as u32), base);
        assert_eq!(
            wang_hash_64_to_32(u32::MAX, u32::MAX, key as u32, (key >> 32) as u32),
            base
        );
    }

    #[test]
    fn matches_reference_on_structured_edge_cases() {
        // Carry-heavy boundaries for the adds/adc chains: low word all-ones,
        // zero low word with nonzero high word, byte lanes walking across the
        // word boundary.
        let fixed = [
            0x0000_0000_ffff_ffff,
            0xffff_ffff_0000_0000,
            0x0000_0001_ffff_ffff,
            0xffff_fffe_ffff_ffff,
        ];
        // Single bits in both words, and single zero bits.
        for k in 0..64 {
            assert_eq!(hash(1u64 << k), reference(1u64 << k), "bit {k}");
            assert_eq!(hash(!(1u64 << k)), reference(!(1u64 << k)), "hole {k}");
        }
        for &key in &fixed {
            assert_eq!(hash(key), reference(key), "key {key:#018x}");
        }
        for shift in 0..64 {
            let key = 0xffu64 << shift;
            assert_eq!(hash(key), reference(key), "byte lane {shift}");
        }
    }

    #[test]
    fn matches_reference_on_a_deterministic_sweep() {
        // splitmix64-style walk for deterministic, well-spread coverage.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..10_000 {
            state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9).wrapping_add(0x94d0_49bb_1331_11eb);
            state ^= state >> 29;
            assert_eq!(hash(state), reference(state), "key {state:#018x}");
        }
    }

    #[test]
    fn neighbouring_keys_diverge() {
        // A hash table mixer must avalanche: sequential keys land far apart.
        for base in 0..256u64 {
            assert_ne!(hash(base), hash(base + 1));
        }
    }
}
