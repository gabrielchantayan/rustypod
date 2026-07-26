//! Port of the ARM ADS 1.0.1 PRNG (`srandom`/`random`) — the first stateful
//! port. This is an additive lagged-Fibonacci generator over a 55-word
//! state table, seeded by an LCG.
//!
//! Originals:
//! - `srandom` @ 0x08030e7c (68 bytes): sets the lag indices to 23 and 54,
//!   then fills table[i] = seed + (seed >> 16) for i in 0..55, advancing
//!   seed = seed * 69069 + 0x66d619e1 after each store (wrapping u32 math).
//! - `srandom1_thunk` @ 0x08030ec0 (8 bytes): `srandom(1)`.
//! - `random` @ 0x08030ec8 (84 bytes): sum = table[idx0] + table[idx1],
//!   stores the sum back at table[idx1], decrements both indices (each
//!   wraps 0 -> 54), returns sum & 0x7fffffff (`bic r0, ip, #0x80000000`).
//!
//! Original state (bss, zero-initialized until the first srandom call):
//! - state table: 55 u32 words @ 0x08b2f918
//! - lag indices: 2 u32 words @ 0x08a0fb94 ([0] starts 23, [1] starts 54)
//!
//! Simplification: the original updates the indices with a conditional
//! sequence that skips the wrap check on index [1] when index [0] wraps.
//! Since both indices decrement in lockstep from (23, 54), their difference
//! stays 31 mod 55 and they can never be 0 at the same time, so the plain
//! "decrement, wrap 0 -> 54" form used here is exactly equivalent.

/// State table — original: 55 words @ 0x08b2f918.
static mut RAND_TABLE: [u32; 55] = [0; 55];

/// Lag indices — original: 2 words @ 0x08a0fb94.
/// [0] lags [1] by 31 positions; seeded to [23, 54] by `srandom`.
static mut RAND_INDEX: [u32; 2] = [0; 2];

const LCG_MULTIPLIER: u32 = 69069; // 0x10dcd
const LCG_INCREMENT: u32 = 0x66d619e1;
const LAST_INDEX: u32 = 54;

/// srandom — original: `FUN_08030e7c` @ 0x08030e7c (68 bytes).
///
/// Seeds the 55-word state table with an LCG and resets the lag indices.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn srandom(seed: u32) {
    RAND_INDEX[0] = 23;
    RAND_INDEX[1] = 54;
    let mut state = seed;
    for i in 0..55 {
        RAND_TABLE[i] = state.wrapping_add(state >> 16);
        state = state.wrapping_mul(LCG_MULTIPLIER).wrapping_add(LCG_INCREMENT);
    }
}

/// srandom1_thunk — original: `FUN_08030ec0` @ 0x08030ec0 (8 bytes).
///
/// `srandom(1)`; the classic ADS `srand(1)`-style reset tail call.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn srandom1_thunk() {
    srandom(1);
}

/// random — original: `FUN_08030ec8` @ 0x08030ec8 (84 bytes).
///
/// Additive lagged-Fibonacci step: add the two lagged table entries, store
/// the sum back at the trailing position, step both indices backward
/// (wrapping 0 -> 54), and return the sum masked to 31 bits.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn random() -> i32 {
    let back = RAND_INDEX[0] as usize;
    let front = RAND_INDEX[1] as usize;
    // Indices are always in 0..=54 by construction (srandom seeds 23/54 and
    // both only ever decrement/wrap). Raw-pointer access keeps bounds checks
    // (and panic_bounds_check) out of the ARM build, like the original.
    let table = core::ptr::addr_of_mut!(RAND_TABLE) as *mut u32;
    let sum = (*table.add(back)).wrapping_add(*table.add(front));
    *table.add(front) = sum;
    RAND_INDEX[0] = if back == 0 { LAST_INDEX } else { back as u32 - 1 };
    RAND_INDEX[1] = if front == 0 { LAST_INDEX } else { front as u32 - 1 };
    (sum & 0x7fff_ffff) as i32
}

/// rand — alias of `random` (no separate original; same generator).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rand() -> i32 {
    random()
}

/// srand — alias of `srandom` (no separate original; same seeding).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn srand(seed: u32) {
    srandom(seed);
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    /// All tests share the one global generator state — serialize them.
    /// Shared with runtime/lib_init.rs, whose init walk seeds the state.
    static LOCK: Mutex<()> = Mutex::new(());

    /// Locks the generator state for a test outside this module
    /// (lib_init.rs's full-init test; raise.rs's `TEST_SIGNAL_LOCK`
    /// precedent).
    pub(crate) fn lock_state() -> std::sync::MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reference implementation, re-derived independently from the ARM
    /// disassembly (not copied from the port above).
    struct Reference {
        table: [u32; 55],
        idx_back: usize,
        idx_front: usize,
    }

    impl Reference {
        fn seeded(seed: u32) -> Self {
            let mut r = Reference {
                table: [0; 55],
                idx_back: 23,
                idx_front: 54,
            };
            let mut x = seed;
            for i in 0..55 {
                r.table[i] = (x + (x >> 16)) & 0xffff_ffff;
                x = (x.wrapping_mul(69069)).wrapping_add(0x66d6_19e1);
            }
            r
        }

        fn next(&mut self) -> i32 {
            let sum = self.table[self.idx_back].wrapping_add(self.table[self.idx_front]);
            self.table[self.idx_front] = sum;
            self.idx_back = if self.idx_back == 0 { 54 } else { self.idx_back - 1 };
            self.idx_front = if self.idx_front == 0 { 54 } else { self.idx_front - 1 };
            (sum & 0x7fff_ffff) as i32
        }
    }

    #[test]
    fn matches_reference_seed_1_first_100() {
        let _g = LOCK.lock().unwrap();
        let mut reference = Reference::seeded(1);
        unsafe {
            srandom(1);
            for i in 0..100 {
                assert_eq!(random(), reference.next(), "mismatch at output {i}");
            }
        }
    }

    #[test]
    fn matches_reference_seed_42() {
        let _g = LOCK.lock().unwrap();
        let mut reference = Reference::seeded(42);
        unsafe {
            srandom(42);
            for i in 0..100 {
                assert_eq!(random(), reference.next(), "mismatch at output {i}");
            }
        }
    }

    #[test]
    fn reseed_reproduces_sequence() {
        let _g = LOCK.lock().unwrap();
        unsafe {
            srandom(7);
            let first: std::vec::Vec<i32> = (0..50).map(|_| random()).collect();
            // Advance the state, then reseed — sequence must restart exactly.
            let _ = random();
            srandom(7);
            let second: std::vec::Vec<i32> = (0..50).map(|_| random()).collect();
            assert_eq!(first, second);
        }
    }

    #[test]
    fn output_is_masked_to_31_bits() {
        let _g = LOCK.lock().unwrap();
        unsafe {
            srandom(0xdead_beef);
            for _ in 0..1000 {
                let value = random();
                assert!(value >= 0, "negative output {value:#x}");
            }
        }
    }

    #[test]
    fn aliases_match_primary_entry_points() {
        let _g = LOCK.lock().unwrap();
        unsafe {
            srandom(99);
            let expected: std::vec::Vec<i32> = (0..20).map(|_| random()).collect();
            srand(99);
            let via_alias: std::vec::Vec<i32> = (0..20).map(|_| rand()).collect();
            assert_eq!(expected, via_alias);
        }
    }

    #[test]
    fn thunk_seeds_with_one() {
        let _g = LOCK.lock().unwrap();
        unsafe {
            srandom(1);
            let expected: std::vec::Vec<i32> = (0..20).map(|_| random()).collect();
            srandom1_thunk();
            let via_thunk: std::vec::Vec<i32> = (0..20).map(|_| random()).collect();
            assert_eq!(expected, via_thunk);
        }
    }
}
