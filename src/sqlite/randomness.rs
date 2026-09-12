//! SQLite pseudo-random byte filling.
//!
//! - `sqlite3_randomness` — original: `FUN_08390eb0` @ **0x08390eb0**
//!   (56 bytes, 0x08390eb0..0x08390ee8; **7 `bl` call sites**, all
//!   unconditional: 0x082367dc, 0x08365424, 0x0836555c, 0x08370384,
//!   0x08389608, 0x08397234, and 0x08398ab8; verified by decoding every
//!   ARM `B`/`BL` word in `osos.dec`).
//!
//! The retail sequence reads the word at `0x08a09918 + 0x1c` and stores 8
//! when it is zero, including for a zero-length request. It then calls the
//! still-stock `FUN_08365444` once per requested byte and stores each result
//! through the advancing output pointer. The byte generator is not ported;
//! target builds call its verified load address `0x08365444`, while host tests
//! install a recorder through the volatile callback slot.
//!
//! ### Deliberate deviations
//!
//! The anonymous setup word has no recovered identity, so this port names it
//! for its observed role rather than guessing. The target accesses the retail
//! BSS word directly; the host uses an equivalent private static. Rust's
//! `i32` count exposes the firmware's ARM `int`; as raw `subs`/`bcs` does,
//! a negative count wraps into a 2^32-byte write and is therefore outside the
//! function's safety contract rather than being normalized to zero.

/// Still-stock `FUN_08365444`, the byte generator called by the retail loop.
pub const RANDOM_BYTE_ADDRESS: usize = 0x0836_5444;

/// The literal at 0x08390ee8 plus the `ldr [r0, #0x1c]` field offset.
const RANDOMNESS_SETUP_WORD_ADDRESS: usize = 0x08a0_9934;

/// ABI of the random-byte callee.
pub type RandomByteFn = unsafe extern "C" fn() -> u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_random_byte() -> u8 {
    let random_byte: RandomByteFn = core::mem::transmute(RANDOM_BYTE_ADDRESS);
    random_byte()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_random_byte() -> u8 {
    panic!("sqlite_randomness requires FUN_08365444 @ 0x08365444")
}

/// Callback table for the only unported callee.
#[derive(Clone, Copy)]
pub struct RandomnessOps {
    pub random_byte: RandomByteFn,
}

/// Target default preserves the retail `bl 0x08365444` behavior.
pub const DEFAULT_RANDOMNESS_OPS: RandomnessOps = RandomnessOps {
    random_byte: retail_random_byte,
};

/// Active byte generator. Host tests replace it to observe every call.
pub static mut RANDOMNESS_OPS: RandomnessOps = DEFAULT_RANDOMNESS_OPS;

/// Volatile dispatch prevents LLVM from folding the target default away.
#[inline(always)]
unsafe fn random_byte_op() -> RandomByteFn {
    core::ptr::read_volatile(core::ptr::addr_of!(RANDOMNESS_OPS.random_byte))
}

#[cfg(target_os = "none")]
unsafe fn initialize_setup_word() {
    let word = RANDOMNESS_SETUP_WORD_ADDRESS as *mut i32;
    if word.read() == 0 {
        word.write(8);
    }
}

#[cfg(not(target_os = "none"))]
static mut RANDOMNESS_SETUP_WORD: i32 = 0;

#[cfg(not(target_os = "none"))]
unsafe fn initialize_setup_word() {
    let word = core::ptr::addr_of_mut!(RANDOMNESS_SETUP_WORD);
    if word.read() == 0 {
        word.write(8);
    }
}

/// `sqlite3Randomness`: fill `output[0..count]` with the generator's bytes.
///
/// # Safety
///
/// `output` must name at least `count` writable bytes and `count` must be
/// nonnegative. Neither condition is checked by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite3_randomness")]
#[inline(never)]
pub unsafe extern "C" fn sqlite_randomness(mut count: i32, mut output: *mut u8) {
    initialize_setup_word();
    if count == 0 {
        return;
    }
    let random_byte = random_byte_op();
    loop {
        output.write(random_byte());
        output = output.add(1);
        count = count.wrapping_sub(1);
        if count == 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that replace the process-global generator slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut NEXT_BYTE: u8 = 0;

    unsafe extern "C" fn sequential_random_byte() -> u8 {
        let byte = *core::ptr::addr_of!(NEXT_BYTE);
        *core::ptr::addr_of_mut!(NEXT_BYTE) = byte.wrapping_add(1);
        *core::ptr::addr_of_mut!(CALLS) += 1;
        byte
    }

    struct Bench {
        _guard: MutexGuard<'static, ()>,
    }

    impl Bench {
        fn new(first_byte: u8) -> Self {
            let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                *core::ptr::addr_of_mut!(CALLS) = 0;
                *core::ptr::addr_of_mut!(NEXT_BYTE) = first_byte;
                *core::ptr::addr_of_mut!(RANDOMNESS_SETUP_WORD) = 0;
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(RANDOMNESS_OPS),
                    RandomnessOps {
                        random_byte: sequential_random_byte,
                    },
                );
            }
            Bench { _guard: guard }
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(RANDOMNESS_OPS),
                    DEFAULT_RANDOMNESS_OPS,
                );
                *core::ptr::addr_of_mut!(RANDOMNESS_SETUP_WORD) = 0;
            }
        }
    }

    #[test]
    fn zero_length_sets_the_setup_word_without_calling_generator() {
        let _bench = Bench::new(0x20);
        let mut output = [0xa5; 3];
        unsafe { sqlite_randomness(0, output.as_mut_ptr().add(1)) };

        assert_eq!(output, [0xa5; 3]);
        unsafe {
            assert_eq!(*core::ptr::addr_of!(RANDOMNESS_SETUP_WORD), 8);
            assert_eq!(*core::ptr::addr_of!(CALLS), 0);
        }
    }

    #[test]
    fn fills_exact_requested_range_with_one_generator_call_per_byte() {
        let _bench = Bench::new(0x40);
        for count in 1usize..=6 {
            let mut output = [0xa5; 10];
            unsafe {
                *core::ptr::addr_of_mut!(CALLS) = 0;
                *core::ptr::addr_of_mut!(NEXT_BYTE) = 0x40;
                sqlite_randomness(count as i32, output.as_mut_ptr().add(2));
            }

            assert_eq!(&output[..2], &[0xa5; 2]);
            let expected = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45];
            assert_eq!(&output[2..2 + count], &expected[..count]);
            assert!(output[2 + count..].iter().all(|&byte| byte == 0xa5));
            unsafe {
                assert_eq!(*core::ptr::addr_of!(CALLS), count as u32);
                assert_eq!(*core::ptr::addr_of!(RANDOMNESS_SETUP_WORD), 8);
            }
        }
    }
}
