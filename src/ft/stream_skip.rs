//! ft_stream_skip_from_owner — original: `FUN_08073e3c` @ `0x08073e3c`
//! (12 bytes; 19 verified direct `bl` call sites, all unconditional).
//!
//! # Algorithm
//!
//! This is a three-instruction FreeType stream-skip wrapper. It loads the
//! stream handle from the owner object's aligned word at `+0x40000`, preserves
//! the signed distance in `r1`, and tail-enters the shared skip helper at
//! `0x0809d81c`. The helper handles negative seeks and positive reads; this
//! wrapper has no NULL guard or local result handling.
//!
//! # Deliberate deviations
//!
//! The shared helper is not ported. ARM builds retain the wrapper and reach
//! `0x0809d81c` through a literal veneer, since the Rust payload cannot retain
//! the original PC-relative branch. Host builds expose that transfer as a
//! volatile callback seam so tests can prove the loaded handle, signed
//! distance, and return value.

const STREAM_SLOT_WORD: usize = 0x10000;

/// ABI of the shared FreeType stream-skip helper at `0x0809d81c`.
pub type FtStreamSkipFn = unsafe extern "C" fn(stream: u32, distance: i32) -> i32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_ft_stream_skip(_stream: u32, _distance: i32) -> i32 {
    0
}

/// Host-only replacement for the unported shared skip helper.
#[cfg(not(target_arch = "arm"))]
pub static mut FT_STREAM_SKIP: FtStreamSkipFn = missing_ft_stream_skip;

/// `FUN_08073e3c` — loads an owner's FreeType stream and tail-enters its skip helper.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_stream_skip_from_owner(owner: *mut u8, distance: i32) -> i32 {
    let stream = owner.cast::<u32>().add(STREAM_SLOT_WORD).read();
    let skip = core::ptr::read_volatile(core::ptr::addr_of!(FT_STREAM_SKIP));
    skip(stream, distance)
}

// The stock body tail-branches to 0x0809d81c. This literal veneer retains the
// exact three-instruction body after relocation into the Rust payload.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl ft_stream_skip_from_owner
    .type ft_stream_skip_from_owner, %function
ft_stream_skip_from_owner:
    add     r0, r0, #0x40000
    ldr     r0, [r0]
    b       retail_ft_stream_skip
    .size ft_stream_skip_from_owner, . - ft_stream_skip_from_owner

retail_ft_stream_skip:
    ldr     pc, [pc, #-4]
    .word   0x0809d81c
    .size retail_ft_stream_skip, . - retail_ft_stream_skip
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{ft_stream_skip_from_owner, FtStreamSkipFn, FT_STREAM_SKIP, STREAM_SLOT_WORD};
    use parking_lot::Mutex;
    use std::vec;
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(u32, i32)> = Vec::new();
    static mut RETURN_VALUE: i32 = 0;

    unsafe extern "C" fn record_skip(stream: u32, distance: i32) -> i32 {
        CALLS.push((stream, distance));
        RETURN_VALUE
    }

    fn owner_with_stream(stream: u32) -> Vec<u32> {
        let mut owner = vec![0u32; STREAM_SLOT_WORD + 1];
        owner[STREAM_SLOT_WORD] = stream;
        owner
    }

    #[test]
    fn forwards_stream_slot_and_signed_distances_unchanged() {
        let _guard = TEST_LOCK.lock();
        let mut owner = owner_with_stream(0x1234_5678);
        unsafe {
            let saved = FT_STREAM_SKIP;
            CALLS.clear();
            RETURN_VALUE = -0x32;
            FT_STREAM_SKIP = record_skip as FtStreamSkipFn;

            assert_eq!(ft_stream_skip_from_owner(owner.as_mut_ptr().cast(), 0), -0x32);
            assert_eq!(ft_stream_skip_from_owner(owner.as_mut_ptr().cast(), 0x400), -0x32);
            assert_eq!(ft_stream_skip_from_owner(owner.as_mut_ptr().cast(), i32::MIN), -0x32);

            FT_STREAM_SKIP = saved;
            assert_eq!(CALLS, vec![(0x1234_5678, 0), (0x1234_5678, 0x400), (0x1234_5678, i32::MIN)]);
        }
    }
}
