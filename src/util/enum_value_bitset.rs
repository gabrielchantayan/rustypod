//! `enum_value_bitset` — original: `FUN_0806b488` @ `0x0806b488`.
//!
//! Verified extent is exactly `0x0806b488..0x0806b4a0` (24 bytes): the next
//! separately linked function starts at `0x0806b4a0` with `push {r3,r4,r5,lr}`.
//! It has four inbound plain `bl` callers (`0x080c6b30`, `0x080c6b7c`,
//! `0x080e2158`, and `0x080e2198`), zero predicated forms, and one plain
//! direct `bl` in its body to `FUN_08055b70` @ `0x08055b70`.
//!
//! The wrapper reserves five stack words, passes the enum value and the stack
//! base to the retail enum-to-bitset writer, then returns its first two output
//! words as a 64-bit bitset. The third output word is deliberately discarded.
//!
//! # Deliberate deviations
//!
//! `FUN_08055b70` has no recovered semantic identity or Rust port. The device
//! build calls its verified retail address directly; host tests install a seam.

#[cfg(not(target_os = "none"))]
use core::ptr;

const RETAIL_ENUM_TO_BITSET: usize = 0x0805_5b70;

type EnumToBitset = unsafe extern "C" fn(u32, *mut u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn enum_to_bitset(value: u32, output: *mut u32) {
    let writer: EnumToBitset = unsafe { core::mem::transmute(RETAIL_ENUM_TO_BITSET) };
    unsafe { writer(value, output) }
}

#[cfg(not(target_os = "none"))]
static mut ENUM_TO_BITSET: EnumToBitset = missing_enum_to_bitset;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_enum_to_bitset(_value: u32, _output: *mut u32) {
    panic!("enum_value_bitset requires FUN_08055b70 @ 0x08055b70")
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn enum_to_bitset(value: u32, output: *mut u32) {
    let writer = unsafe { ptr::read_volatile(ptr::addr_of!(ENUM_TO_BITSET)) };
    unsafe { writer(value, output) }
}

/// Returns the low 64 bits written by retailOS's enum-to-bitset conversion.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.enum_value_bitset")]
#[inline(never)]
pub unsafe extern "C" fn enum_value_bitset(value: u32) -> u64 {
    let mut output = core::mem::MaybeUninit::<[u32; 3]>::uninit();
    unsafe { enum_to_bitset(value, output.as_mut_ptr().cast()) };
    let output = unsafe { output.assume_init() };
    u64::from(output[0]) | (u64::from(output[1]) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn write_distinct_words(value: u32, output: *mut u32) {
        unsafe {
            output.write(value ^ 0x55aa_0000);
            output.add(1).write(value.wrapping_add(0x1234_5678));
            output.add(2).write(0xffff_ffff);
        }
    }

    #[test]
    fn returns_only_first_two_retail_output_words() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            ENUM_TO_BITSET = write_distinct_words;
            assert_eq!(
                enum_value_bitset(0),
                u64::from(0x55aa_0000u32) | (u64::from(0x1234_5678u32) << 32)
            );
            assert_eq!(
                enum_value_bitset(u32::MAX),
                u64::from(0xaa55_ffffu32) | (u64::from(0x1234_5677u32) << 32)
            );
            ENUM_TO_BITSET = missing_enum_to_bitset;
        }
    }
}
