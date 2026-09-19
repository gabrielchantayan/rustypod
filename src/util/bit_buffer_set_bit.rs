//! Sets one MSB-first bit in a growable retailOS bit buffer.
//!
//! `bit_buffer_set_bit` — retailOS `FUN_080913dc` @ 0x080913dc.
//!
//! Raw `osos.dec` establishes the exact 88-byte extent from 0x080913dc
//! through `pop {r4,r5,r6,pc}` at 0x08091430; 0x08091434 starts the next
//! function. Whole-image A32 decoding finds three incoming plain `bl` calls
//! (0x0809c248, 0x0809c260, and 0x080cd9a4) and one incoming predicated
//! `bleq` call (0x0809c274). The body has one plain `bl`, to unported
//! `bit_buffer_ensure_capacity` at 0x0808ab4c, and no predicated calls.
//!
//! Algorithm: reject negative bit indices, grow the byte buffer when the
//! index is beyond its logical bit length, then set the selected byte's
//! MSB-first bit. The capacity helper receives the caller's context in r2;
//! Ghidra omitted that third argument. Deliberate deviations: the verified
//! but unported helper remains an address-based target call and host seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_BIT_BUFFER_ENSURE_CAPACITY: usize = 0x0808_ab4c;

type BitBufferEnsureCapacity = unsafe extern "C" fn(*mut u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ensure_capacity(_buffer: *mut u32, _bits: u32, _context: u32) -> u32 {
    panic!("install bit-buffer set-bit host operations before growing a buffer")
}

#[cfg(not(target_os = "none"))]
pub static mut BIT_BUFFER_SET_BIT_ENSURE_CAPACITY: BitBufferEnsureCapacity = missing_ensure_capacity;

#[inline(always)]
unsafe fn ensure_capacity(buffer: *mut u32, bits: u32, context: u32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let helper: BitBufferEnsureCapacity = unsafe { core::mem::transmute(RETAIL_BIT_BUFFER_ENSURE_CAPACITY) };
        return unsafe { helper(buffer, bits, context) };
    }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(addr_of!(BIT_BUFFER_SET_BIT_ENSURE_CAPACITY))(buffer, bits, context) }
}

/// Sets `bit_index` in an MSB-first growable bit buffer.
///
/// `buffer` word zero is its logical bit length and word two is a target-width
/// pointer to its byte storage. `context` is forwarded to the capacity helper.
///
/// # Safety
///
/// A non-negative index requires a valid `buffer`; when it is already within
/// the logical length, word two must address writable byte storage for it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bit_buffer_set_bit(buffer: *mut u32, bit_index: i32, context: u32) -> u32 {
    if bit_index < 0 {
        return 0;
    }

    let bit_index = bit_index as u32;
    if unsafe { buffer.read() } <= bit_index {
        let result = unsafe { ensure_capacity(buffer, bit_index.wrapping_add(1), context) };
        if result != 0 {
            return result;
        }
        unsafe { buffer.write(bit_index.wrapping_add(1)); }
    }

    let byte = unsafe { (buffer.add(2).read() as usize as *mut u8).add((bit_index >> 3) as usize) };
    unsafe { byte.write(byte.read() | (0x80 >> (bit_index & 7))); }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{bit_buffer_set_bit, BitBufferEnsureCapacity, BIT_BUFFER_SET_BIT_ENSURE_CAPACITY};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CAPACITY_RESULT: u32 = 0;
    static mut EXPECTED_CONTEXT: u32 = 0;
    static mut EXPECTED_BITS: u32 = 0;

    unsafe extern "C" fn ensure_capacity(_buffer: *mut u32, bits: u32, context: u32) -> u32 {
        assert_eq!(bits, unsafe { EXPECTED_BITS });
        assert_eq!(context, unsafe { EXPECTED_CONTEXT });
        unsafe { CAPACITY_RESULT }
    }

    unsafe fn install(result: u32, bits: u32, context: u32) {
        CAPACITY_RESULT = result;
        EXPECTED_BITS = bits;
        EXPECTED_CONTEXT = context;
        BIT_BUFFER_SET_BIT_ENSURE_CAPACITY = ensure_capacity as BitBufferEnsureCapacity;
    }

    #[test]
    fn negative_indices_return_without_dereferencing_the_buffer() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(unsafe { bit_buffer_set_bit(core::ptr::null_mut(), -1, 0) }, 0);
        assert_eq!(unsafe { bit_buffer_set_bit(core::ptr::null_mut(), i32::MIN, 0) }, 0);
    }

    #[test]
    fn sets_msb_first_bits_without_growing() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(bytes) = crate::testing::try_map_u32_slab(crate::testing::hints::BIT_BUFFER_SET_BIT, 0x1000) else { return };
        unsafe {
            bytes.write_bytes(0, 0x1000);
            let mut buffer = [16, 0, bytes as usize as u32];
            assert_eq!(bit_buffer_set_bit(buffer.as_mut_ptr(), 0, 0), 0);
            assert_eq!(bit_buffer_set_bit(buffer.as_mut_ptr(), 7, 0), 0);
            assert_eq!(bit_buffer_set_bit(buffer.as_mut_ptr(), 8, 0), 0);
            assert_eq!(buffer[0], 16);
            assert_eq!(*bytes, 0x81);
            assert_eq!(*bytes.add(1), 0x80);
        }
    }

    #[test]
    fn grows_then_sets_and_propagates_capacity_failure() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(bytes) = crate::testing::try_map_u32_slab(crate::testing::hints::BIT_BUFFER_SET_BIT, 0x1000) else { return };
        unsafe {
            bytes.write_bytes(0, 0x1000);
            let mut buffer = [0, 0, bytes as usize as u32];
            install(0, 10, 0xdead_beef);
            assert_eq!(bit_buffer_set_bit(buffer.as_mut_ptr(), 9, 0xdead_beef), 0);
            assert_eq!(buffer[0], 10);
            assert_eq!(*bytes.add(1), 0x40);

            install(7, 11, 3);
            assert_eq!(bit_buffer_set_bit(buffer.as_mut_ptr(), 10, 3), 7);
            assert_eq!(buffer[0], 10);
            assert_eq!(*bytes.add(1), 0x40);
        }
    }
}
