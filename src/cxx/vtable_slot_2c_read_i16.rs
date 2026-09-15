//! Virtual slot-`+0x2c` signed-16-bit reader.
//!
//! `vtable_slot_2c_read_i16` — original: `FUN_08275c38` @ **0x08275c38**
//! (80 bytes). Raw ARM establishes the exact extent from `push {r3,r4,r5,lr}`
//! at `0x08275c38` through `pop {r3,r4,r5,pc}` at `0x08275c84`; the next
//! separately linked function begins at `0x08275c88`.
//!
//! Decoding every aligned immediate ARM `B`/`BL` word in `osos.dec` finds
//! exactly five inbound direct calls, all unconditional plain `bl` at
//! `0x0815fab0`, `0x081a378c`, `0x081a3798`, `0x081a37bc`, and `0x081a37c8`.
//! There are no predicated direct calls or direct tail branches. The wrapper
//! invokes an indirect `blx` through vtable word 11 (`+0x2c`).
//!
//! # Algorithm
//!
//! Seeds a caller-supplied word's low 16 bits, asks vtable slot `+0x2c` to
//! read two bytes into it, and returns -1 unless exactly two bytes were read.
//! On success, byte +8 of the receiver selects a byte swap before the signed
//! 16-bit result is returned. The two middle ABI arguments are unused.
//!
//! # Deliberate deviation
//!
//! Target vtable entries are 32-bit words, while host function pointers are
//! wider. Rust selects word index 11 in a host-sized vtable and calls the
//! equivalent typed callback.

/// ARMv5TE vtable word index for byte offset `+0x2c`.
const READ_I16_SLOT: usize = 0x2c / 4;

/// ABI of the unrecovered virtual method in vtable slot `+0x2c`.
pub type VtableReadI16 = unsafe extern "C" fn(*mut u8, *mut u16, u32) -> i32;

/// Reads a signed 16-bit value through vtable slot `+0x2c`.
///
/// # Safety
///
/// `receiver` must have a readable vtable pointer and byte +8, and vtable word
/// 11 must name a valid [`VtableReadI16`] callback. The callback must accept a
/// writable two-byte result cell. No pointers are validated, matching retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_2c_read_i16(
    receiver: *mut u8,
    _discarded_r1: u32,
    _discarded_r2: u32,
    initial_value: u32,
) -> i32 {
    let vtable = unsafe { (receiver as *const *const usize).read() };
    let entry = unsafe { vtable.add(READ_I16_SLOT).read() };
    let read: VtableReadI16 = unsafe { core::mem::transmute(entry) };
    let mut value = initial_value as u16;
    if unsafe { read(receiver, &mut value, 2) } != 2 {
        return -1;
    }
    if unsafe { receiver.add(8).read() } != 0 {
        value = value.swap_bytes();
    }
    value as i16 as i32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_RECEIVER: usize = 0;
    static mut FORWARDED_LENGTH: u32 = 0;
    static mut INITIAL_VALUE: u16 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;
    static mut READ_RESULT: i32 = 0;
    static mut READ_VALUE: u16 = 0;

    unsafe extern "C" fn read_method(receiver: *mut u8, value: *mut u16, length: u32) -> i32 {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            FORWARDED_LENGTH = length;
            INITIAL_VALUE = value.read();
            value.write(READ_VALUE);
            READ_RESULT
        }
    }

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8, _value: *mut u16, _length: u32) -> i32 {
        unsafe { WRONG_SLOT_CALLS += 1; }
        0
    }

    #[repr(C)]
    struct VtableObject {
        vtable: *const usize,
        byte_order: u8,
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_RECEIVER = 0;
            FORWARDED_LENGTH = 0;
            INITIAL_VALUE = 0;
            WRONG_SLOT_CALLS = 0;
            READ_RESULT = 0;
            READ_VALUE = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn returns_signed_little_endian_value_after_exact_read() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; READ_I16_SLOT + 1];
        vtable[READ_I16_SLOT] = read_method as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr(), byte_order: 0 };
        unsafe {
            READ_RESULT = 2;
            READ_VALUE = 0x80ff;
        }

        let result = unsafe {
            vtable_slot_2c_read_i16((&mut object as *mut VtableObject).cast(), 1, 2, 0x1234_5678)
        };

        assert_eq!(result, -32513);
        assert_eq!(unsafe { FORWARDED_RECEIVER }, (&mut object as *mut VtableObject) as usize);
        assert_eq!(unsafe { FORWARDED_LENGTH }, 2);
        assert_eq!(unsafe { INITIAL_VALUE }, 0x5678);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x2c may run");
    }

    #[test]
    fn swaps_bytes_when_receiver_byte_eight_is_nonzero() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; READ_I16_SLOT + 1];
        vtable[READ_I16_SLOT] = read_method as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr(), byte_order: 1 };
        unsafe {
            READ_RESULT = 2;
            READ_VALUE = 0x80ff;
        }

        let result = unsafe {
            vtable_slot_2c_read_i16((&mut object as *mut VtableObject).cast(), 0, 0, 0)
        };

        assert_eq!(result, -128);
    }

    #[test]
    fn returns_minus_one_for_short_read_without_byte_swap() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; READ_I16_SLOT + 1];
        vtable[READ_I16_SLOT] = read_method as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr(), byte_order: 1 };
        unsafe {
            READ_RESULT = 1;
            READ_VALUE = 0x1234;
        }

        let result = unsafe {
            vtable_slot_2c_read_i16((&mut object as *mut VtableObject).cast(), 0, 0, 0xabcd)
        };

        assert_eq!(result, -1);
        assert_eq!(unsafe { INITIAL_VALUE }, 0xabcd);
    }
}
