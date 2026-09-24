//! Process a selected record in the shared four-slot buffer.
//!
//! `four_slot_buffer_process` — original: `FUN_080f7f08` @ `0x080f7f08`
//! (196 bytes, `0x080f7f08..0x080f7fcc`; **3 plain `bl` calls, 0 predicated**).
//!
//! Each 40-byte slot begins with a type byte. A selected type-3 slot passes
//! its +4 word and the caller's buffer triple to the fixed-address consumer.
//! Independently, slot zero of type 4 feeds its two embedded descriptor ranges
//! to the fixed-address transform, then copies the final `len & 15` bytes.
//!
//! # Deliberate deviations
//!
//! The two unported fixed-address targets remain typed seams on the host; ARM
//! builds call their verified raw addresses directly. The ROM memcpy veneer is
//! called through the existing `__rt_memcpy` port rather than its veneer.

use crate::libc::rt_memcpy::__rt_memcpy;

const SLOT_SIZE: usize = 0x28;
const TYPE_THREE: u8 = 3;
const TYPE_FOUR: u8 = 4;

type TypeThreeConsumer = unsafe extern "C" fn(u32, *mut u8, *mut u8, u32);
type TypeFourTransform = unsafe extern "C" fn(u32, u32, *mut u8, *mut u8, *mut u8, u32, *mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_type_three_consumer(
    slot_word: u32, source: *mut u8, destination: *mut u8, len: u32,
) {
    let call: TypeThreeConsumer = unsafe { core::mem::transmute(0x0806_e0e0usize) };
    unsafe { call(slot_word, source, destination, len) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_type_three_consumer(
    _slot_word: u32, _source: *mut u8, _destination: *mut u8, _len: u32,
) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_type_four_transform(
    zero_a: u32, zero_b: u32, descriptor: *mut u8, source: *mut u8, destination: *mut u8,
    aligned_len: u32, tail_descriptor: *mut u8,
) {
    let call: TypeFourTransform = unsafe { core::mem::transmute(0x0803_9968usize) };
    unsafe { call(zero_a, zero_b, descriptor, source, destination, aligned_len, tail_descriptor) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_type_four_transform(
    _zero_a: u32, _zero_b: u32, _descriptor: *mut u8, _source: *mut u8, _destination: *mut u8,
    _aligned_len: u32, _tail_descriptor: *mut u8,
) {}

#[cfg(not(target_os = "none"))]
static mut TYPE_THREE_CONSUMER: TypeThreeConsumer = missing_type_three_consumer;
#[cfg(not(target_os = "none"))]
static mut TYPE_FOUR_TRANSFORM: TypeFourTransform = missing_type_four_transform;

#[cfg(target_os = "none")]
unsafe fn type_three_consume(slot_word: u32, source: *mut u8, destination: *mut u8, len: u32) {
    unsafe { firmware_type_three_consumer(slot_word, source, destination, len) }
}
#[cfg(not(target_os = "none"))]
unsafe fn type_three_consume(slot_word: u32, source: *mut u8, destination: *mut u8, len: u32) {
    let consumer = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TYPE_THREE_CONSUMER)) };
    unsafe { consumer(slot_word, source, destination, len) }
}

#[cfg(target_os = "none")]
unsafe fn type_four_transform(
    descriptor: *mut u8, source: *mut u8, destination: *mut u8, aligned_len: u32, tail_descriptor: *mut u8,
) {
    unsafe { firmware_type_four_transform(0, 0, descriptor, source, destination, aligned_len, tail_descriptor) }
}
#[cfg(not(target_os = "none"))]
unsafe fn type_four_transform(
    descriptor: *mut u8, source: *mut u8, destination: *mut u8, aligned_len: u32, tail_descriptor: *mut u8,
) {
    let transform = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TYPE_FOUR_TRANSFORM)) };
    unsafe { transform(0, 0, descriptor, source, destination, aligned_len, tail_descriptor) }
}

/// # Safety
/// `slots` contains four 40-byte records. `source` and `destination` are valid
/// for `len` bytes whenever slot zero has type 4.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn four_slot_buffer_process(
    slots: *mut u8, source: *mut u8, destination: *mut u8, len: u32, selected_slot: u32,
) {
    if selected_slot < 4 {
        let slot = unsafe { slots.add(selected_slot as usize * SLOT_SIZE) };
        if unsafe { slot.read() } == TYPE_THREE {
            unsafe { type_three_consume(slot.add(4).cast::<u32>().read(), source, destination, len) };
        }
    }

    if unsafe { slots.read() } == TYPE_FOUR && selected_slot == 0 {
        let aligned_len = len & !15;
        unsafe {
            type_four_transform(slots.add(8), source, destination, aligned_len, slots.add(0x18));
            __rt_memcpy(
                destination.add(aligned_len as usize), source.add(aligned_len as usize), (len & 15) as usize,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut TYPE_THREE_ARGS: [usize; 4] = [0; 4];
    static mut TYPE_FOUR_ARGS: [usize; 7] = [0; 7];

    unsafe extern "C" fn record_type_three(slot_word: u32, source: *mut u8, destination: *mut u8, len: u32) {
        unsafe { TYPE_THREE_ARGS = [slot_word as usize, source as usize, destination as usize, len as usize]; }
    }

    unsafe extern "C" fn record_type_four(
        zero_a: u32, zero_b: u32, descriptor: *mut u8, source: *mut u8, destination: *mut u8,
        aligned_len: u32, tail_descriptor: *mut u8,
    ) {
        unsafe {
            TYPE_FOUR_ARGS = [zero_a as usize, zero_b as usize, descriptor as usize, source as usize,
                destination as usize, aligned_len as usize, tail_descriptor as usize];
        }
    }

    struct Seams { type_three: TypeThreeConsumer, type_four: TypeFourTransform }
    impl Seams {
        unsafe fn install() -> Self {
            unsafe {
                let seams = Self { type_three: TYPE_THREE_CONSUMER, type_four: TYPE_FOUR_TRANSFORM };
                TYPE_THREE_CONSUMER = record_type_three;
                TYPE_FOUR_TRANSFORM = record_type_four;
                TYPE_THREE_ARGS = [0; 4];
                TYPE_FOUR_ARGS = [0; 7];
                seams
            }
        }
    }
    impl Drop for Seams {
        fn drop(&mut self) {
            unsafe { TYPE_THREE_CONSUMER = self.type_three; TYPE_FOUR_TRANSFORM = self.type_four; }
        }
    }

    #[test]
    fn type_three_selected_slot_forwards_the_exact_buffer_triple() {
        let _lock = SEAM_LOCK.lock();
        let _seams = unsafe { Seams::install() };
        let mut slots = [0u8; SLOT_SIZE * 4];
        slots[SLOT_SIZE * 2] = TYPE_THREE;
        unsafe { slots.as_mut_ptr().add(SLOT_SIZE * 2 + 4).cast::<u32>().write(0xdead_beef); }
        let mut source = [0u8; 32];
        let mut destination = [0u8; 32];
        unsafe { four_slot_buffer_process(slots.as_mut_ptr(), source.as_mut_ptr(), destination.as_mut_ptr(), 31, 2); }
        assert_eq!(unsafe { TYPE_THREE_ARGS }, [0xdead_beef, source.as_mut_ptr() as usize, destination.as_mut_ptr() as usize, 31]);
        assert_eq!(unsafe { TYPE_FOUR_ARGS }, [0; 7]);
    }

    #[test]
    fn type_four_slot_zero_transforms_aligned_prefix_and_copies_tail() {
        let _lock = SEAM_LOCK.lock();
        let _seams = unsafe { Seams::install() };
        let mut slots = [0u8; SLOT_SIZE * 4];
        slots[0] = TYPE_FOUR;
        let source = *b"0123456789abcdefghijklmnopqrstuv";
        let mut destination = [0xa5u8; 32];
        unsafe { four_slot_buffer_process(slots.as_mut_ptr(), source.as_ptr() as *mut u8, destination.as_mut_ptr(), 19, 0); }
        assert_eq!(unsafe { TYPE_FOUR_ARGS }, [0, 0, slots.as_mut_ptr().wrapping_add(8) as usize, source.as_ptr() as usize, destination.as_mut_ptr() as usize, 16, slots.as_mut_ptr().wrapping_add(0x18) as usize]);
        assert_eq!(&destination[16..19], &source[16..19]);
        assert_eq!(&destination[..16], &[0xa5; 16]);
    }

    #[test]
    fn nonmatching_type_or_selector_has_no_side_effects() {
        let _lock = SEAM_LOCK.lock();
        let _seams = unsafe { Seams::install() };
        let mut slots = [0u8; SLOT_SIZE * 4];
        slots[0] = TYPE_FOUR;
        let source = [1u8; 16];
        let mut destination = [0xa5u8; 16];
        unsafe { four_slot_buffer_process(slots.as_mut_ptr(), source.as_ptr() as *mut u8, destination.as_mut_ptr(), 16, 4); }
        assert_eq!(unsafe { TYPE_THREE_ARGS }, [0; 4]);
        assert_eq!(unsafe { TYPE_FOUR_ARGS }, [0; 7]);
        assert_eq!(destination, [0xa5; 16]);
    }
}
