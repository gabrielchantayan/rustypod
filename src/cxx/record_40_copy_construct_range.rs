//! record_40_copy_construct_range — original: `FUN_083e9d08` @ 0x083e9d08 (52 bytes).
//!
//! Raw `osos.dec` words establish the exact thirteen-instruction extent
//! `0x083e9d08..0x083e9d3b`: `push {r4-r6,lr}` at the entry and the distinct
//! sibling's `push {r4-r6,lr}` at `0x083e9d3c` bound it. The body has one
//! plain `bl`, to the 40-byte record copy constructor at `0x0825c824`, and no
//! predicated `bl`. Whole-image ARM branch decoding finds two inbound plain
//! `bl` calls (`0x083e351c`, `0x083e356c`) and no inbound predicated calls.
//!
//! Algorithm: construct-copy successive 40-byte records from `[source, end)`
//! into `destination`, advancing both cursors by 40 bytes after each call, and
//! return the final destination cursor. Deliberate deviation: the retail
//! direct call is represented by an absolute-literal veneer so relocated patch
//! payload code can reach the unported constructor at `0x0825c824`.

/// Constructs one 40-byte record at `destination` from `source` using the
/// unported retail copy constructor at `0x0825c824`.
#[cfg(not(target_arch = "arm"))]
pub type Record40CopyConstructor = unsafe extern "C" fn(*mut u8, *const u8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_record_40_copy_constructor(_destination: *mut u8, _source: *const u8) {}

/// Host-only replacement for the retail copy constructor.
#[cfg(not(target_arch = "arm"))]
pub static mut RECORD_40_COPY_CONSTRUCTOR: Record40CopyConstructor = missing_record_40_copy_constructor;

#[cfg(not(target_arch = "arm"))]
#[inline(never)]
unsafe fn record_40_copy_construct(destination: *mut u8, source: *const u8) {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(RECORD_40_COPY_CONSTRUCTOR))(destination, source);
    }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .type record_40_copy_construct, %function
record_40_copy_construct:
    ldr     pc, 1f

1:  .word   0x0825c824
    .size record_40_copy_construct, . - record_40_copy_construct
"#
);
#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn record_40_copy_construct(destination: *mut u8, source: *const u8);
}


/// Construct-copy 40-byte records from `[source, end)` into `destination`.
///
/// # Safety
///
/// `source` and `end` must delimit a forward range in 40-byte increments, and
/// `destination` must designate enough valid record storage. The retail
/// constructor defines the individual record-copy semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_40_copy_construct_range(
    source: *const u8,
    end: *const u8,
    mut destination: *mut u8,
) -> *mut u8 {
    let mut source = source;
    while source != end {
        unsafe {
            record_40_copy_construct(destination, source);
            source = source.add(40);
            destination = destination.add(40);
        }
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{RECORD_40_COPY_CONSTRUCTOR, Record40CopyConstructor, record_40_copy_construct_range};
    use core::ptr::copy_nonoverlapping;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: usize = 0;

    unsafe extern "C" fn copying_constructor(destination: *mut u8, source: *const u8) {
        unsafe {
            CALLS += 1;
            copy_nonoverlapping(source, destination, 40);
        }
    }

    struct ConstructorRestore(Record40CopyConstructor);

    impl Drop for ConstructorRestore {
        fn drop(&mut self) {
            unsafe { RECORD_40_COPY_CONSTRUCTOR = self.0 };
        }
    }

    #[test]
    fn empty_range_does_not_construct_a_record() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RECORD_40_COPY_CONSTRUCTOR;
            RECORD_40_COPY_CONSTRUCTOR = copying_constructor;
            CALLS = 0;
            ConstructorRestore(previous)
        };
        let mut record = [0xa5u8; 40];
        let result = unsafe {
            record_40_copy_construct_range(record.as_ptr(), record.as_ptr(), record.as_mut_ptr())
        };

        assert_eq!(unsafe { CALLS }, 0);
        assert_eq!(result, record.as_mut_ptr());
        assert_eq!(record, [0xa5; 40]);
    }

    #[test]
    fn constructs_each_record_and_returns_final_destination() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RECORD_40_COPY_CONSTRUCTOR;
            RECORD_40_COPY_CONSTRUCTOR = copying_constructor;
            CALLS = 0;
            ConstructorRestore(previous)
        };
        let mut source = [0u8; 80];
        for (index, byte) in source.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut destination = [0xa5u8; 120];
        let result = unsafe {
            record_40_copy_construct_range(source.as_ptr(), unsafe { source.as_ptr().add(80) }, unsafe {
                destination.as_mut_ptr().add(8)
            })
        };

        assert_eq!(unsafe { CALLS }, 2);
        assert_eq!(&destination[8..88], &source);
        assert_eq!(&destination[..8], &[0xa5; 8]);
        assert_eq!(&destination[88..], &[0xa5; 32]);
        assert_eq!(result, unsafe { destination.as_mut_ptr().add(88) });
    }
}
