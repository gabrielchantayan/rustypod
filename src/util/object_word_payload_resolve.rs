//! Resolving an object's mutable four-word payload.

/// Observed ABI of the unported payload processor at 0x0829b804.
pub type ObjectWordPayloadProcessor = unsafe extern "C" fn(*mut u32, *mut u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_object_word_payload_processor(
    object: *mut u32,
    words: *mut u32,
) {
    let processor: ObjectWordPayloadProcessor = unsafe { core::mem::transmute(0x0829_b804usize) };
    unsafe { processor(object, words) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_word_payload_processor(
    _object: *mut u32,
    _words: *mut u32,
) {
    panic!("object_word_payload_resolve requires processor 0x0829b804")
}

#[cfg(target_os = "none")]
const DEFAULT_OBJECT_WORD_PAYLOAD_PROCESSOR: ObjectWordPayloadProcessor =
    firmware_object_word_payload_processor;
#[cfg(not(target_os = "none"))]
const DEFAULT_OBJECT_WORD_PAYLOAD_PROCESSOR: ObjectWordPayloadProcessor =
    missing_object_word_payload_processor;

/// The unported retailOS payload processor. Target builds call its original
/// entry directly; host tests replace this seam with a behavioral model.
pub static mut OBJECT_WORD_PAYLOAD_PROCESSOR: ObjectWordPayloadProcessor =
    DEFAULT_OBJECT_WORD_PAYLOAD_PROCESSOR;

/// object_word_payload_resolve — original: `FUN_0829b490` @ **0x0829b490**
/// (**48 bytes exactly**, `0x0829b490..0x0829b4c0`; the separately linked next
/// function starts at `0x0829b4c4`).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies **10 direct inbound
/// `bl` call sites**, all unconditional; there are no predicated BL forms or
/// direct tail branches. The function snapshots four words from `object +
/// 0x1c` into a stack record, passes that record to the object's payload
/// processor, then copies the processor's four resulting words to
/// `destination`. The original restores its incoming r0 from the saved
/// register set, so it returns `destination` even though Ghidra reports an
/// eight-byte result.
///
/// Deliberate deviations: the still-unported processor at 0x0829b804 is an
/// explicit dispatch seam. Its target default reaches the retailOS entry;
/// host tests install a model. The two retail copies use a stack temporary, so
/// this port likewise snapshots all input words before any destination store.
///
/// # Safety
/// `object` must be valid for the processor and for four aligned `u32` reads
/// beginning at byte offset 0x1c. `destination` must be valid for four aligned
/// `u32` writes. Neither pointer is NULL-checked by the firmware.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_word_payload_resolve(
    destination: *mut u32,
    object: *mut u32,
) -> *mut u32 {
    let mut words = [
        unsafe { object.add(7).read() },
        unsafe { object.add(8).read() },
        unsafe { object.add(9).read() },
        unsafe { object.add(10).read() },
    ];
    let processor = unsafe {
        core::ptr::addr_of_mut!(OBJECT_WORD_PAYLOAD_PROCESSOR).read_volatile()
    };
    unsafe { processor(object, words.as_mut_ptr()) };
    unsafe {
        destination.write(words[0]);
        destination.add(1).write(words[1]);
        destination.add(2).write(words[2]);
        destination.add(3).write(words[3]);
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        object_word_payload_resolve, ObjectWordPayloadProcessor, OBJECT_WORD_PAYLOAD_PROCESSOR,
    };
    use parking_lot::Mutex;

    static PROCESSOR_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut SEEN_OBJECT: *mut u32 = core::ptr::null_mut();
    static mut SEEN_WORDS: [u32; 4] = [0; 4];

    unsafe extern "C" fn transform_payload(object: *mut u32, words: *mut u32) {
        unsafe {
            CALLS += 1;
            SEEN_OBJECT = object;
            SEEN_WORDS = [words.read(), words.add(1).read(), words.add(2).read(), words.add(3).read()];
            words.write(0xfeed_0001);
            words.add(1).write(SEEN_WORDS[3]);
            words.add(2).write(SEEN_WORDS[0] ^ SEEN_WORDS[2]);
            words.add(3).write(0xfeed_0004);
        }
    }

    struct ProcessorGuard(ObjectWordPayloadProcessor);

    impl Drop for ProcessorGuard {
        fn drop(&mut self) {
            unsafe { OBJECT_WORD_PAYLOAD_PROCESSOR = self.0 };
        }
    }

    unsafe fn install_transformer() -> ProcessorGuard {
        let previous = unsafe { OBJECT_WORD_PAYLOAD_PROCESSOR };
        unsafe { OBJECT_WORD_PAYLOAD_PROCESSOR = transform_payload };
        ProcessorGuard(previous)
    }

    #[test]
    fn snapshots_payload_processes_it_and_returns_destination() {
        let _lock = PROCESSOR_TEST_LOCK.lock();
        let _restore = unsafe { install_transformer() };
        let mut object = [0u32; 14];
        object[7..11].copy_from_slice(&[0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888]);
        let mut destination = [0u32; 4];
        unsafe {
            CALLS = 0;
            SEEN_OBJECT = core::ptr::null_mut();
            SEEN_WORDS = [0; 4];
        }

        let returned = unsafe { object_word_payload_resolve(destination.as_mut_ptr(), object.as_mut_ptr()) };

        assert_eq!(returned, destination.as_mut_ptr());
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { SEEN_OBJECT }, object.as_mut_ptr());
        assert_eq!(unsafe { SEEN_WORDS }, [0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888]);
        assert_eq!(destination, [0xfeed_0001, 0x7777_8888, 0x4444_4444, 0xfeed_0004]);
    }

    #[test]
    fn snapshots_source_before_writing_an_overlapping_destination() {
        let _lock = PROCESSOR_TEST_LOCK.lock();
        let _restore = unsafe { install_transformer() };
        let mut object = [0u32; 14];
        object[7..11].copy_from_slice(&[0x0123_4567, 0x89ab_cdef, 0x1357_9bdf, 0x2468_ace0]);
        unsafe {
            CALLS = 0;
            SEEN_OBJECT = core::ptr::null_mut();
            SEEN_WORDS = [0; 4];
        }

        let destination = unsafe { object.as_mut_ptr().add(7) };
        let returned = unsafe { object_word_payload_resolve(destination, object.as_mut_ptr()) };

        assert_eq!(returned, destination);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { SEEN_WORDS }, [0x0123_4567, 0x89ab_cdef, 0x1357_9bdf, 0x2468_ace0]);
        assert_eq!(&object[7..11], &[0xfeed_0001, 0x2468_ace0, 0x1274_deb8, 0xfeed_0004]);
    }
}
