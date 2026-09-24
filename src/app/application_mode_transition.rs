//! `application_mode_transition` — original: `FUN_081163cc` @ `0x081163cc`.
//!
//! Raw A32 establishes the true 64-byte extent: fifteen instruction words
//! through the tail `b 0x082898dc` at `0x08116408`, followed by the
//! `0x089ca660` global-byte literal at `0x0811640c`. The next distinct
//! function begins at `0x08116410`. The body has zero plain `bl` and zero
//! predicated `bl` instructions; its final branch targets the one-word
//! `bx lr` no-op at `0x082898dc`, preserving `r0` as the return value.
//!
//! # Algorithm
//!
//! When enabling from a clear global mode byte, copy the context word at
//! `+0x488` to `+0x494` and set that byte. When disabling from a set byte,
//! clear it. In every case return the context word at `+0x42c`.
//!
//! # Deliberate deviations
//!
//! The global's subsystem identity is not recovered. Host builds use private
//! backing storage in place of firmware RAM at `0x089ca660`; the verified
//! tail call is inlined because it is an empty `bx lr` function.
use core::ptr;

#[cfg(target_os = "none")]
const APPLICATION_MODE_FLAG_ADDRESS: *mut u8 = 0x089c_a660usize as *mut u8;
const RESULT_OFFSET: usize = 0x42c;
const SOURCE_OFFSET: usize = 0x488;
const DESTINATION_OFFSET: usize = 0x494;

#[cfg(not(target_os = "none"))]
static mut HOST_APPLICATION_MODE_FLAG: u8 = 0;

#[cfg(test)]
static APPLICATION_MODE_TRANSITION_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[inline(always)]
unsafe fn application_mode_flag() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        APPLICATION_MODE_FLAG_ADDRESS
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(HOST_APPLICATION_MODE_FLAG)
    }
}

/// Applies the application mode transition and returns the context result word.
///
/// # Safety
///
/// `context` must be four-byte aligned and point to at least `0x498`
/// readable/writable bytes. The retail routine has no NULL or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn application_mode_transition(context: *mut u8, enabled: u32) -> u32 {
    let flag = unsafe { application_mode_flag() };
    let current = unsafe { ptr::read_volatile(flag) };

    if enabled != 0 {
        if current == 0 {
            let source = unsafe { ptr::read_volatile(context.add(SOURCE_OFFSET).cast::<u32>()) };
            unsafe { ptr::write_volatile(context.add(DESTINATION_OFFSET).cast::<u32>(), source) };
            unsafe { ptr::write_volatile(flag, 1) };
        }
    } else if current != 0 {
        unsafe { ptr::write_volatile(flag, 0) };
    }

    unsafe { ptr::read_volatile(context.add(RESULT_OFFSET).cast::<u32>()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT_WORDS: usize = (DESTINATION_OFFSET + core::mem::size_of::<u32>()) / core::mem::size_of::<u32>();

    unsafe fn set_flag(value: u8) {
        unsafe { ptr::write_volatile(application_mode_flag(), value) };
    }

    unsafe fn flag() -> u8 {
        unsafe { ptr::read_volatile(application_mode_flag()) }
    }

    #[test]
    fn enabling_from_clear_copies_source_and_sets_flag() {
        let _guard = APPLICATION_MODE_TRANSITION_TEST_LOCK.lock();
        let mut context = [0u32; CONTEXT_WORDS];
        let context_bytes = context.as_mut_ptr().cast::<u8>();
        unsafe {
            ptr::write_volatile(context_bytes.add(RESULT_OFFSET).cast::<u32>(), 0x1357_9bdf);
            ptr::write_volatile(context_bytes.add(SOURCE_OFFSET).cast::<u32>(), 0x2468_ace0);
            ptr::write_volatile(context_bytes.add(DESTINATION_OFFSET).cast::<u32>(), 0xfeed_face);
            set_flag(0);
            assert_eq!(application_mode_transition(context_bytes, 7), 0x1357_9bdf);
            assert_eq!(ptr::read_volatile(context_bytes.add(DESTINATION_OFFSET).cast::<u32>()), 0x2468_ace0);
            assert_eq!(flag(), 1);
        }
    }

    #[test]
    fn repeated_enable_preserves_destination() {
        let _guard = APPLICATION_MODE_TRANSITION_TEST_LOCK.lock();
        let mut context = [0u32; CONTEXT_WORDS];
        let context_bytes = context.as_mut_ptr().cast::<u8>();
        unsafe {
            ptr::write_volatile(context_bytes.add(SOURCE_OFFSET).cast::<u32>(), 0x1111_1111);
            ptr::write_volatile(context_bytes.add(DESTINATION_OFFSET).cast::<u32>(), 0x2222_2222);
            set_flag(1);
            application_mode_transition(context_bytes, 1);
            assert_eq!(ptr::read_volatile(context_bytes.add(DESTINATION_OFFSET).cast::<u32>()), 0x2222_2222);
            assert_eq!(flag(), 1);
        }
    }

    #[test]
    fn disabling_clears_only_a_set_flag() {
        let _guard = APPLICATION_MODE_TRANSITION_TEST_LOCK.lock();
        let mut context = [0u32; CONTEXT_WORDS];
        let context_bytes = context.as_mut_ptr().cast::<u8>();
        unsafe {
            ptr::write_volatile(context_bytes.add(RESULT_OFFSET).cast::<u32>(), 0xa5a5_5a5a);
            ptr::write_volatile(context_bytes.add(DESTINATION_OFFSET).cast::<u32>(), 0x1234_5678);
            set_flag(0xff);
            assert_eq!(application_mode_transition(context_bytes, 0), 0xa5a5_5a5a);
            assert_eq!(flag(), 0);
            assert_eq!(ptr::read_volatile(context_bytes.add(DESTINATION_OFFSET).cast::<u32>()), 0x1234_5678);
        }
    }
}
