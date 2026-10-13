//! Event-handler child acquisition IRAM boundary.

#[cfg(test)]
extern crate std;

/// `thunk_EXT_FUN_22007aec` @ `0x080380d0`: 8 bytes including its literal,
/// ending at the next veneer at `0x080380d8`. Full-image raw ARM decoding
/// verifies two plain BL callers (0x08167834, 0x081b0e60), zero predicated
/// BL callers, and no outgoing BL instructions.
///
/// The words `e51ff004 22007aec` tail-dispatch the source in r0 to the IRAM
/// mirror of 0x08007aec. That body selects a child from source +0x20,
/// increments the halfword at +0x50 when an inactive child is selected,
/// retires active children, activates the selected child, and returns it.
/// The firmware body remains unported; this entry preserves its exact address
/// and argument/result ABI rather than duplicating its algorithm.
///
/// Deliberate deviation: LLVM emits an indirect C-ABI call/tail-call instead
/// of the ADS literal-load jump. Hosts cannot execute retail ARM code and
/// reject execution outside tests; tests supply the firmware boundary.
///
/// # Safety
/// `source` and its child must satisfy the original firmware body's contract;
/// the IRAM image must have been installed by the 0x080046e0 relocator.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_handler_child_acquire_iram(source: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let acquire: unsafe extern "C" fn(*mut u8) -> *mut u8 =
            core::mem::transmute(0x2200_7aecusize);
        acquire(source)
    }
    #[cfg(all(not(target_os = "none"), test))]
    {
        HOST_ACQUIRE.with(|acquire| acquire.get()(source))
    }
    #[cfg(all(not(target_os = "none"), not(test)))]
    {
        let _ = source;
        panic!("retail IRAM child acquisition is unavailable on hosts")
    }
}

#[cfg(test)]
std::thread_local! {
    static HOST_ACQUIRE: core::cell::Cell<unsafe extern "C" fn(*mut u8) -> *mut u8> =
        core::cell::Cell::new(unavailable);
}

#[cfg(test)]
unsafe extern "C" fn unavailable(_: *mut u8) -> *mut u8 {
    panic!("install a firmware boundary before exercising the veneer")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // The boundary consumes only the final accessible byte. The veneer must
    // not inspect the source as an object or truncate a host pointer to u32.
    unsafe extern "C" fn consume_boundary_byte(source: *mut u8) -> *mut u8 {
        source.write(source.read().wrapping_add(1));
        core::ptr::null_mut()
    }

    #[test]
    fn opaque_source_at_guard_boundary_is_not_read_as_an_object() {
        unsafe extern "C" {
            fn getpagesize() -> i32;
            fn mmap(address: usize, length: usize, protection: i32,
                flags: i32, fd: i32, offset: i64) -> *mut u8;
            fn mprotect(address: *mut u8, length: usize, protection: i32) -> i32;
            fn munmap(address: *mut u8, length: usize) -> i32;
        }
        unsafe {
            let page = getpagesize() as usize;
            let mapping = mmap(0, page * 2, 3, 0x22, -1, 0);
            assert_ne!(mapping as usize, usize::MAX);
            assert_eq!(mprotect(mapping.add(page), page, 0), 0);
            let source = mapping.add(page - 1);
            HOST_ACQUIRE.with(|slot| {
                let previous = slot.replace(consume_boundary_byte);
                for initial in [0, 127, 255] {
                    source.write(initial);
                    assert!(event_handler_child_acquire_iram(source).is_null());
                    assert_eq!(source.read(), initial.wrapping_add(1));
                }
                slot.set(previous);
            });
            assert_eq!(munmap(mapping, page * 2), 0);
        }
    }
}
