//! Path component splitting with the retail delimiter configuration.

use core::ptr;

/// Resident byte locations consulted as path-component delimiters.
///
/// The decrypted image initially contains `b't'`, `b'u'`, and `b'v'` at these
/// locations. The raw body rereads these locations for each tested input byte,
/// so they remain fixed-address mutable state rather than invented constants.
const COMPONENT_DELIMITER_ADDRESSES: [*const u8; 3] = [
    0x0890_59b7 as *const u8,
    0x0890_59b8 as *const u8,
    0x0890_59b9 as *const u8,
];

/// Resident word incremented by the numeric value of the third argument.
const PATH_SPLIT_ACCUMULATOR_ADDRESS: *mut u32 = 0x08a0_a748 as *mut u32;

#[cfg(not(target_os = "none"))]
static mut HOST_COMPONENT_DELIMITERS: [u8; 3] = [b't', b'u', b'v'];
#[cfg(not(target_os = "none"))]
static mut HOST_PATH_SPLIT_ACCUMULATOR: u32 = 0xf347_b05c;

#[inline(always)]
unsafe fn delimiter_at(index: usize) -> u8 {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(COMPONENT_DELIMITER_ADDRESSES[index])
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(HOST_COMPONENT_DELIMITERS[index]))
    }
}

#[inline(always)]
unsafe fn is_component_delimiter(byte: u8) -> bool {
    byte == delimiter_at(0) || byte == delimiter_at(1) || byte == delimiter_at(2)
}

#[inline(always)]
unsafe fn add_accumulator_contribution(contribution: *mut u8) {
    #[cfg(target_os = "none")]
    let accumulator = PATH_SPLIT_ACCUMULATOR_ADDRESS;
    #[cfg(not(target_os = "none"))]
    let accumulator = ptr::addr_of_mut!(HOST_PATH_SPLIT_ACCUMULATOR);

    let current = ptr::read_volatile(accumulator);
    ptr::write_volatile(
        accumulator,
        current.wrapping_add(contribution as usize as u32),
    );
}

/// split_path_at_last_delimiter — retailOS `FUN_082e37d4` at `0x082e37d4`
/// (224 bytes: a 208-byte code body plus its 16-byte literal pool; 7 direct
/// `bl` call sites, verified by decoding every ARM B/BL word in `osos.dec`:
/// all seven are unconditional plain `bl`, with no predicated calls or tail
/// branches).
///
/// Adds the numeric value of `accumulator_contribution` to the resident word
/// at `0x08a0a748`, then scans `path` for bytes matching any of the three
/// mutable delimiter bytes at `0x089059b7..=0x089059b9`. It copies the prefix
/// ending after the last match to `prefix_out` and the remaining tail to
/// `component_out`; when there are two or more matches, it excludes the final
/// delimiter from the prefix. Both outputs are always NUL-terminated and the
/// function returns 1. The raw body has no NULL guards: all three string
/// pointers must be valid writable/readable NUL-terminated buffers. No
/// deliberate deviations; host builds mirror the decrypted image's initial
/// mutable delimiter bytes and accumulator solely to make this fixed-address
/// state observable in tests.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn split_path_at_last_delimiter(
    prefix_out: *mut u8,
    component_out: *mut u8,
    accumulator_contribution: *mut u8,
    path: *const u8,
) -> u32 {
    add_accumulator_contribution(accumulator_contribution);

    let mut delimiter_count = 0usize;
    let mut last_after_delimiter = 0usize;
    let mut index = 0usize;
    loop {
        let byte = path.add(index).read();
        if byte == 0 {
            break;
        }

        if is_component_delimiter(byte) {
            last_after_delimiter = index + 1;
            if is_component_delimiter(byte) {
                delimiter_count += 1;
            }
        }
        index += 1;
    }

    let prefix_len = last_after_delimiter - usize::from(delimiter_count > 1);
    for index in 0..prefix_len {
        prefix_out.add(index).write(path.add(index).read());
    }

    let mut source = path.add(last_after_delimiter);
    let mut destination = component_out;
    loop {
        let byte = source.read();
        if byte == 0 {
            break;
        }
        destination.write(byte);
        source = source.add(1);
        destination = destination.add(1);
    }

    destination.write(0);
    prefix_out.add(prefix_len).write(0);
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static PATH_COMPONENT_SPLIT_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe fn accumulator() -> u32 {
        ptr::read_volatile(ptr::addr_of!(HOST_PATH_SPLIT_ACCUMULATOR))
    }

    unsafe fn reset_accumulator() {
        ptr::write_volatile(ptr::addr_of_mut!(HOST_PATH_SPLIT_ACCUMULATOR), 0xf347_b05c);
    }

    unsafe fn split(path: &[u8]) -> ([u8; 32], [u8; 32]) {
        assert_eq!(path.last(), Some(&0));
        let mut prefix = [0xa5; 32];
        let mut component = [0xa5; 32];
        let mut contribution = 0u8;
        assert_eq!(
            split_path_at_last_delimiter(
                prefix.as_mut_ptr(),
                component.as_mut_ptr(),
                &mut contribution,
                path.as_ptr(),
            ),
            1,
        );
        (prefix, component)
    }

    #[test]
    fn no_delimiter_leaves_prefix_empty_and_copies_the_whole_path() {
        let _guard = PATH_COMPONENT_SPLIT_TEST_LOCK.lock();
        unsafe { reset_accumulator() };
        let (prefix, component) = unsafe { split(b"plain\0") };
        assert_eq!(&prefix[..1], b"\0");
        assert_eq!(&component[..6], b"plain\0");
    }

    #[test]
    fn a_single_delimiter_remains_at_the_end_of_the_prefix() {
        let _guard = PATH_COMPONENT_SPLIT_TEST_LOCK.lock();
        unsafe { reset_accumulator() };
        let (prefix, component) = unsafe { split(b"abucd\0") };
        assert_eq!(&prefix[..4], b"abu\0");
        assert_eq!(&component[..3], b"cd\0");
    }

    #[test]
    fn repeated_delimiters_remove_only_the_last_one_from_the_prefix() {
        let _guard = PATH_COMPONENT_SPLIT_TEST_LOCK.lock();
        unsafe { reset_accumulator() };
        let (prefix, component) = unsafe { split(b"abucvd\0") };
        assert_eq!(&prefix[..5], b"abuc\0");
        assert_eq!(&component[..2], b"d\0");
    }

    #[test]
    fn delimiter_run_and_empty_tail_are_nul_terminated() {
        let _guard = PATH_COMPONENT_SPLIT_TEST_LOCK.lock();
        unsafe { reset_accumulator() };
        let (prefix, component) = unsafe { split(b"tuv\0") };
        assert_eq!(&prefix[..3], b"tu\0");
        assert_eq!(&component[..1], b"\0");
    }

    #[test]
    fn accumulator_receives_the_third_argument_address_on_each_call() {
        let _guard = PATH_COMPONENT_SPLIT_TEST_LOCK.lock();
        unsafe { reset_accumulator() };
        let before = unsafe { accumulator() };
        let mut first_contribution = 0u8;
        let mut second_contribution = 0u8;
        let mut prefix = [0u8; 8];
        let mut component = [0u8; 8];

        unsafe {
            split_path_at_last_delimiter(
                prefix.as_mut_ptr(),
                component.as_mut_ptr(),
                &mut first_contribution,
                b"\0".as_ptr(),
            );
        }
        let after_first = unsafe { accumulator() };
        assert_eq!(
            after_first,
            before.wrapping_add(&mut first_contribution as *mut u8 as usize as u32),
        );

        unsafe {
            split_path_at_last_delimiter(
                prefix.as_mut_ptr(),
                component.as_mut_ptr(),
                &mut second_contribution,
                b"\0".as_ptr(),
            );
        }
        assert_eq!(
            unsafe { accumulator() },
            after_first.wrapping_add(&mut second_contribution as *mut u8 as usize as u32),
        );
    }
}
