//! Width-selected scalar buffer fill.

/// Fill elements — retailOS `FUN_08106a04` at **0x08106a04**.
/// True extent: **136 bytes**, [0x08106a04, 0x08106a8c), ending at BX LR
/// before the next function's PUSH. Raw A32 words contain zero plain or
/// predicated outbound BLs; two plain inbound BLs (0x08106584, 0x081065b0)
/// and zero predicated inbound BLs target this entry.
///
/// Ignore the caller's context. For widths 1, 2, or 4, write the low bits of
/// value to count consecutive elements. A null destination, unsupported
/// width, or signed count <= 0 performs no writes. The caller uses this for
/// individual rows and contiguous tails of a larger accelerated fill.
///
/// Deliberate deviations: volatile typed stores preserve scalar store widths
/// and prevent LLVM from replacing the byte loop with a libc builtin. Rust
/// uses separate typed loops instead of ARM's predicated stores. No defined
/// return value is exposed: callers discard r0, which the original reuses
/// as its loop counter.
///
/// # Safety
/// For a supported width and positive count, a non-null destination must
/// hold count writable elements aligned to that width.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fill_elements(
    _context: *mut core::ffi::c_void,
    destination: *mut u8,
    value: u32,
    element_width: i32,
    count: i32,
) {
    if destination.is_null() || count <= 0 {
        return;
    }
    match element_width {
        1 => {
            for index in 0..count as usize {
                destination.add(index).write_volatile(value as u8);
            }
        }
        2 => {
            let destination = destination.cast::<u16>();
            for index in 0..count as usize {
                destination.add(index).write_volatile(value as u16);
            }
        }
        4 => {
            let destination = destination.cast::<u32>();
            for index in 0..count as usize {
                destination.add(index).write_volatile(value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::fill_elements;

    #[test]
    fn widths_truncation_counts_and_boundaries() {
        for width in [1usize, 2, 4] {
            for offset in (0..8).filter(|offset| offset % width == 0) {
                for count in 0..=64usize {
                    for value in [0, 0x1234_5678, u32::MAX, 0x8000_0000] {
                        let mut storage = [0xcccc_ccccu32; 68];
                        let destination = storage.as_mut_ptr().cast::<u8>();
                        unsafe {
                            fill_elements(core::ptr::null_mut(), destination.add(offset),
                                value, width as i32, count as i32);
                        }
                        let actual = unsafe {
                            core::slice::from_raw_parts(destination, storage.len() * 4)
                        };
                        let mut expected = [0xccu8; 272];
                        for index in 0..count {
                            let start = offset + index * width;
                            expected[start..start + width]
                                .copy_from_slice(&value.to_le_bytes()[..width]);
                        }
                        assert_eq!(actual, expected);
                    }
                }
            }
        }
    }

    #[test]
    fn null_unsupported_and_nonpositive_are_noops() {
        for width in [i32::MIN, -1, 0, 1, 2, 3, 4, 8, i32::MAX] {
            unsafe {
                fill_elements(core::ptr::null_mut(), core::ptr::null_mut(),
                    u32::MAX, width, i32::MAX);
            }
            for count in [i32::MIN, -1, 0, 1, 7] {
                if count > 0 && [1, 2, 4].contains(&width) {
                    continue;
                }
                let mut storage = [0x1234_5678u32; 8];
                unsafe {
                    fill_elements(1usize as *mut core::ffi::c_void,
                        storage.as_mut_ptr().cast(), u32::MAX, width, count);
                }
                assert_eq!(storage, [0x1234_5678; 8]);
            }
        }
    }
}
