//! cstr_copy — original: `FUN_0827668c` @ 0x0827668c (20 bytes).
//!
//! Raw `osos.dec` disassembly confirms five ARM instructions from 0x0827668c
//! through 0x0827669c; the separately linked `utf8_copy_codepoints` starts
//! at 0x082766a0. Decoding every ARM B/BL immediate in the firmware finds
//! seven direct inbound `bl` references, all plain unconditional calls at
//! 0x08111d80, 0x08115498, 0x081155a8, 0x08115630, 0x081157ec, 0x081701b0,
//! and 0x0827e154; there are no predicated BL callers.
//!
//! Algorithm: load one byte from the advancing source cursor, compare it to
//! zero, store it through the advancing destination cursor, and repeat until
//! the copied byte is NUL. The ARM body leaves r0 as one byte past the copied
//! terminator, but no caller consumes it and the recovered ABI is `void`.
//! Deliberate deviation: volatile accesses keep this tiny routine as direct
//! byte loads/stores instead of allowing LLVM to replace it with a libc
//! builtin; for valid ordinary memory they preserve the firmware behavior.

/// Copies a NUL-terminated byte string, including its NUL terminator.
///
/// # Safety
/// `src` must be readable and `dst` writable through the source terminator.
/// The destination must not overlap unread source bytes; in particular, an
/// overlapping destination above the source can overwrite the terminator and
/// make the firmware loop run past the original string. Neither pointer has a
/// NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cstr_copy")]
#[inline(never)]
pub unsafe extern "C" fn cstr_copy(mut dst: *mut u8, mut src: *const u8) {
    loop {
        let byte = core::ptr::read_volatile(src);
        src = src.add(1);
        core::ptr::write_volatile(dst, byte);
        dst = dst.add(1);
        if byte == 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn copies_terminator_at_all_byte_alignments_and_lengths() {
        for source_offset in 0..4 {
            for destination_offset in 0..4 {
                for len in 0..=64 {
                    let mut source = vec![0xa5; source_offset + len + 5];
                    for (index, byte) in source[source_offset..source_offset + len]
                        .iter_mut()
                        .enumerate()
                    {
                        *byte = (index as u8).wrapping_add(1);
                    }
                    source[source_offset + len] = 0;

                    let mut destination = vec![0xcc; destination_offset + len + 5];
                    unsafe {
                        cstr_copy(
                            destination.as_mut_ptr().add(destination_offset),
                            source.as_ptr().add(source_offset),
                        );
                    }

                    assert_eq!(
                        &destination[destination_offset..destination_offset + len + 1],
                        &source[source_offset..source_offset + len + 1],
                        "source offset {source_offset}, destination offset {destination_offset}, length {len}",
                    );
                    assert_eq!(destination[destination_offset + len + 1], 0xcc);
                }
            }
        }
    }

    #[test]
    fn permits_forward_copy_when_destination_precedes_source() {
        let mut buffer = [0xcc, 0xcc, 0xcc, 0xcc, b'a', b'b', b'c', 0, 0xcc];

        unsafe {
            cstr_copy(buffer.as_mut_ptr(), buffer.as_ptr().add(4));
        }

        assert_eq!(buffer, [b'a', b'b', b'c', 0, b'a', b'b', b'c', 0, 0xcc]);
    }
}
