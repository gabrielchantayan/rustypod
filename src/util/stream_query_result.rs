//! Stream seek/tell adapters and two-word position results.
//!
//! `stream_seek_position` — `FUN_08266bc0` @ 0x08266bc0, 40 bytes,
//! ending before the next body at 0x08266be8 (`mov ip,r0`). Raw A32
//! decoding verifies one plain BL (fseek @ 0x0802fef0), zero predicated
//! BLs, and a conditional tail branch to ftell @ 0x0802ff38. Two inbound
//! plain BLs occur at 0x083d8ea0 and 0x083d9884; no predicated BLs.
//! Dereference the FILE slot, seek with the supplied offset and origin,
//! reload the slot and tell on success; any nonzero seek result becomes -1.
//! Deliberate deviation: use the existing Rust fseek/ftell ports, rather
//! than Ghidra's erroneous inlining of ftell across the tail branch.
//! LLVM inlines fseek's hook dispatch and ftell's position calculation:
//! match.py reports 34 instructions versus the original ten. The nonzero
//! status exit and success-only slot reload remain intact; no exact match
//! or preserved tail-call shape is claimed.
//!
//! The existing result adapters at 0x083d8e88 and 0x083d986c each have
//! 44-byte bodies and one plain BL, zero predicated BLs. They seek through
//! the FILE slot at stream + 0x30, store the returned position bits, and
//! clear the second result word. Their former raw-address assembly and
//! unrecovered host seam are replaced with the recovered Rust callee.

use crate::stream_file::AdsFile;

/// Seek through a FILE slot, then return its logical position, or -1.
/// The slot must be aligned, readable, and contain a valid FILE pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_seek_position(
    file_slot: *mut *mut AdsFile,
    offset: i32,
    origin: i32,
) -> i32 {
    if crate::stdio_init::fseek(file_slot.read_volatile(), offset, origin) != 0 {
        return -1;
    }
    crate::ftell::ftell(file_slot.read_volatile())
}

/// Seek the stream subobject at offset 48 and form its two-word result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_query_result(
    result: *mut u32,
    stream: *mut u8,
    offset: u32,
    origin: u32,
) {
    result.write_volatile(stream_seek_position(stream.add(0x30).cast(), offset as i32, origin as i32) as u32);
    result.add(1).write_volatile(0);
}

/// Seek to the supplied position and form its two-word result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_query_result_at_position(
    result: *mut u32,
    stream: *mut u8,
    position: u32,
    query_mode: u32,
) {
    result.write_volatile(stream_seek_position(stream.add(0x30).cast(), position as i32, query_mode as i32) as u32);
    result.add(1).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_file::ADS_FILE_ZERO;
    use crate::getc_core::MODE_READ;
    use crate::semihost::tests::{mock_swi, restore_swi};

    #[repr(C)]
    struct StreamObject {
        prefix: [u32; 12],
        file: *mut AdsFile,
    }

    #[test]
    fn real_seek_tell_and_failure_result() {
        let guard = mock_swi(&[0, 0, 0, 0]);
        unsafe {
            let saved = crate::stdio_init::STREAM_SEEK_CORE;
            crate::stdio_init::STREAM_SEEK_CORE = crate::seek_core::fseek_core;
            let mut file = ADS_FILE_ZERO;
            file.stream.flags = MODE_READ;
            file.stream.handle = 7;
            let mut object = StreamObject { prefix: [0; 12], file: &mut file };
            assert_eq!(stream_seek_position(&mut object.file, 123, 0), 123);
            assert_eq!(stream_seek_position(&mut object.file, -23, 1), 100);
            // Negative target and invalid origin must return -1, not core's 2.
            assert_eq!(stream_seek_position(&mut object.file, -1, 0), -1);
            assert_eq!(stream_seek_position(&mut object.file, 0, 99), -1);
            assert_eq!(file.stream.alt_offset, 100);
            crate::stdio_init::STREAM_SEEK_CORE = saved;
        }
        restore_swi();
        drop(guard);
    }

    #[test]
    fn result_adapters_seek_and_clear_tail() {
        let guard = mock_swi(&[0, 0]);
        unsafe {
            let saved = crate::stdio_init::STREAM_SEEK_CORE;
            crate::stdio_init::STREAM_SEEK_CORE = crate::seek_core::fseek_core;
            let mut file = ADS_FILE_ZERO;
            file.stream.flags = MODE_READ;
            file.stream.handle = 7;
            let mut object = StreamObject { prefix: [0; 12], file: &mut file };
            let stream = core::ptr::addr_of_mut!(object).cast();
            let mut result = [u32::MAX; 2];
            stream_query_result(result.as_mut_ptr(), stream, 250, 0);
            assert_eq!(result, [250, 0]);
            result[1] = 99;
            stream_query_result_at_position(result.as_mut_ptr(), stream, (-251i32) as u32, 1);
            assert_eq!(result, [u32::MAX, 0]);
            assert_eq!(file.stream.alt_offset, 250);
            crate::stdio_init::STREAM_SEEK_CORE = saved;
        }
        restore_swi();
        drop(guard);
    }
}
