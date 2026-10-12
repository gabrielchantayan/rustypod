//! OpenSSL `ASN1_STRING_print` — `FUN_0803a310` @ 0x0803a310.
//! True extent: 188 bytes, 0x0803a310..0x0803a3cc (next function prologue).
//! Raw words contain two plain BLs to BIO_write @ 0x0803da74, no predicated
//! BLs. The two inbound BLs are independently decoded from the full image.
//!
//! Capture the string data pointer, reload its signed length on every loop
//! test, and replace bytes outside ASCII 32..126 (except CR/LF) with dots.
//! Write 80-byte chunks and a nonempty tail; return zero on a NULL string or
//! any nonpositive write result, otherwise one. Positive short writes count
//! as success without retry. Zero/negative lengths succeed without a write.
//!
//! Deliberate deviations: none in behavior. Reuse the verified, unported
//! BIO_write seam from i2a_asn1_object. OwnedBuffer provides the ASN1_STRING
//! prefix (length, type, data) with native pointers for host fixtures and
//! the exact target layout; no uninitialized buffer tail is passed to BIO.

use crate::crypto::bio_ctrl::Bio;
use crate::crypto::i2a_asn1_object::bio_write;
use crate::heap::owned_buffer::OwnedBuffer;
use core::mem::MaybeUninit;

/// Print the counted string as sanitized ASCII through a live BIO.
///
/// # Safety
/// `string` is NULL or an aligned readable OwnedBuffer. Its captured data
/// must remain readable for each positive length observed, including changes
/// made by BIO callbacks. BIO_write's own pointer/callback contract applies.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn asn1_string_print(bio: *mut Bio, string: *const OwnedBuffer) -> i32 {
    if string.is_null() {
        return 0;
    }
    let data = (*string).data;
    let mut buffer = [MaybeUninit::<u8>::uninit(); 80];
    let mut used = 0usize;
    let mut index = 0i32;
    while index < core::ptr::read_volatile(core::ptr::addr_of!((*string).length)) as i32 {
        let byte = data.add(index as usize).read();
        buffer[used].write(if (32..=126).contains(&byte) || byte == 10 || byte == 13 {
            byte
        } else {
            b'.'
        });
        used += 1;
        if used == 80 {
            if bio_write(bio, buffer.as_ptr().cast(), used as i32) <= 0 {
                return 0;
            }
            used = 0;
        }
        index += 1;
    }
    if used != 0 && bio_write(bio, buffer.as_ptr().cast(), used as i32) <= 0 {
        return 0;
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::crypto::i2a_asn1_object::{BioWriteFn, BIO_WRITE};
    use crate::crypto::i2a_asn1_object::tests::SEAM_LOCK;
    use std::vec::Vec;

    struct Sink {
        chunks: Vec<Vec<u8>>,
        fail_at: usize,
        result: i32,
        shrink: *mut OwnedBuffer,
    }

    unsafe extern "C" fn write(bio: *mut Bio, data: *const u8, length: i32) -> i32 {
        let sink = &mut *bio.cast::<Sink>();
        sink.chunks.push(core::slice::from_raw_parts(data, length as usize).to_vec());
        if !sink.shrink.is_null() {
            (*sink.shrink).length = 80;
            (*sink.shrink).data = core::ptr::null_mut();
        }
        if sink.chunks.len() == sink.fail_at { sink.result } else { 1 }
    }

    struct Seam(BioWriteFn);
    impl Drop for Seam {
        fn drop(&mut self) { unsafe { BIO_WRITE = self.0; } }
    }

    #[test]
    fn byte_domain_chunk_boundaries_and_signed_lengths() {
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { let old = BIO_WRITE; BIO_WRITE = write; Seam(old) };
        let mut bytes: Vec<u8> = (0..=255).collect();
        for length in [0i32, -1, i32::MIN, 1, 79, 80, 81, 159, 160, 161, 256] {
            let string = OwnedBuffer { length: length as u32, source: 0, data: bytes.as_mut_ptr(), context: 0 };
            let mut sink = Sink { chunks: Vec::new(), fail_at: usize::MAX, result: 1, shrink: core::ptr::null_mut() };
            assert_eq!(unsafe { asn1_string_print((&mut sink as *mut Sink).cast(), &string) }, 1);
            let expected: Vec<u8> = bytes.iter().take(length.max(0) as usize).map(|&b| {
                if b == b'\n' || b == b'\r' || (b >= b' ' && b <= b'~') { b } else { b'.' }
            }).collect();
            assert_eq!(sink.chunks, expected.chunks(80).map(|c| c.to_vec()).collect::<Vec<_>>());
        }
        assert_eq!(unsafe { asn1_string_print(core::ptr::null_mut(), core::ptr::null()) }, 0);
    }

    #[test]
    fn failure_stops_at_full_chunk_or_tail_and_length_is_reloaded() {
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { let old = BIO_WRITE; BIO_WRITE = write; Seam(old) };
        let mut bytes = [b'A'; 161];
        for result in [0, -7, 1, 79] {
            for fail_at in [1, 2, 3] {
                let string = OwnedBuffer { length: 161, source: 0, data: bytes.as_mut_ptr(), context: 0 };
                let mut sink = Sink { chunks: Vec::new(), fail_at, result, shrink: core::ptr::null_mut() };
                assert_eq!(unsafe { asn1_string_print((&mut sink as *mut Sink).cast(), &string) }, if result > 0 { 1 } else { 0 });
                let count = if result > 0 { 3 } else { fail_at };
                assert_eq!(sink.chunks, [80, 80, 1][..count].iter().map(|&n| std::vec![b'A'; n]).collect::<Vec<_>>());
            }
        }
        let mut string = OwnedBuffer { length: 161, source: 0, data: bytes.as_mut_ptr(), context: 0 };
        let mut sink = Sink { chunks: Vec::new(), fail_at: usize::MAX, result: 1, shrink: &mut string };
        assert_eq!(unsafe { asn1_string_print((&mut sink as *mut Sink).cast(), &string) }, 1);
        assert_eq!(sink.chunks, std::vec![std::vec![b'A'; 80]]);
    }
}
