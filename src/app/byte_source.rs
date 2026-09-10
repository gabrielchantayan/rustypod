//! `byte_source_at` — original: `FUN_082725c0` @ `0x082725c0`
//! (44 bytes).
//!
//! # Verified call sites
//!
//! Raw ARM decoding finds exactly ten direct call sites, all unconditional
//! `bl`; there are no predicated calls or tail branches. The ten callers are
//! `0x08103204`, `0x08117f20`, `0x08118fc8`, `0x08119178`, `0x081198b0`,
//! `0x08119bb4`, `0x0827261c`, `0x0828a3c0`, `0x0828a3dc`, and `0x0828b304`.
//!
//! # Algorithm
//!
//! A `ByteSource` presents one byte from three ordered stores. Its optional
//! override buffer wins only when its byte at `index` is nonzero. Otherwise,
//! the optional fallback buffer supplies the byte; when neither external
//! buffer applies, the embedded five-byte store supplies it. The ARM code
//! uses unchecked byte and word loads, with no bounds, null, or alignment
//! guard beyond its two optional external-buffer pointers.
//!
//! Sources: raw `osos.dec` words at `0x082725c0..0x082725e8` (the next
//! function begins at `0x082725ec`), and
//! `ipod-decomp/decomp/c/026/082725c0_FUN_082725c0.c`.
//!
//! Deviation: none.

/// The 16-byte retail byte-source object.
///
/// On the 32-bit target, `fallback_bytes` and `override_bytes` occupy words
/// `+0x08` and `+0x0c`. The status fields are not read by [`byte_source_at`]
/// but keep the named field layout faithful for callers sharing the object.
#[repr(C)]
pub struct ByteSource {
    /// `+0x00..+0x04`: final fallback when external buffers do not answer.
    pub inline_bytes: [u8; 5],
    /// `+0x05`: state owned by sibling mutators.
    pub status: u8,
    /// `+0x06`: dirty flag owned by sibling mutators.
    pub dirty: u8,
    /// `+0x07`: alignment padding before the two pointer words.
    pub padding: u8,
    /// `+0x08`: optional external fallback bytes.
    pub fallback_bytes: *const u8,
    /// `+0x0c`: optional, nonzero-byte-only override bytes.
    pub override_bytes: *const u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(ByteSource, fallback_bytes)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(ByteSource, override_bytes)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::size_of::<ByteSource>()];

/// Returns byte `index` from the override, fallback, or embedded source.
///
/// # Safety
///
/// `source` must name a readable, word-aligned [`ByteSource`]. Every selected
/// byte store must be readable at `index`; the retail function has no bounds
/// checks. A non-null `override_bytes` is read before either lower-priority
/// store, and a non-null `fallback_bytes` is read before `inline_bytes`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn byte_source_at(source: *const ByteSource, index: usize) -> u8 {
    let override_bytes = unsafe { (*source).override_bytes };
    if !override_bytes.is_null() {
        let byte = unsafe { override_bytes.add(index).read() };
        if byte != 0 {
            return byte;
        }
    }

    let fallback_bytes = unsafe { (*source).fallback_bytes };
    if !fallback_bytes.is_null() {
        return unsafe { fallback_bytes.add(index).read() };
    }

    unsafe { (*source).inline_bytes.as_ptr().add(index).read() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    fn source(inline_bytes: [u8; 5], fallback_bytes: *const u8, override_bytes: *const u8) -> ByteSource {
        ByteSource {
            inline_bytes,
            status: 0xa5,
            dirty: 0x5a,
            padding: 0,
            fallback_bytes,
            override_bytes,
        }
    }

    #[test]
    fn nonzero_override_byte_wins_at_each_index() {
        let inline = [0x10, 0x11, 0x12, 0x13, 0x14];
        let fallback = [0x20, 0x21, 0x22, 0x23, 0x24];
        let override_bytes = [0x30, 0x31, 0x32, 0x33, 0x34];
        let byte_source = source(inline, fallback.as_ptr(), override_bytes.as_ptr());

        for index in 0..inline.len() {
            assert_eq!(unsafe { byte_source_at(&byte_source, index) }, override_bytes[index]);
        }
    }

    #[test]
    fn zero_override_byte_falls_back_to_external_byte_even_when_zero() {
        let inline = [0x10, 0x11, 0x12, 0x13, 0x14];
        let fallback = [0x20, 0, 0x22, 0x23, 0x24];
        let override_bytes = [0x30, 0, 0x32, 0x33, 0x34];
        let byte_source = source(inline, fallback.as_ptr(), override_bytes.as_ptr());

        assert_eq!(unsafe { byte_source_at(&byte_source, 1) }, 0);
    }

    #[test]
    fn null_override_uses_external_fallback() {
        let inline = [0x10, 0x11, 0x12, 0x13, 0x14];
        let fallback = [0x20, 0x21, 0x22, 0x23, 0x24];
        let byte_source = source(inline, fallback.as_ptr(), ptr::null());

        assert_eq!(unsafe { byte_source_at(&byte_source, 3) }, 0x23);
    }

    #[test]
    fn absent_external_buffers_use_embedded_bytes() {
        let inline = [0x10, 0x11, 0x12, 0x13, 0x14];
        let byte_source = source(inline, ptr::null(), ptr::null());

        assert_eq!(unsafe { byte_source_at(&byte_source, 4) }, 0x14);
    }
}
