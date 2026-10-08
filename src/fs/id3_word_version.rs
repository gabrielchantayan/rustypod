//! ID3-prefixed word version reader, `FUN_08120bdc` @ `0x08120bdc`.
//!
//! True extent: 116 bytes, through the literal at 0x08120c4c; next real
//! function starts at 0x08120c50. Raw decoding verifies two unconditional
//! inbound BLs (0x08167304, 0x0818db98), no predicated inbound BLs, zero
//! outbound plain/predicated BLs, and two register BLXs.
//! Invoke virtual slot +0x14 with the supplied offset, zero high word and
//! zero stack argument. On zero status, invoke slot +0x10 to read four bytes
//! with flag 1. Accept only words 0x49443300..=0x494433fe (the ID3 prefix);
//! return the low byte, otherwise 255. The receiver/context in r0 is unused.
//! Virtual identities are unresolved: preserve dispatch and all ABI words,
//! including the first method's own address in r1. Deliberate deviations:
//! repr(C) pointer fields widen on hosts while retaining target slot indices;
//! a wrapping subtraction expresses the original addition of 0xb6bbcd00.

#[repr(C)]
pub struct Id3WordSource {
    pub vtable: *const Id3WordSourceVtable,
}

pub type PositionMethod = unsafe extern "C" fn(*mut Id3WordSource, usize, u32, u32, u32) -> u32;
pub type ReadWordMethod = unsafe extern "C" fn(*mut Id3WordSource, *mut u32, u32, u32) -> u32;

#[repr(C)]
pub struct Id3WordSourceVtable {
    pub reserved: [usize; 4],
    pub read_word: ReadWordMethod,
    pub position: PositionMethod,
}

/// Source and both virtual entries must be valid. A successful four-byte
/// read must initialize the output word; the virtual methods obey the stock ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn id3_word_version(
    _context: *mut u8, source: *mut Id3WordSource, offset: u32,
) -> u32 {
    let position = (*(*source).vtable).position;
    if position(source, position as usize, offset, 0, 0) != 0 {
        return 255;
    }
    let mut word = core::mem::MaybeUninit::<u32>::uninit();
    let read_word = (*(*source).vtable).read_word;
    if read_word(source, word.as_mut_ptr(), 4, 1) != 4 {
        return 255;
    }
    let word = word.assume_init();
    if word.wrapping_sub(0x4944_3300) < 255 { word & 255 } else { 255 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        source: Id3WordSource,
        position_status: u32,
        read_count: u32,
        word: u32,
        observed_offset: u32,
        reads: u32,
    }

    unsafe extern "C" fn position(source: *mut Id3WordSource, method: usize, offset: u32, high: u32, origin: u32) -> u32 {
        assert_eq!(method, position as *const () as usize);
        assert_eq!((high, origin), (0, 0));
        let fixture = &mut *source.cast::<Fixture>();
        fixture.observed_offset = offset;
        fixture.position_status
    }

    unsafe extern "C" fn read_word(source: *mut Id3WordSource, output: *mut u32, size: u32, flag: u32) -> u32 {
        assert_eq!((size, flag), (4, 1));
        let fixture = &mut *source.cast::<Fixture>();
        fixture.reads += 1;
        if fixture.read_count == 4 { output.write(fixture.word); }
        fixture.read_count
    }

    fn run(status: u32, count: u32, word: u32) -> (u32, u32) {
        let vtable = Id3WordSourceVtable { reserved: [0; 4], read_word, position };
        let mut fixture = Fixture {
            source: Id3WordSource { vtable: &vtable }, position_status: status,
            read_count: count, word, observed_offset: 0, reads: 0,
        };
        let result = unsafe { id3_word_version(core::ptr::null_mut(), &mut fixture.source, u32::MAX) };
        assert_eq!(fixture.observed_offset, u32::MAX);
        (result, fixture.reads)
    }

    #[test]
    fn accepts_every_non_sentinel_version_and_rejects_prefix_boundaries() {
        for version in 0..255 {
            assert_eq!(run(0, 4, 0x4944_3300 + version), (version, 1));
        }
        for word in [0, u32::MAX, 0x4944_32ff, 0x4944_33ff, 0x4944_3400, 0x0033_4449] {
            assert_eq!(run(0, 4, word), (255, 1));
        }
    }

    #[test]
    fn positioning_failure_skips_read_and_nonexact_reads_fail() {
        for status in [1, 4, u32::MAX] {
            assert_eq!(run(status, 4, 0x4944_3302), (255, 0));
        }
        for count in [0, 1, 2, 3, 5, u32::MAX] {
            assert_eq!(run(0, count, 0x4944_3302), (255, 1));
        }
    }
}
