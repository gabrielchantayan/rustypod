//! CFF DICT fixed-number dispatch (`cffparse.c`).

/// Target-word callback ABI for the retail CFF integer parser at `0x080a1b68`.
pub type CffIntegerParse = unsafe extern "C" fn(*const u8, *const u8) -> u32;
/// Target-word callback ABI for the retail CFF real-number parser at `0x08087bf8`.
pub type CffRealParse = unsafe extern "C" fn(*const u8, *const u8, i32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn cff_parse_integer_host(cursor: *const u8, limit: *const u8) -> u32 {
    let first = cursor.read();
    let remaining = limit.offset_from(cursor);
    match first {
        0x1c if remaining >= 3 => u16::from_be_bytes([cursor.add(1).read(), cursor.add(2).read()]) as i16 as u32,
        0x1d if remaining >= 5 => u32::from_be_bytes([
            cursor.add(1).read(), cursor.add(2).read(), cursor.add(3).read(), cursor.add(4).read(),
        ]),
        32..=246 => first as u32 - 139,
        247..=250 if remaining >= 2 => cursor.add(1).read() as u32 + (first as u32 - 247) * 256 + 108,
        251..=254 if remaining >= 2 => 0xffff_ff94u32 - (cursor.add(1).read() as u32 + (first as u32 - 251) * 256),
        _ => 0,
    }
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_cff_parse_real(_cursor: *const u8, _limit: *const u8, _exponent: i32) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
pub static mut CFF_INTEGER_PARSE: CffIntegerParse = cff_parse_integer_host;
#[cfg(not(target_arch = "arm"))]
pub static mut CFF_REAL_PARSE: CffRealParse = missing_cff_parse_real;

/// cff_parse_fixed — original: `FUN_080903ec` @ `0x080903ec` (48 bytes,
/// `0x080903ec..0x0809041c`; `push {r4-r6,lr}` at `0x0809041c` begins the
/// next function). Five inbound direct `bl` calls are verified by decoding
/// every ARM B/BL word in `osos.dec`; all are unconditional and none predicated.
///
/// A two-word target-width cursor record holds the CFF DICT operand and its
/// exclusive limit. Real operands (byte `30`) transfer to the shared real
/// parser with exponent zero. All other operand encodings pass through the
/// shared integer parser, whose signed result becomes a 16.16 fixed value.
///
/// Deliberate deviation: retail tail-branches to the real parser and directly
/// calls the integer parser. This port uses typed callback seams so host tests
/// can observe both unported callees; ARM builds call their verified retail
/// addresses. The extra return frame is not observable at this ABI boundary.
///
/// # Safety
/// `cursor_record` addresses two target-width words: a valid cursor and its
/// exclusive limit. The pointed range must satisfy the selected retail parser.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_parse_fixed(cursor_record: *const u32) -> u32 {
    let cursor = cursor_record.read() as usize as *const u8;
    let limit = cursor_record.add(1).read() as usize as *const u8;
    if cursor.read() == 30 {
        #[cfg(target_arch = "arm")]
        let parse_real: CffRealParse = core::mem::transmute(0x0808_7bf8usize);
        #[cfg(not(target_arch = "arm"))]
        let parse_real = core::ptr::read_volatile(core::ptr::addr_of!(CFF_REAL_PARSE));
        return parse_real(cursor, limit, 0);
    }
    #[cfg(target_arch = "arm")]
    let parse_integer: CffIntegerParse = core::mem::transmute(0x080a_1b68usize);
    #[cfg(not(target_arch = "arm"))]
    let parse_integer = core::ptr::read_volatile(core::ptr::addr_of!(CFF_INTEGER_PARSE));
    parse_integer(cursor, limit).wrapping_shl(16)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use crate::testing::hints::CFF_PARSE_FIXED;
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static REAL_CURSOR: AtomicUsize = AtomicUsize::new(0);
    static REAL_LIMIT: AtomicUsize = AtomicUsize::new(0);
    static REAL_EXPONENT: AtomicI32 = AtomicI32::new(-1);

    unsafe extern "C" fn record_real(cursor: *const u8, limit: *const u8, exponent: i32) -> u32 {
        REAL_CURSOR.store(cursor as usize, Ordering::SeqCst);
        REAL_LIMIT.store(limit as usize, Ordering::SeqCst);
        REAL_EXPONENT.store(exponent, Ordering::SeqCst);
        0x1357_9bdf
    }

    unsafe fn fixture(bytes: &[u8]) -> Option<(*mut u32, *const u8, *const u8)> {
        let slab = try_map_u32_slab(CFF_PARSE_FIXED, 0x100)?;
        let cursor = slab.add(0x20);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), cursor, bytes.len());
        let record = slab.cast::<u32>();
        record.write(cursor as usize as u32);
        record.add(1).write(cursor.add(bytes.len()) as usize as u32);
        Some((record, cursor, cursor.add(bytes.len())))
    }

    #[test]
    fn dispatches_integer_and_real_operands_at_their_boundaries() {
        let _guard = TEST_LOCK.lock();
        let Some((record, cursor, _)) = (unsafe { fixture(&[0x1c, 0xff, 0xfe]) }) else {
            note_missing_u32_fixture("ft/cff_parse_fixed");
            return;
        };
        assert_eq!(unsafe { cff_parse_fixed(record) }, 0xfffe_0000);

        unsafe { (cursor as *mut u8).write(0x1d); }
        assert_eq!(unsafe { cff_parse_fixed(record) }, 0);

        unsafe {
            (cursor as *mut u8).write(30);
            record.add(1).write(cursor.add(3) as usize as u32);
            CFF_REAL_PARSE = record_real;
        }
        REAL_CURSOR.store(0, Ordering::SeqCst);
        REAL_LIMIT.store(0, Ordering::SeqCst);
        REAL_EXPONENT.store(-1, Ordering::SeqCst);
        assert_eq!(unsafe { cff_parse_fixed(record) }, 0x1357_9bdf);
        assert_eq!(REAL_CURSOR.load(Ordering::SeqCst), cursor as usize);
        assert_eq!(REAL_LIMIT.load(Ordering::SeqCst), unsafe { cursor.add(3) } as usize);
        assert_eq!(REAL_EXPONENT.load(Ordering::SeqCst), 0);
        unsafe { CFF_REAL_PARSE = missing_cff_parse_real; }
    }
}
