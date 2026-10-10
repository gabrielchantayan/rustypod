//! CFF DICT fixed-number dispatch (`cffparse.c`).

use crate::ft::cff_parse_integer::cff_parse_integer;
/// Target-word callback ABI for the retail CFF real-number parser at `0x08087bf8`.
pub type CffRealParse = unsafe extern "C" fn(*const u8, *const u8, i32) -> u32;


#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_cff_parse_real(_cursor: *const u8, _limit: *const u8, _exponent: i32) -> u32 {
    0
}

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
/// Deliberate deviation: retail tail-branches to the real parser; this port
/// uses a typed callback seam for that unported callee on hosts and its
/// verified retail address on ARM. The integer path calls the Rust port.
/// The extra return frame is not observable at this ABI boundary.
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
    cff_parse_integer(cursor, limit).wrapping_shl(16)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use crate::testing::hints::CFF_PARSE_FIXED;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

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
    fn signed_integer_operands_become_q16_and_truncated_operands_return_zero() {
        let _guard = TEST_LOCK.lock();
        let Some((record, cursor, _)) = (unsafe { fixture(&[0x1c, 0xff, 0xfe]) }) else {
            note_missing_u32_fixture("ft/cff_parse_fixed");
            return;
        };
        assert_eq!(unsafe { cff_parse_fixed(record) }, 0xfffe_0000);

        unsafe { (cursor as *mut u8).write(0x1d); }
        assert_eq!(unsafe { cff_parse_fixed(record) }, 0);

    }
}
