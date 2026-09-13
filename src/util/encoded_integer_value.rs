//! `encoded_integer_value` — original: `FUN_080834a4` @ **0x080834a4**
//! (48 bytes, `0x080834a4..0x080834d0`; the independently linked sibling
//! starts at `0x080834d4`). Full-image ARM decoding finds **seven** direct
//! inbound `bl` call sites, all unconditional and none predicated:
//! `0x08087ec0`, `0x08087f28`, `0x080a1b38`, `0x080a1b48`, `0x080a1b54`,
//! `0x080c8b24`, and `0x080c8b30`.
//!
//! The input is an unchecked byte range. A leading `0x1e` is decoded by the
//! retail packed-decimal decoder with scale zero, then sign-extends its
//! Q16.16 integer component. Every other leading byte tail-delegates to the
//! retail compact-token decoder. Target builds call the verified firmware
//! entries directly; host tests replace them with deterministic seams. There
//! are no deliberate behavioral deviations.

/// The input range consumed by [`encoded_integer_value`].
///
/// The retail implementation dereferences `start` without a NULL or range
/// guard. `end` is forwarded exactly to the selected decoder.
#[repr(C)]
pub struct EncodedValueRange {
    pub start: *const u8,
    pub end: *const u8,
}

type CompactTokenValue = unsafe extern "C" fn(*const u8, *const u8) -> u32;
type PackedDecimalValue = unsafe extern "C" fn(*const u8, *const u8, u32) -> u32;

#[cfg(target_arch = "arm")]
unsafe fn compact_token_value(start: *const u8, end: *const u8) -> u32 {
    let decoder: CompactTokenValue = core::mem::transmute(0x080a_1b68usize);
    decoder(start, end)
}

#[cfg(target_arch = "arm")]
unsafe fn packed_decimal_value(start: *const u8, end: *const u8, scale: u32) -> u32 {
    let decoder: PackedDecimalValue = core::mem::transmute(0x0808_7bf8usize);
    decoder(start, end, scale)
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_compact_token_value(_: *const u8, _: *const u8) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_packed_decimal_value(_: *const u8, _: *const u8, _: u32) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
#[derive(Clone, Copy)]
struct EncodedIntegerValueOps {
    compact_token_value: CompactTokenValue,
    packed_decimal_value: PackedDecimalValue,
}

#[cfg(not(target_arch = "arm"))]
static mut ENCODED_INTEGER_VALUE_OPS: EncodedIntegerValueOps = EncodedIntegerValueOps {
    compact_token_value: missing_compact_token_value,
    packed_decimal_value: missing_packed_decimal_value,
};

#[cfg(not(target_arch = "arm"))]
unsafe fn compact_token_value(start: *const u8, end: *const u8) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(ENCODED_INTEGER_VALUE_OPS.compact_token_value)))(start, end)
}

#[cfg(not(target_arch = "arm"))]
unsafe fn packed_decimal_value(start: *const u8, end: *const u8, scale: u32) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(ENCODED_INTEGER_VALUE_OPS.packed_decimal_value)))(start, end, scale)
}

/// Decodes a compact token or the integral portion of a packed decimal.
///
/// # Safety
///
/// `range` must point to a readable [`EncodedValueRange`] whose `start` points
/// to a readable byte. The selected retail decoder owns all further range
/// validity requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.encoded_integer_value")]
#[inline(never)]
pub unsafe extern "C" fn encoded_integer_value(range: *const EncodedValueRange) -> u32 {
    let start = (*range).start;
    let end = (*range).end;

    if start.read() != 0x1e {
        return compact_token_value(start, end);
    }

    ((packed_decimal_value(start, end, 0) as i32) >> 16) as u32
}

#[cfg(test)]
mod tests {
    use super::{compact_token_value, encoded_integer_value, packed_decimal_value, CompactTokenValue, EncodedIntegerValueOps, EncodedValueRange, PackedDecimalValue, ENCODED_INTEGER_VALUE_OPS};
    use core::ptr;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static COMPACT_START: AtomicUsize = AtomicUsize::new(0);
    static COMPACT_END: AtomicUsize = AtomicUsize::new(0);
    static COMPACT_CALLS: AtomicU32 = AtomicU32::new(0);
    static PACKED_START: AtomicUsize = AtomicUsize::new(0);
    static PACKED_END: AtomicUsize = AtomicUsize::new(0);
    static PACKED_SCALE: AtomicU32 = AtomicU32::new(u32::MAX);
    static PACKED_CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn compact_value(start: *const u8, end: *const u8) -> u32 {
        COMPACT_CALLS.fetch_add(1, Ordering::SeqCst);
        COMPACT_START.store(start as usize, Ordering::SeqCst);
        COMPACT_END.store(end as usize, Ordering::SeqCst);
        0xffff_ff94
    }

    unsafe extern "C" fn packed_value(start: *const u8, end: *const u8, scale: u32) -> u32 {
        PACKED_CALLS.fetch_add(1, Ordering::SeqCst);
        PACKED_START.store(start as usize, Ordering::SeqCst);
        PACKED_END.store(end as usize, Ordering::SeqCst);
        PACKED_SCALE.store(scale, Ordering::SeqCst);
        0xfffe_0000
    }

    struct OpsReset(EncodedIntegerValueOps);

    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(ENCODED_INTEGER_VALUE_OPS), self.0) };
        }
    }

    unsafe fn install(compact: CompactTokenValue, packed: PackedDecimalValue) -> OpsReset {
        let old = ptr::read_volatile(ptr::addr_of!(ENCODED_INTEGER_VALUE_OPS));
        ptr::write_volatile(ptr::addr_of_mut!(ENCODED_INTEGER_VALUE_OPS), EncodedIntegerValueOps {
            compact_token_value: compact,
            packed_decimal_value: packed,
        });
        OpsReset(old)
    }

    fn reset_trace() {
        COMPACT_START.store(0, Ordering::SeqCst);
        COMPACT_END.store(0, Ordering::SeqCst);
        COMPACT_CALLS.store(0, Ordering::SeqCst);
        PACKED_START.store(0, Ordering::SeqCst);
        PACKED_END.store(0, Ordering::SeqCst);
        PACKED_SCALE.store(u32::MAX, Ordering::SeqCst);
        PACKED_CALLS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn compact_token_tail_delegates_for_every_non_marker_byte() {
        let _guard = TEST_LOCK.lock();
        let _reset = unsafe { install(compact_value, packed_value) };
        reset_trace();
        let bytes = [0xff, 0x99];
        let range = EncodedValueRange { start: bytes.as_ptr(), end: unsafe { bytes.as_ptr().add(bytes.len()) } };

        assert_eq!(unsafe { encoded_integer_value(&range) }, 0xffff_ff94);
        assert_eq!(COMPACT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(PACKED_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(COMPACT_START.load(Ordering::SeqCst), bytes.as_ptr() as usize);
        assert_eq!(COMPACT_END.load(Ordering::SeqCst), unsafe { bytes.as_ptr().add(bytes.len()) } as usize);
    }

    #[test]
    fn packed_decimal_marker_uses_zero_scale_and_sign_extends_q16() {
        let _guard = TEST_LOCK.lock();
        let _reset = unsafe { install(compact_value, packed_value) };
        reset_trace();
        let bytes = [0x1e, 0x12, 0x3f];
        let range = EncodedValueRange { start: bytes.as_ptr(), end: unsafe { bytes.as_ptr().add(bytes.len()) } };

        assert_eq!(unsafe { encoded_integer_value(&range) }, 0xffff_fffe);
        assert_eq!(PACKED_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(COMPACT_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(PACKED_START.load(Ordering::SeqCst), bytes.as_ptr() as usize);
        assert_eq!(PACKED_END.load(Ordering::SeqCst), unsafe { bytes.as_ptr().add(bytes.len()) } as usize);
        assert_eq!(PACKED_SCALE.load(Ordering::SeqCst), 0);
    }
}
