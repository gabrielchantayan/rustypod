//! `encoded_fixed_value` — original: `FUN_080d4020` @ **0x080d4020**
//! (56 bytes, `0x080d4020..0x080d4054`; the next sibling begins at
//! `0x080d4058`). Full-image ARM decoding finds **seven** direct inbound
//! `bl` call sites, all unconditional and none predicated:
//! `0x08087ed8`, `0x080bfdac`, `0x080bfdbc`, `0x080bfdcc`, `0x080bfddc`,
//! `0x080bfdec`, and `0x080bfdf8`.
//!
//! The input is an unchecked byte range. A leading `0x1e` delegates to the
//! retail packed-decimal decoder with scale `3`; every other leading token is
//! decoded by the retail compact-token helper, converted to Q16.16, then
//! multiplied by 1000 through the retail Q16.16 product helper. The target
//! keeps those three direct firmware calls; host tests replace them with
//! deterministic seams. There are no deliberate behavioral deviations.

/// Two pointer words consumed by [`encoded_fixed_value`].
///
/// `start` and `end` are the exact `r0` and `r1` arguments forwarded to the
/// retail token decoders. The retail implementation dereferences `start`
/// without a NULL or range guard.
#[repr(C)]
pub struct EncodedValueRange {
    pub start: *const u8,
    pub end: *const u8,
}

type CompactTokenValue = unsafe extern "C" fn(*const u8, *const u8) -> u32;
type FixedProduct = unsafe extern "C" fn(i32, i32) -> i32;
type PackedDecimalValue = unsafe extern "C" fn(*const u8, *const u8, u32) -> u32;

#[cfg(target_arch = "arm")]
unsafe fn compact_token_value(start: *const u8, end: *const u8) -> u32 {
    let decoder: CompactTokenValue = core::mem::transmute(0x080a_1b68usize);
    decoder(start, end)
}

#[cfg(target_arch = "arm")]
unsafe fn fixed_product(left: i32, right: i32) -> i32 {
    let product: FixedProduct = core::mem::transmute(0x0804_d2ccusize);
    product(left, right)
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
unsafe extern "C" fn missing_fixed_product(_: i32, _: i32) -> i32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_packed_decimal_value(_: *const u8, _: *const u8, _: u32) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
#[derive(Clone, Copy)]
struct EncodedFixedValueOps {
    compact_token_value: CompactTokenValue,
    fixed_product: FixedProduct,
    packed_decimal_value: PackedDecimalValue,
}

#[cfg(not(target_arch = "arm"))]
static mut ENCODED_FIXED_VALUE_OPS: EncodedFixedValueOps = EncodedFixedValueOps {
    compact_token_value: missing_compact_token_value,
    fixed_product: missing_fixed_product,
    packed_decimal_value: missing_packed_decimal_value,
};

#[cfg(not(target_arch = "arm"))]
unsafe fn compact_token_value(start: *const u8, end: *const u8) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(ENCODED_FIXED_VALUE_OPS.compact_token_value)))(start, end)
}

#[cfg(not(target_arch = "arm"))]
unsafe fn fixed_product(left: i32, right: i32) -> i32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(ENCODED_FIXED_VALUE_OPS.fixed_product)))(left, right)
}

#[cfg(not(target_arch = "arm"))]
unsafe fn packed_decimal_value(start: *const u8, end: *const u8, scale: u32) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(ENCODED_FIXED_VALUE_OPS.packed_decimal_value)))(start, end, scale)
}

/// Decodes the firmware's compact or packed-decimal fixed-point token.
///
/// # Safety
///
/// `range` must point to a readable [`EncodedValueRange`]; its `start` must
/// point to a readable token. The selected retail decoder owns the remaining
/// range validity requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.encoded_fixed_value")]
#[inline(never)]
pub unsafe extern "C" fn encoded_fixed_value(range: *const EncodedValueRange) -> u32 {
    let start = (*range).start;
    let end = (*range).end;

    if start.read() == 0x1e {
        return packed_decimal_value(start, end, 3);
    }

    let value_q16 = (compact_token_value(start, end) as i32).wrapping_shl(16);
    fixed_product(value_q16, 1000) as u32
}


#[cfg(test)]
mod tests {
    use super::{encoded_fixed_value, CompactTokenValue, EncodedFixedValueOps, EncodedValueRange, FixedProduct, PackedDecimalValue, ENCODED_FIXED_VALUE_OPS};
    use core::ptr;
    use parking_lot::Mutex;
    use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static COMPACT_START: AtomicUsize = AtomicUsize::new(0);
    static COMPACT_END: AtomicUsize = AtomicUsize::new(0);
    static PRODUCT_LEFT: AtomicI32 = AtomicI32::new(0);
    static PRODUCT_RIGHT: AtomicI32 = AtomicI32::new(0);
    static PACKED_START: AtomicUsize = AtomicUsize::new(0);
    static PACKED_END: AtomicUsize = AtomicUsize::new(0);
    static PACKED_SCALE: AtomicU32 = AtomicU32::new(0);
    static COMPACT_CALLS: AtomicU32 = AtomicU32::new(0);
    static PRODUCT_CALLS: AtomicU32 = AtomicU32::new(0);
    static PACKED_CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn compact_value(start: *const u8, end: *const u8) -> u32 {
        COMPACT_CALLS.fetch_add(1, Ordering::SeqCst);
        COMPACT_START.store(start as usize, Ordering::SeqCst);
        COMPACT_END.store(end as usize, Ordering::SeqCst);
        0xffff_fffe
    }

    unsafe extern "C" fn product_value(left: i32, right: i32) -> i32 {
        PRODUCT_CALLS.fetch_add(1, Ordering::SeqCst);
        PRODUCT_LEFT.store(left, Ordering::SeqCst);
        PRODUCT_RIGHT.store(right, Ordering::SeqCst);
        -123_456
    }

    unsafe extern "C" fn packed_value(start: *const u8, end: *const u8, scale: u32) -> u32 {
        PACKED_CALLS.fetch_add(1, Ordering::SeqCst);
        PACKED_START.store(start as usize, Ordering::SeqCst);
        PACKED_END.store(end as usize, Ordering::SeqCst);
        PACKED_SCALE.store(scale, Ordering::SeqCst);
        0xfeed_beef
    }

    struct OpsReset(EncodedFixedValueOps);

    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(ENCODED_FIXED_VALUE_OPS), self.0) };
        }
    }

    unsafe fn install(compact: CompactTokenValue, product: FixedProduct, packed: PackedDecimalValue) -> OpsReset {
        let old = ptr::read_volatile(ptr::addr_of!(ENCODED_FIXED_VALUE_OPS));
        ptr::write_volatile(ptr::addr_of_mut!(ENCODED_FIXED_VALUE_OPS), EncodedFixedValueOps {
            compact_token_value: compact,
            fixed_product: product,
            packed_decimal_value: packed,
        });
        OpsReset(old)
    }

    fn reset_trace() {
        COMPACT_START.store(0, Ordering::SeqCst);
        COMPACT_END.store(0, Ordering::SeqCst);
        PRODUCT_LEFT.store(0, Ordering::SeqCst);
        PRODUCT_RIGHT.store(0, Ordering::SeqCst);
        PACKED_START.store(0, Ordering::SeqCst);
        PACKED_END.store(0, Ordering::SeqCst);
        PACKED_SCALE.store(0, Ordering::SeqCst);
        COMPACT_CALLS.store(0, Ordering::SeqCst);
        PRODUCT_CALLS.store(0, Ordering::SeqCst);
        PACKED_CALLS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn ordinary_token_becomes_q16_then_multiplies_by_1000() {
        let _guard = TEST_LOCK.lock();
        let _reset = unsafe { install(compact_value, product_value, packed_value) };
        reset_trace();
        let bytes = [0x42, 0x99];
        let range = EncodedValueRange { start: bytes.as_ptr(), end: unsafe { bytes.as_ptr().add(bytes.len()) } };

        assert_eq!(unsafe { encoded_fixed_value(&range) }, (-123_456i32) as u32);
        assert_eq!(COMPACT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(PRODUCT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(PACKED_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(COMPACT_START.load(Ordering::SeqCst), bytes.as_ptr() as usize);
        assert_eq!(COMPACT_END.load(Ordering::SeqCst), unsafe { bytes.as_ptr().add(bytes.len()) } as usize);
        assert_eq!(PRODUCT_LEFT.load(Ordering::SeqCst), -0x0002_0000);
        assert_eq!(PRODUCT_RIGHT.load(Ordering::SeqCst), 1000);
    }

    #[test]
    fn packed_decimal_marker_tail_delegates_with_scale_three() {
        let _guard = TEST_LOCK.lock();
        let _reset = unsafe { install(compact_value, product_value, packed_value) };
        reset_trace();
        let bytes = [0x1e, 0x12, 0x3f];
        let range = EncodedValueRange { start: bytes.as_ptr(), end: unsafe { bytes.as_ptr().add(bytes.len()) } };

        assert_eq!(unsafe { encoded_fixed_value(&range) }, 0xfeed_beef);
        assert_eq!(PACKED_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(COMPACT_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(PRODUCT_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(PACKED_START.load(Ordering::SeqCst), bytes.as_ptr() as usize);
        assert_eq!(PACKED_END.load(Ordering::SeqCst), unsafe { bytes.as_ptr().add(bytes.len()) } as usize);
        assert_eq!(PACKED_SCALE.load(Ordering::SeqCst), 3);
    }
}
