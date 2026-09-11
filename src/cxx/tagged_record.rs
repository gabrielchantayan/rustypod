//! `tagged_record_init` — original: `FUN_0826fc2c` @ 0x0826fc2c (20 bytes).
//!
//! Raw ARM establishes the true extent as the four instruction words at
//! 0x0826fc2c..0x0826fc3c plus the literal-pool word at 0x0826fc40; the next
//! separately linked function starts at 0x0826fc44. Decoding every ARM B/BL
//! word in `osos.dec` finds exactly 20 direct call sites: all are unconditional
//! plain `bl`, with no predicated forms or plain-B tail calls.
//!
//! # Algorithm
//!
//! Store the incoming payload word at +0x04, install the literal
//! `0x089a5b04` at +0x00, store the low byte of `flag` at +0x08, then return
//! `this` unchanged in r0. There is no NULL or alignment guard.
//!
//! The stored literal does **not** decode as a callable function entry in the
//! static image: it lands at 0x089a5b04, a branch-table case label within a
//! larger body. This initializer never calls through it, so the field remains
//! an opaque 32-bit descriptor and no dispatch seam is invented. Deliberate
//! deviations: none.

/// Literal descriptor the ARM initializer loads from its pool word at
/// 0x0826fc40.
pub const TAGGED_RECORD_DESCRIPTOR: u32 = 0x089a_5b04;

/// A target-width view of the twelve-byte record initialized by
/// [`tagged_record_init`].
#[repr(C)]
pub struct TaggedRecord {
    /// +0x00: opaque descriptor installed by the initializer.
    pub descriptor: u32,
    /// +0x04: incoming payload word.
    pub payload: u32,
    /// +0x08: low byte of the incoming flag register.
    pub flag: u8,
}

/// Initializes a tagged record and returns `this` unchanged.
///
/// # Safety
///
/// `this` must be valid and four-byte aligned for the two word stores and
/// point to at least twelve writable bytes. The original writes every field
/// unconditionally, leaves the three trailing bytes untouched, and discards
/// flag bits 8..31.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_record_init")]
#[inline(never)]
pub unsafe extern "C" fn tagged_record_init(
    this: *mut TaggedRecord,
    payload: u32,
    flag: u32,
) -> *mut TaggedRecord {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).payload), payload);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*this).descriptor),
            TAGGED_RECORD_DESCRIPTOR,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).flag), flag as u8);
    }
    this
}

/// Observed ABI of the unported nested `'liti'` class check at
/// `0x08057bdc`. It returns zero for no match and a nonzero word for a match.
pub type NestedLitiClassCheck = unsafe extern "C" fn(*const u8) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_nested_liti_class_check(target: *const u8) -> u32 {
    let check: NestedLitiClassCheck = unsafe { core::mem::transmute(0x0805_7bdcusize) };
    unsafe { check(target) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_nested_liti_class_check(_target: *const u8) -> u32 {
    panic!("tagged_record_payload_is_liti_class requires core 0x08057bdc")
}

#[cfg(target_os = "none")]
const DEFAULT_NESTED_LITI_CLASS_CHECK: NestedLitiClassCheck = firmware_nested_liti_class_check;
#[cfg(not(target_os = "none"))]
const DEFAULT_NESTED_LITI_CLASS_CHECK: NestedLitiClassCheck = missing_nested_liti_class_check;

/// The unported nested `'liti'` class check. Target builds invoke its retailOS
/// entry; host tests replace this seam to observe the exact payload forwarded.
pub static mut NESTED_LITI_CLASS_CHECK: NestedLitiClassCheck = DEFAULT_NESTED_LITI_CLASS_CHECK;

/// tagged_record_payload_is_liti_class — original: `FUN_0826fc14` @
/// 0x0826fc14 (24 bytes).
///
/// Raw ARM extent is exactly 0x0826fc14..0x0826fc2c: the next separately
/// linked function, `tagged_record_init`, starts at 0x0826fc2c. Decoding
/// every ARM B/BL word in osos.dec finds nine incoming direct calls, all
/// unconditional plain `bl`; there are no predicated BL forms or plain-B tail
/// callers.
///
/// Algorithm: load the target-width payload word at record +0x04, call the
/// unported nested `'liti'` class check at 0x08057bdc with that value, then
/// return strict 0 or 1 according to whether the callee result is zero. The
/// callee itself NULL-guards the payload and follows its +0x08 field to the
/// ported `'liti'` tag predicate; this wrapper deliberately makes no
/// pre-call NULL check. The record and nested-object identities beyond those
/// observed fields are unknown, so no stronger type claim is made.
///
/// Deliberate deviation: the fixed retailOS call is represented by the
/// replaceable `NESTED_LITI_CLASS_CHECK` seam so host tests can observe its
/// argument; target builds default that seam to 0x08057bdc. The original
/// direct `bl` therefore becomes an indirect target-default call.
///
/// # Safety
///
/// `record` must be non-NULL, four-byte aligned, and readable through +0x07.
/// Its payload is a target-width pointer expected by the unported callee.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_record_payload_is_liti_class")]
pub unsafe extern "C" fn tagged_record_payload_is_liti_class(record: *const TaggedRecord) -> u32 {
    let payload = unsafe { core::ptr::addr_of!((*record).payload).read() };
    let check = unsafe {
        core::ptr::addr_of_mut!(NESTED_LITI_CLASS_CHECK).read_volatile()
    };
    u32::from(unsafe { check(payload as usize as *const u8) } != 0)
}


#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    const FIXTURE_LEN: usize = 0x1000;
    const RECORD_OFFSET: usize = 0x100;

    static PAYLOAD_CHECK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static PAYLOAD_CHECK_FIXTURE: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::TAGGED_RECORD_PAYLOAD_LITI_CLASS_CHECK,
            FIXTURE_LEN,
        )
        .map(|pointer| pointer as usize)
    });
    static mut CALLEE_RESULT: u32 = 0;
    static mut FORWARDED_PAYLOAD: usize = 0;

    unsafe extern "C" fn record_nested_liti_class_check(target: *const u8) -> u32 {
        unsafe {
            FORWARDED_PAYLOAD = target as usize;
            CALLEE_RESULT
        }
    }

    struct CheckSeamRestore(NestedLitiClassCheck);

    impl Drop for CheckSeamRestore {
        fn drop(&mut self) {
            unsafe {
                NESTED_LITI_CLASS_CHECK = self.0;
            }
        }
    }

    fn mapped_record(payload: u32) -> Option<*mut TaggedRecord> {
        let base = (*PAYLOAD_CHECK_FIXTURE)? as *mut u8;
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            let record = base.add(RECORD_OFFSET).cast::<TaggedRecord>();
            (*record).descriptor = 0xfeed_face;
            (*record).payload = payload;
            (*record).flag = 0xa5;
            Some(record)
        }
    }

    #[test]
    fn forwards_target_width_payload_and_normalizes_nonzero_result() {
        let _guard = PAYLOAD_CHECK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(record) = mapped_record(0x1234_5678) else {
            assert!(crate::testing::note_missing_u32_fixture("cxx::tagged_record"));
            return;
        };

        unsafe {
            let _restore = CheckSeamRestore(NESTED_LITI_CLASS_CHECK);
            NESTED_LITI_CLASS_CHECK = record_nested_liti_class_check;
            CALLEE_RESULT = 0xfeed_face;
            FORWARDED_PAYLOAD = 0;

            assert_eq!(tagged_record_payload_is_liti_class(record), 1);
            assert_eq!(FORWARDED_PAYLOAD, 0x1234_5678);
        }
    }

    #[test]
    fn null_payload_is_still_forwarded_to_callee() {
        let _guard = PAYLOAD_CHECK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(record) = mapped_record(0) else {
            assert!(crate::testing::note_missing_u32_fixture("cxx::tagged_record"));
            return;
        };

        unsafe {
            let _restore = CheckSeamRestore(NESTED_LITI_CLASS_CHECK);
            NESTED_LITI_CLASS_CHECK = record_nested_liti_class_check;
            CALLEE_RESULT = 0;
            FORWARDED_PAYLOAD = usize::MAX;

            assert_eq!(tagged_record_payload_is_liti_class(record), 0);
            assert_eq!(FORWARDED_PAYLOAD, 0);
        }
    }

    #[test]
    fn installs_descriptor_payload_and_low_flag_byte_in_store_order() {
        let mut words = [0xfeed_faceu32, 0xa5a5_a5a5, 0x1122_3344, 0xdead_beef];
        let record = unsafe { words.as_mut_ptr().add(1).cast::<TaggedRecord>() };

        let returned = unsafe { tagged_record_init(record, 0x7654_3210, 0xabcd_ef89) };

        assert_eq!(returned, record);
        assert_eq!(words, [0xfeed_face, TAGGED_RECORD_DESCRIPTOR, 0x7654_3210, 0xdead_be89]);
        assert_eq!(unsafe { (*record).flag }, 0x89);
        assert_eq!(unsafe { record.cast::<u8>().add(9).read() }, 0xbe);
        assert_eq!(unsafe { record.cast::<u8>().add(10).read() }, 0xad);
        assert_eq!(unsafe { record.cast::<u8>().add(11).read() }, 0xde);
    }

    #[test]
    fn accepts_zero_payload_and_zero_flag() {
        let mut record = TaggedRecord {
            descriptor: 0xffff_ffff,
            payload: 0xffff_ffff,
            flag: 0xff,
        };

        let returned = unsafe { tagged_record_init(&mut record, 0, 0) };

        assert_eq!(returned, &mut record as *mut TaggedRecord);
        assert_eq!(record.descriptor, TAGGED_RECORD_DESCRIPTOR);
        assert_eq!(record.payload, 0);
        assert_eq!(record.flag, 0);
    }
}
