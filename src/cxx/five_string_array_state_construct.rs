//! Default-construct a five-string state with an embedded observable array.
//! Original: `FUN_08140648` @ 0x08140648, true extent 136 bytes
//! (128 code bytes and literals at 0x081406c8/cc; next function 0x081406d0).
//! Whole-image raw A32 decoding verifies two inbound plain BLs at 0x081dd1c4
//! and 0x081e8710, zero predicated BLs. Body: six plain BLs, zero predicated.
//!
//! Install vtable 0x089857e0; construct three strings at +4/+12/+20;
//! clear four words at +28 and six at +44; construct a string pair at +68;
//! construct the array at +84, replace its vtable with 0x089a4488, set byte
//! +100 to one, and clear words +104..+116. Bytes +101..+103 are untouched.
//! Both callers allocate 0x78 bytes. Return the original object.
//! Deliberate deviations: existing StringObject ports use a static vtable
//! identity and native pointers. repr(C) fields widen on hosts; ARM retains
//! every verified offset. No class identity beyond the observed state is claimed.

use super::four_word_clear::four_word_clear;
use super::observable_array::{observable_array_construct, ObservableArray};
use super::string_object::{string_default_construct, string_object_pair_default_construct,
    StringObject, StringObjectPair};

#[repr(C)]
pub struct FiveStringArrayState {
    pub vtable: u32,
    pub strings: [StringObject; 3],
    pub cleared_record: [u32; 4],
    pub cleared_state: [u32; 6],
    pub pair: StringObjectPair,
    pub array: ObservableArray,
    pub enabled: u8,
    pub untouched: [u8; 3],
    pub cleared_tail: [u32; 4],
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(FiveStringArrayState, strings) == 4);
    assert!(core::mem::offset_of!(FiveStringArrayState, cleared_record) == 28);
    assert!(core::mem::offset_of!(FiveStringArrayState, cleared_state) == 44);
    assert!(core::mem::offset_of!(FiveStringArrayState, pair) == 68);
    assert!(core::mem::offset_of!(FiveStringArrayState, array) == 84);
    assert!(core::mem::offset_of!(FiveStringArrayState, enabled) == 100);
    assert!(core::mem::offset_of!(FiveStringArrayState, cleared_tail) == 104);
    assert!(core::mem::size_of::<FiveStringArrayState>() == 120);
};

/// # Safety
/// `this` must be aligned writable storage for FiveStringArrayState. Existing
/// payloads are overwritten without release, matching the stock constructor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn five_string_array_state_construct(
    this: *mut FiveStringArrayState,
) -> *mut FiveStringArrayState {
    core::ptr::addr_of_mut!((*this).vtable).write(0x0898_57e0);
    let strings = core::ptr::addr_of_mut!((*this).strings).cast::<StringObject>();
    let first = string_default_construct(strings);
    let second = string_default_construct(first.add(1));
    string_default_construct(second.add(1));
    four_word_clear(core::ptr::addr_of_mut!((*this).cleared_record).cast::<u32>());
    let state = core::ptr::addr_of_mut!((*this).cleared_state).cast::<u32>();
    for index in 0..6 {
        state.add(index).write(0);
    }
    string_object_pair_default_construct(core::ptr::addr_of_mut!((*this).pair));
    let array = observable_array_construct(core::ptr::addr_of_mut!((*this).array));
    core::ptr::addr_of_mut!((*array).base.vtable).write_volatile(0x089a_4488);
    core::ptr::addr_of_mut!((*this).enabled).write(1);
    let tail = core::ptr::addr_of_mut!((*this).cleared_tail).cast::<u32>();
    for index in 0..4 {
        tail.add(index).write(0);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::string_object::STRING_OBJECT_VTABLE;

    #[repr(C)]
    struct Fixture {
        before: [u64; 2],
        object: FiveStringArrayState,
        after: [u64; 2],
    }

    #[test]
    fn initializes_dirty_storage_preserving_reserved_bytes_and_neighbors() {
        for fill in [0xa5, 0xff, 0x00] {
            let mut fixture = core::mem::MaybeUninit::<Fixture>::uninit();
            unsafe {
                fixture.as_mut_ptr().cast::<u8>().write_bytes(fill,
                    core::mem::size_of::<Fixture>());
                let object = core::ptr::addr_of_mut!((*fixture.as_mut_ptr()).object);
                assert_eq!(five_string_array_state_construct(object), object);
                let fixture = fixture.assume_init();
                let object = &fixture.object;
                assert_eq!(object.vtable, 0x0898_57e0);
                for string in object.strings.iter().chain([
                    &object.pair.first, &object.pair.second]) {
                    assert_eq!(string.vtable, &STRING_OBJECT_VTABLE as *const _);
                    assert!(string.payload.is_null());
                }
                assert_eq!(object.cleared_record, [0; 4]);
                assert_eq!(object.cleared_state, [0; 6]);
                assert_eq!(object.array.base.vtable, 0x089a_4488);
                assert_eq!(object.array.len, 0);
                assert_eq!(object.array.storage, 0);
                assert_eq!(object.array.observers, 0);
                assert_eq!(object.enabled, 1);
                assert_eq!(object.untouched, [fill; 3]);
                assert_eq!(object.cleared_tail, [0; 4]);
                let guard = u64::from_ne_bytes([fill; 8]);
                assert_eq!(fixture.before, [guard; 2]);
                assert_eq!(fixture.after, [guard; 2]);
            }
        }
    }
}
