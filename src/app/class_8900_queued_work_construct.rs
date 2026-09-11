//! `class_8900_queued_work_construct` — original: `FUN_0813b05c` @
//! **0x0813b05c** (**60 bytes**, 0x0813b05c..0x0813b098; the next separately
//! linked function starts `ldr r2, [r0]` at 0x0813b098). **9 direct `bl` call
//! sites**, verified by decoding every ARM B/BL word in `work/firmware/osos.dec`:
//! 0x081ee574, 0x081ee624, 0x081ee97c, 0x081eeb6c, 0x081eec24, 0x081eecc0,
//! 0x081eed68, 0x081eee44, and 0x081eef24. All nine are unconditional; there
//! are no predicated calls, direct tail branches, or aligned data words targeting
//! this entry.
//!
//! Constructs the 32-byte work record enqueued by `Class8900WorkQueue`: copies
//! the caller's context pointer, default-constructs the primary and secondary
//! `StringObject`s, installs the `0xff` state sentinel and zero flags/options,
//! then clears the FIFO link and trailing word. The byte at +0x0f is deliberately
//! untouched. This is the common record construction path before callers fill
//! command-specific fields and enqueue it.
//!
//! Deliberate deviations: none. The two nested default constructions call the
//! already ported `string_default_construct` directly; no new dispatch seam is
//! introduced.

use core::ffi::c_void;

use crate::app::class_8900_work_queue::Class8900QueuedWork;
use crate::cxx::string_object::string_default_construct;

/// class_8900_queued_work_construct — original: `FUN_0813b05c` @ 0x0813b05c
/// (60 bytes; 9 unconditional direct `bl` callers, binary-verified above).
///
/// Initializes a queued-work record in the same write order as retailOS and
/// returns `this`. Neither input is NULL-checked, matching the original.
///
/// # Safety
///
/// `this` must address writable storage for a complete [`Class8900QueuedWork`].
/// `request_context` is copied but not dereferenced.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_queued_work_construct(
    this: *mut Class8900QueuedWork,
    request_context: *mut c_void,
) -> *mut Class8900QueuedWork {
    (*this).request_context = request_context;
    string_default_construct(core::ptr::addr_of_mut!((*this).primary_name));
    (*this).state = u8::MAX;
    (*this).flags = 0;
    (*this).option = 0;
    string_default_construct(core::ptr::addr_of_mut!((*this).secondary_name));
    (*this).next = core::ptr::null_mut();
    (*this).trailing = 0;
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{StringObject, StringObjectVtable, STRING_OBJECT_VTABLE};

    fn garbage_work() -> Class8900QueuedWork {
        Class8900QueuedWork {
            request_context: 0x1111_2222usize as *mut c_void,
            primary_name: StringObject {
                vtable: 0x3333_4444usize as *const StringObjectVtable,
                payload: 0x5555_6666usize as *mut u8,
            },
            state: 0,
            flags: 0x7e,
            option: 0x31,
            reserved: 0xa5,
            secondary_name: StringObject {
                vtable: 0x7777_8888usize as *const StringObjectVtable,
                payload: 0x9999_aaaausize as *mut u8,
            },
            next: 0xbbbb_ccccusize as *mut Class8900QueuedWork,
            trailing: u32::MAX,
        }
    }

    #[test]
    fn initializes_both_strings_and_all_owned_record_fields() {
        let mut work = garbage_work();
        let request_context = 0xdead_beefusize as *mut c_void;

        let returned = unsafe { class_8900_queued_work_construct(&mut work, request_context) };

        assert!(core::ptr::eq(returned, &mut work));
        assert_eq!(work.request_context, request_context, "context is copied verbatim");
        assert!(core::ptr::eq(work.primary_name.vtable, &STRING_OBJECT_VTABLE));
        assert!(work.primary_name.payload.is_null());
        assert_eq!(work.state, 0xff, "the sentinel is unsigned 0xff");
        assert_eq!(work.flags, 0);
        assert_eq!(work.option, 0);
        assert_eq!(work.reserved, 0xa5, "+0x0f is not written");
        assert!(core::ptr::eq(work.secondary_name.vtable, &STRING_OBJECT_VTABLE));
        assert!(work.secondary_name.payload.is_null());
        assert!(work.next.is_null());
        assert_eq!(work.trailing, 0);
    }

    #[test]
    fn repeated_construction_replaces_owned_values_but_preserves_padding() {
        let mut work = garbage_work();
        unsafe { class_8900_queued_work_construct(&mut work, core::ptr::null_mut()) };
        work.state = 3;
        work.flags = 4;
        work.option = 5;
        work.reserved = 0x5a;
        work.next = 0xfeed_faceusize as *mut Class8900QueuedWork;
        work.trailing = 0x1234_5678;

        unsafe { class_8900_queued_work_construct(&mut work, 0x88usize as *mut c_void) };

        assert_eq!(work.request_context, 0x88usize as *mut c_void);
        assert_eq!(work.state, 0xff);
        assert_eq!(work.flags, 0);
        assert_eq!(work.option, 0);
        assert_eq!(work.reserved, 0x5a);
        assert!(work.next.is_null());
        assert_eq!(work.trailing, 0);
    }
}
