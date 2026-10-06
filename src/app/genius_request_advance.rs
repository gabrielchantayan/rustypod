//! Advances a Genius request by attaching its next alternate-ID descriptor.
//!
//! Original: FUN_0816ee74 @ 0x0816ee74, 136 bytes through the literal
//! 0x0816eef8; next function starts at 0x0816eefc. Whole-image raw ARM
//! decoding finds two inbound plain BLs (0x0816eca0, 0x081de6a0), no
//! predicated callers. Body: three plain BLs and one BLNE.
//!
//! Completed requests return one without advancing. Otherwise obtain the next
//! 64-bit identifier from request+0x34; zero returns zero. A nonzero identifier
//! is looked up by alternate ID in global manager+0x30 -> service+0xf60.
//! A found descriptor is attached to request+0x18 with NULL context; missing
//! descriptors and attachment failure still return one. No target deviations.
//! The unported NULL-guarded iterator wrapper at 0x082cacfc tail-branches to
//! 0x08269e48; this observed boundary does not claim a deeper callee identity.

use core::ptr;
use crate::app::genius_request_selection_is_complete::genius_request_selection_is_complete;
use crate::app::descriptor_attachment::attach_matching_descriptor;
use crate::ui::tdat_node_find::ui_tdat_find_node_by_alt_id;

pub type GeniusNextIdentifier = unsafe extern "C" fn(*mut u8) -> u64;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_next_identifier(iterator: *mut u8) -> u64 {
    let next: GeniusNextIdentifier = core::mem::transmute(0x082c_acfcusize);
    next(iterator)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_next_identifier(_iterator: *mut u8) -> u64 {
    panic!("Genius next identifier requires retailOS or installed host operation")
}

/// Unported iterator boundary; all other calls use existing Rust ports.
pub static mut GENIUS_NEXT_IDENTIFIER: GeniusNextIdentifier = retail_next_identifier;

#[inline(always)]
fn advance_identifier(next: impl FnOnce() -> u64, lookup: impl FnOnce(u64) -> u32,
                      attach: impl FnOnce(u32)) -> u32 {
    let identifier = next();
    if identifier == 0 {
        return 0;
    }
    let descriptor = lookup(identifier);
    if descriptor != 0 {
        attach(descriptor);
    }
    1
}

/// # Safety
/// Request fields and the global manager chain must satisfy the ready predicate,
/// iterator, tdat lookup, and descriptor attachment contracts. Links are u32.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn genius_request_advance(request: *mut u8) -> u32 {
    if genius_request_selection_is_complete(request) != 0 {
        return 1;
    }
    advance_identifier(
        || {
            let next = ptr::read_volatile(ptr::addr_of!(GENIUS_NEXT_IDENTIFIER));
            next(request.add(0x34).cast::<u32>().read() as usize as *mut u8)
        },
        |identifier| {
            let manager = (0x089c_a674usize as *const u32).read() as usize as *const u32;
            let service = manager.add(0x30 / 4).read() as usize as *const u32;
            let element = service.add(0xf60 / 4).read() as usize as *const u8;
            ui_tdat_find_node_by_alt_id(element, identifier as u32, (identifier >> 32) as u32)
        },
        |descriptor| {
            let owner = request.add(0x18).cast::<u32>().read() as usize as *mut u32;
            attach_matching_descriptor(owner, descriptor as usize as *mut u32, ptr::null_mut());
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_request_with_null_iterator_exercises_exported_path() {
        unsafe extern "C" fn exhausted(iterator: *mut u8) -> u64 {
            assert!(iterator.is_null());
            0
        }
        let mut request = [0u32; 14];
        unsafe {
            let saved = ptr::read_volatile(ptr::addr_of!(GENIUS_NEXT_IDENTIFIER));
            ptr::write_volatile(ptr::addr_of_mut!(GENIUS_NEXT_IDENTIFIER), exhausted);
            let result = genius_request_advance(request.as_mut_ptr().cast());
            ptr::write_volatile(ptr::addr_of_mut!(GENIUS_NEXT_IDENTIFIER), saved);
            assert_eq!(result, 0);
        }
    }

    #[test]
    fn exhausted_iterator_does_not_lookup_or_attach() {
        assert_eq!(advance_identifier(|| 0, |_| panic!("lookup after exhaustion"),
                                     |_| panic!("attachment after exhaustion")), 0);
    }

    #[test]
    fn either_identifier_half_is_sufficient() {
        for identifier in [1, 1u64 << 32, u64::MAX] {
            let attached = core::cell::Cell::new(0);
            assert_eq!(advance_identifier(|| identifier, |id| {
                assert_eq!(id, identifier);
                0x1234
            }, |descriptor| attached.set(descriptor)), 1);
            assert_eq!(attached.get(), 0x1234);
        }
    }

    #[test]
    fn missing_descriptor_still_reports_progress() {
        assert_eq!(advance_identifier(|| 7, |_| 0,
                                     |_| panic!("attachment of missing descriptor")), 1);
    }
}
