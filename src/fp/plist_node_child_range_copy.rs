//! plist_node_child_range_copy — original: `FUN_083e9000` @ 0x083e9000 (56 bytes).
//!
//! Raw `osos.dec` words establish the exact fourteen-instruction extent
//! `0x083e9000..0x083e9037`: the final `pop {r4,r5,r6,pc}` is at
//! `0x083e9034`, and the next independent function begins at `0x083e9038`.
//! Whole-image A32 branch decoding finds two inbound plain `bl` sites
//! (`0x083e3368`, `0x083e33b4`) and no predicated inbound `bl` sites. The body
//! has one predicated `blne`, to the verified `plist_node_child_copy_construct`
//! seam at `0x0825c61c`, and no plain `bl`.
//!
//! Algorithm: construct-copy 40-byte plist-node records from the half-open
//! range `[source, end)` into consecutive `destination` storage, advancing both
//! cursors after every record, then return the advanced destination cursor.
//! Deliberate deviation: the direct ARM call is dispatched through the existing
//! volatile copy-constructor operation table so host tests can supply a real
//! constructor and target builds retain the verified retailOS callee.

use crate::fp::fp_misc::{plist_node_child_copy_construct, PlistNode};

const PLIST_NODE_SIZE: usize = 0x28;

type RecordCopy = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;

unsafe extern "C" fn copy_plist_node(destination: *mut u8, source: *const u8) -> *mut u8 {
    unsafe { plist_node_child_copy_construct(destination.cast(), source.cast()).cast() }
}


#[inline(always)]
unsafe fn copy_range_with(
    mut source: *const u8,
    end: *const u8,
    mut destination: *mut u8,
    copy: RecordCopy,
) -> *mut u8 {
    while source != end {
        unsafe { copy(destination, source) };
        source = source.add(PLIST_NODE_SIZE);
        destination = destination.add(PLIST_NODE_SIZE);
    }
    destination
}

/// Construct-copy plist nodes from `[source, end)` into `destination`.
///
/// # Safety
///
/// `source` and `end` must delimit a forward range in 40-byte increments, and
/// `destination` must designate enough valid plist-node storage. The child copy
/// constructor defines each record's ownership semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.plist_node_child_range_copy")]
#[inline(never)]
pub unsafe extern "C" fn plist_node_child_range_copy(
    source: *const PlistNode,
    end: *const PlistNode,
    destination: *mut PlistNode,
) -> *mut PlistNode {
    unsafe {
        copy_range_with(
            source.cast(),
            end.cast(),
            destination.cast(),
            copy_plist_node,
        )
        .cast()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::Mutex;

    use super::{copy_range_with, PLIST_NODE_SIZE};

    static COPY_LOCK: Mutex<()> = Mutex::new(());
    static mut COPY_CALLS: usize = 0;

    unsafe extern "C" fn copy_record(destination: *mut u8, source: *const u8) -> *mut u8 {
        unsafe {
            COPY_CALLS += 1;
            core::ptr::copy_nonoverlapping(source, destination, PLIST_NODE_SIZE);
        }
        destination
    }

    #[test]
    fn empty_range_returns_destination_without_copying() {
        let _lock = COPY_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let source = [0xa5u8; PLIST_NODE_SIZE];
        let mut destination = [0x5au8; PLIST_NODE_SIZE];
        unsafe { COPY_CALLS = 0 };

        let returned = unsafe {
            copy_range_with(
                source.as_ptr(),
                source.as_ptr(),
                destination.as_mut_ptr(),
                copy_record,
            )
        };

        assert_eq!(returned, destination.as_mut_ptr());
        assert_eq!(destination, [0x5a; PLIST_NODE_SIZE]);
        assert_eq!(unsafe { COPY_CALLS }, 0);
    }

    #[test]
    fn copies_complete_records_and_returns_advanced_destination() {
        let _lock = COPY_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut source = [0u8; PLIST_NODE_SIZE * 3];
        for (index, byte) in source.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut destination = [0xa5u8; PLIST_NODE_SIZE * 4];
        unsafe { COPY_CALLS = 0 };

        let returned = unsafe {
            copy_range_with(
                source.as_ptr(),
                source.as_ptr().add(PLIST_NODE_SIZE * 3),
                destination.as_mut_ptr(),
                copy_record,
            )
        };

        assert_eq!(returned, unsafe { destination.as_mut_ptr().add(PLIST_NODE_SIZE * 3) });
        assert_eq!(&destination[..PLIST_NODE_SIZE * 3], &source);
        assert_eq!(&destination[PLIST_NODE_SIZE * 3..], &[0xa5; PLIST_NODE_SIZE]);
        assert_eq!(unsafe { COPY_CALLS }, 3);
    }
}
