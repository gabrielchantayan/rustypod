//! Record list insertion — `record_list_insert_after` @ `0x0814d6e4`.
//!
//! True size: 28 bytes, seven A32 instructions ending in `bx lr` at
//! `0x0814d6fc`; the next function starts with `push {r4, lr}` at `0x0814d700`.
//! Raw-image branch decoding verifies two incoming plain BLs at `0x081a82c8`
//! and `0x081a8624`, zero predicated BLs, and zero outgoing calls.
//! Inserts `record` after `position`: copy the successor, set both record
//! links, reload position's successor, update its backlink, then publish the
//! new successor. The reload preserves the original behavior under aliasing.
//! No target behavioral deviations. Host pointer fields widen naturally;
//! the ARM layout remains header +0, next +4, previous +8.

/// Intrusive links following a variable-length record's header word.
#[repr(C)]
pub struct RecordListNode {
    pub header: u32,
    pub next: *mut RecordListNode,
    pub previous: *mut RecordListNode,
}

/// # Safety
/// Both arguments and the successor reloaded from `position` must be valid,
/// aligned, writable nodes. There are no NULL or membership checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_list_insert_after(
    position: *mut RecordListNode,
    record: *mut RecordListNode,
) {
    unsafe {
        let successor = (*position).next;
        (*record).previous = position;
        (*record).next = successor;
        let successor = (*position).next;
        (*successor).previous = record;
        (*position).next = record;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    fn node(header: u32) -> RecordListNode {
        RecordListNode { header, next: null_mut(), previous: null_mut() }
    }

    #[test]
    fn inserts_into_empty_ring_and_between_existing_nodes() {
        let mut sentinel = node(0xff00_0000);
        let mut first = node(0x1200_0020);
        let mut second = node(0x3400_0040);
        let s = &mut sentinel as *mut RecordListNode;
        let a = &mut first as *mut RecordListNode;
        let b = &mut second as *mut RecordListNode;
        sentinel.next = s;
        sentinel.previous = s;
        unsafe { record_list_insert_after(s, a) };
        assert_eq!((sentinel.next, sentinel.previous), (a, a));
        assert_eq!((first.next, first.previous), (s, s));
        unsafe { record_list_insert_after(s, b) };
        assert_eq!((sentinel.next, sentinel.previous), (b, a));
        assert_eq!((second.next, second.previous), (a, s));
        assert_eq!((first.next, first.previous), (s, b));
        assert_eq!((sentinel.header, first.header, second.header),
                   (0xff00_0000, 0x1200_0020, 0x3400_0040));
    }

    #[test]
    fn aliased_position_record_preserves_original_store_order() {
        let mut position = node(0xab00_0004);
        let mut successor = node(0xcd00_0008);
        let p = &mut position as *mut RecordListNode;
        let s = &mut successor as *mut RecordListNode;
        position.next = s;
        successor.previous = p;
        unsafe { record_list_insert_after(p, p) };
        assert_eq!((position.next, position.previous), (p, p));
        assert_eq!(successor.previous, p);
        assert_eq!((position.header, successor.header), (0xab00_0004, 0xcd00_0008));
    }

    #[test]
    fn successor_alias_reloads_updated_next_link() {
        let mut position = node(1);
        let mut successor = node(2);
        let p = &mut position as *mut RecordListNode;
        let s = &mut successor as *mut RecordListNode;
        position.next = s;
        successor.next = p;
        successor.previous = p;
        unsafe { record_list_insert_after(p, s) };
        assert_eq!(position.next, s);
        assert_eq!((successor.next, successor.previous), (s, s));
        assert_eq!((position.header, successor.header), (1, 2));
    }
}
