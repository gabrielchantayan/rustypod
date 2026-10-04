use crate::heap::block_deque::BlockDeque;

pub type StatusQuery = unsafe extern "C" fn(*mut StatusObject) -> u32;

#[repr(C)]
pub struct StatusVtable {
    pub preceding_slots: [usize; 6],
    pub query: StatusQuery,
}

#[repr(C)]
pub struct StatusObject {
    pub vtable: *const StatusVtable,
}

// Raw 0x082156b8 checks the count via 0x083d7610, copies the begin
// iterator via 0x083da34c, then loads the object pointer through its cursor.
// Only r0 is an input: the saved r1-r3 are overwritten by the iterator copy.
#[inline(always)]
unsafe fn front_object(deque: *const BlockDeque) -> *mut StatusObject {
    #[cfg(target_os = "none")]
    {
        let lookup: unsafe extern "C" fn(*const BlockDeque) -> *mut StatusObject =
            core::mem::transmute(0x0821_56b8usize);
        lookup(deque)
    }
    #[cfg(not(target_os = "none"))]
    {
        // Native-pointer model of the same lookup, not a second exported port.
        if (*deque).count == 0 {
            core::ptr::null_mut()
        } else {
            (*deque).begin.cur.cast::<*mut StatusObject>().read()
        }
    }
}

/// container_status_flags — original `FUN_082158c0` @ 0x082158c0.
/// True size: 44 bytes, ending at 0x082158ec's independent push prologue.
/// Two inbound plain BL sites (0x0818ba0c, 0x0818ba24), no predicated BL.
/// Body: one plain BL to 0x082156b8, no predicated BL, one BLX r1.
/// Retrieves the front object from a deque of object pointers; returns zero
/// for an empty deque or NULL front object, otherwise invokes vtable slot 6
/// (+0x18 on target) with the object as receiver and returns all result bits.
/// Callers extract bits 4 and 2. Deliberate deviations: the unported lookup
/// remains a stock firmware call on target; hosts use its verified algorithm
/// with native pointers. Typed vtable fields preserve slot indices on hosts.
///
/// # Safety
/// `deque` must be a readable deque. If nonempty, its begin cursor must point
/// to a readable object pointer. A non-NULL object must contain a valid vtable
/// whose query slot accepts that object and returns a u32.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn container_status_flags(deque: *const BlockDeque) -> u32 {
    let object = front_object(deque);
    if object.is_null() {
        0
    } else {
        ((*(*object).vtable).query)(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::block_deque::DequeIter;

    #[repr(C)]
    struct Receiver {
        base: StatusObject,
        flags: u32,
        calls: u32,
    }

    unsafe extern "C" fn query(object: *mut StatusObject) -> u32 {
        let receiver = &mut *object.cast::<Receiver>();
        receiver.calls += 1;
        receiver.flags
    }

    static VTABLE: StatusVtable = StatusVtable {
        preceding_slots: [0; 6],
        query,
    };

    fn deque(cursor: *mut u8, count: u32) -> BlockDeque {
        BlockDeque {
            begin: DequeIter { cur: cursor, ..DequeIter::NULL },
            end: DequeIter::NULL,
            count,
            map: core::ptr::null_mut(),
            map_cap: 0,
        }
    }

    #[test]
    fn empty_deque_does_not_read_null_cursor() {
        let container = deque(core::ptr::null_mut(), 0);
        assert_eq!(unsafe { container_status_flags(&container) }, 0);
    }

    #[test]
    fn nonempty_null_front_does_not_read_vtable() {
        let mut slot: *mut StatusObject = core::ptr::null_mut();
        let container = deque(core::ptr::addr_of_mut!(slot).cast(), 1);
        assert_eq!(unsafe { container_status_flags(&container) }, 0);
    }

    #[test]
    fn dispatches_front_receiver_once_and_preserves_every_result_bit() {
        let mut receiver = Receiver {
            base: StatusObject { vtable: &VTABLE },
            flags: 0,
            calls: 0,
        };
        let mut slot = core::ptr::addr_of_mut!(receiver.base);
        let mut container = deque(core::ptr::addr_of_mut!(slot).cast(), 1);
        for flags in [0, 4, 16, 20, 0x8000_0000, u32::MAX] {
            receiver.flags = flags;
            let before = receiver.calls;
            assert_eq!(unsafe { container_status_flags(&container) }, flags);
            assert_eq!(receiver.calls, before + 1);
        }
        container.count = 0;
        let before = receiver.calls;
        assert_eq!(unsafe { container_status_flags(&container) }, 0);
        assert_eq!(receiver.calls, before);
    }
}
