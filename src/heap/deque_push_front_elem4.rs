//! Four-byte `std::deque` push-front template member.

use crate::cxx::templates::container_is_empty;
use crate::heap::block_deque::BlockDeque;

/// Firmware load address of the unported grow-and-insert helper `FUN_083de3b8`.
pub const DEQUE_PUSH_FRONT_AUX_ELEM4_ADDRESS: usize = 0x083d_e3b8;

/// Indirect binding for the deque growth helper.
///
/// The helper receives the deque head and source word address. It allocates or
/// advances a segment so the caller can perform its ordinary prepend.
#[derive(Clone, Copy)]
pub struct DequePushFrontElem4Ops {
    pub push_front_aux: unsafe extern "C" fn(*mut BlockDeque, *const u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_deque_push_front_aux_elem4(
    deque: *mut BlockDeque,
    value: *const u32,
) {
    let f: unsafe extern "C" fn(*mut BlockDeque, *const u32) =
        core::mem::transmute(DEQUE_PUSH_FRONT_AUX_ELEM4_ADDRESS);
    f(deque, value);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_deque_push_front_aux_elem4(
    _deque: *mut BlockDeque,
    _value: *const u32,
) {
}

pub const DEFAULT_DEQUE_PUSH_FRONT_ELEM4_OPS: DequePushFrontElem4Ops = DequePushFrontElem4Ops {
    push_front_aux: firmware_deque_push_front_aux_elem4,
};

/// Host tests replace this with a deque-growth model; target builds call the
/// stock helper until that helper itself is ported.
pub static mut DEQUE_PUSH_FRONT_ELEM4_OPS: DequePushFrontElem4Ops =
    DEFAULT_DEQUE_PUSH_FRONT_ELEM4_OPS;

#[inline(always)]
fn deque_push_front_elem4_ops() -> DequePushFrontElem4Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DEQUE_PUSH_FRONT_ELEM4_OPS)) }
}

/// deque_push_front_elem4 — original: `FUN_083de1dc` @ 0x083de1dc
/// (80 bytes; Ghidra reports 80 bytes).
///
/// Prepends the four-byte word referenced by `value` to a `std::deque<u32>`.
/// The raw A32 body calls `container_is_empty_alias_75d0` at 0x083d75d0; an
/// empty deque or a begin cursor at its segment base calls the grow-and-insert
/// helper `FUN_083de3b8`. It then decrements the resulting begin cursor by
/// four bytes, writes the word only through a non-NULL cursor, and increments
/// the count with ARM wrapping arithmetic.
///
/// Raw `osos.dec` establishes the exact extent from the `push {r4,r5,r6,lr}`
/// at 0x083de1dc through `pop {r4,r5,r6,pc}` at 0x083de228; the next function
/// begins at 0x083de22c. Full-image ARM branch decoding finds exactly two
/// inbound direct calls, both plain `bl` (0x083de580 and 0x083de620), no
/// predicated `bl` calls. The body has two plain `bl` calls, to 0x083d75d0
/// and 0x083de3b8, and no predicated calls.
/// Deliberate deviations: the byte-identical 0x083d75d0 predicate calls the
/// canonical `container_is_empty` family seam rather than adding another
/// identity; `FUN_083de3b8` is unported, so the target call crosses a volatile
/// operations seam. Target builds call the verified firmware address and host
/// tests install a segment-growth model.
///
/// # Safety
///
/// `deque` must point to a writable valid four-byte-element [`BlockDeque`].
/// `value` must be readable when the helper or resulting cursor is non-NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_push_front_elem4")]
#[inline(never)]
pub unsafe extern "C" fn deque_push_front_elem4(deque: *mut BlockDeque, value: *const u32) {
    let begin = core::ptr::addr_of_mut!((*deque).begin);
    if container_is_empty(deque.cast()) != 0 || (*begin).cur == (*begin).seg_base {
        (deque_push_front_elem4_ops().push_front_aux)(deque, value);
    }

    let cursor = (*begin).cur.wrapping_sub(4);
    (*begin).cur = cursor;
    if !cursor.is_null() {
        cursor.cast::<u32>().write(value.read());
    }
    (*deque).count = (*deque).count.wrapping_add(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::block_deque::DequeIter;

    static OPS_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut AUX_CALLS: usize = 0;
    static mut AUX_STORAGE: *mut u32 = core::ptr::null_mut();

    struct OpsReset;
    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(DEQUE_PUSH_FRONT_ELEM4_OPS)
                    .write_volatile(DEFAULT_DEQUE_PUSH_FRONT_ELEM4_OPS);
            }
        }
    }

    unsafe extern "C" fn grow_one_slot(deque: *mut BlockDeque, _value: *const u32) {
        AUX_CALLS += 1;
        (*deque).begin.cur = AUX_STORAGE.add(1).cast();
        (*deque).begin.seg_base = AUX_STORAGE.cast();
    }

    #[test]
    fn fast_path_prepends_without_calling_growth_helper() {
        let mut storage = [0u32; 2];
        let mut deque = BlockDeque {
            begin: DequeIter {
                cur: storage.as_mut_ptr().wrapping_add(1).cast(),
                seg_base: storage.as_mut_ptr().cast(),
                seg_end: storage.as_mut_ptr().wrapping_add(2).cast(),
                seg_slot: core::ptr::null_mut(),
            },
            end: DequeIter::NULL,
            count: 1,
            map: core::ptr::null_mut(),
            map_cap: 0,
        };

        unsafe { deque_push_front_elem4(&mut deque, &0x1122_3344) };

        assert_eq!(storage, [0x1122_3344, 0]);
        assert_eq!(deque.begin.cur, storage.as_mut_ptr().cast());
        assert_eq!(deque.count, 2);
    }

    #[test]
    fn empty_deque_grows_then_prepends() {
        let _lock = OPS_LOCK.lock();
        let _reset = OpsReset;
        let mut storage = [0u32; 1];
        let mut deque = BlockDeque {
            begin: DequeIter::NULL,
            end: DequeIter::NULL,
            count: 0,
            map: core::ptr::null_mut(),
            map_cap: 0,
        };
        unsafe {
            AUX_CALLS = 0;
            AUX_STORAGE = storage.as_mut_ptr();
            core::ptr::addr_of_mut!(DEQUE_PUSH_FRONT_ELEM4_OPS).write_volatile(
                DequePushFrontElem4Ops { push_front_aux: grow_one_slot },
            );
            deque_push_front_elem4(&mut deque, &0xaabb_ccdd);
        }

        assert_eq!(unsafe { AUX_CALLS }, 1);
        assert_eq!(storage, [0xaabb_ccdd]);
        assert_eq!(deque.begin.cur, storage.as_mut_ptr().cast());
        assert_eq!(deque.count, 1);
    }

    #[test]
    fn segment_boundary_grows_and_wraps_count() {
        let _lock = OPS_LOCK.lock();
        let _reset = OpsReset;
        let mut storage = [0u32; 1];
        let mut deque = BlockDeque {
            begin: DequeIter {
                cur: storage.as_mut_ptr().cast(),
                seg_base: storage.as_mut_ptr().cast(),
                seg_end: storage.as_mut_ptr().wrapping_add(1).cast(),
                seg_slot: core::ptr::null_mut(),
            },
            end: DequeIter::NULL,
            count: u32::MAX,
            map: core::ptr::null_mut(),
            map_cap: 0,
        };
        unsafe {
            AUX_CALLS = 0;
            AUX_STORAGE = storage.as_mut_ptr();
            core::ptr::addr_of_mut!(DEQUE_PUSH_FRONT_ELEM4_OPS).write_volatile(
                DequePushFrontElem4Ops { push_front_aux: grow_one_slot },
            );
            deque_push_front_elem4(&mut deque, &7);
        }

        assert_eq!(unsafe { AUX_CALLS }, 1);
        assert_eq!(storage, [7]);
        assert_eq!(deque.count, 0);
    }
}
