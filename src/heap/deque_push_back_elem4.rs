//! Four-byte `std::deque` push-back template member.

use crate::cxx::templates::container_is_empty;
use crate::heap::block_deque::BlockDeque;

/// Firmware load address of the unported slow-path helper `FUN_083defc8`.
pub const DEQUE_PUSH_BACK_AUX_ELEM4_ADDRESS: usize = 0x083d_efc8;

/// Indirect binding for the deque growth helper.
///
/// The helper receives the deque head and source word address. It allocates or
/// advances a segment so the caller can perform its ordinary append.
#[derive(Clone, Copy)]
pub struct DequePushBackElem4Ops {
    pub push_back_aux: unsafe extern "C" fn(*mut BlockDeque, *const u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_deque_push_back_aux_elem4(deque: *mut BlockDeque, value: *const u32) {
    let f: unsafe extern "C" fn(*mut BlockDeque, *const u32) =
        core::mem::transmute(DEQUE_PUSH_BACK_AUX_ELEM4_ADDRESS);
    f(deque, value);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_deque_push_back_aux_elem4(_deque: *mut BlockDeque, _value: *const u32) {}

pub const DEFAULT_DEQUE_PUSH_BACK_ELEM4_OPS: DequePushBackElem4Ops = DequePushBackElem4Ops {
    push_back_aux: firmware_deque_push_back_aux_elem4,
};

/// Host tests replace this with a deque-growth model; target builds call the
/// stock helper until that helper itself is ported.
pub static mut DEQUE_PUSH_BACK_ELEM4_OPS: DequePushBackElem4Ops = DEFAULT_DEQUE_PUSH_BACK_ELEM4_OPS;

#[inline(always)]
fn deque_push_back_elem4_ops() -> DequePushBackElem4Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DEQUE_PUSH_BACK_ELEM4_OPS)) }
}

/// Firmware load address of `FUN_083df988`, the grow-and-insert helper used
/// only by [`deque_push_back_elem4_alias_feb8`].
pub const DEQUE_PUSH_BACK_AUX_ELEM4_ALIAS_FEB8_ADDRESS: usize = 0x083d_f988;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_deque_push_back_aux_elem4_alias_feb8(
    deque: *mut BlockDeque,
    value: *const u32,
) {
    let f: unsafe extern "C" fn(*mut BlockDeque, *const u32) =
        core::mem::transmute(DEQUE_PUSH_BACK_AUX_ELEM4_ALIAS_FEB8_ADDRESS);
    f(deque, value);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_deque_push_back_aux_elem4_alias_feb8(
    _deque: *mut BlockDeque,
    _value: *const u32,
) {
}

pub const DEFAULT_DEQUE_PUSH_BACK_ELEM4_ALIAS_FEB8_OPS: DequePushBackElem4Ops =
    DequePushBackElem4Ops {
        push_back_aux: firmware_deque_push_back_aux_elem4_alias_feb8,
    };

/// Active helper for the independently linked `0x083dfeb8` instantiation.
pub static mut DEQUE_PUSH_BACK_ELEM4_ALIAS_FEB8_OPS: DequePushBackElem4Ops =
    DEFAULT_DEQUE_PUSH_BACK_ELEM4_ALIAS_FEB8_OPS;

#[inline(always)]
fn deque_push_back_elem4_alias_feb8_ops() -> DequePushBackElem4Ops {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(DEQUE_PUSH_BACK_ELEM4_ALIAS_FEB8_OPS))
    }
}

/// deque_push_back_elem4_alias_feb8 — original: `FUN_083dfeb8` @ 0x083dfeb8
/// (92 bytes; Ghidra reports 92).
///
/// Appends the four-byte word referenced by `value` to a `std::deque<u32>`.
/// The raw A32 body calls [`container_is_empty`] at 0x083d7630; when the deque
/// is empty or `end.cur == end.seg_end`, it calls the distinct grow-and-insert
/// helper `FUN_083df988` before storing. It writes only through a non-NULL
/// resulting cursor, advances that cursor by four bytes, and increments the
/// count with ARM wrapping arithmetic.
///
/// Raw `osos.dec` establishes the exact extent from its `push {r4,r5,r6,lr}`
/// through `pop {r4,r5,r6,pc}` at 0x083dff10; the next independently linked
/// function begins at 0x083dff14. Full-image A32 branch decoding finds two
/// inbound plain `bl` calls (0x081de288 and 0x083ea568), no predicated calls,
/// and two plain body `bl` calls, to 0x083d7630 and 0x083df988.
///
/// Deliberate deviation: the grow helper is unported, so this instantiation
/// crosses its own volatile operations seam; target builds call the verified
/// firmware address and host tests install a growth model.
///
/// # Safety
///
/// `deque` must point to a writable valid four-byte-element [`BlockDeque`].
/// `value` must be readable when the helper or resulting cursor is non-NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_push_back_elem4_alias_feb8")]
#[inline(never)]
pub unsafe extern "C" fn deque_push_back_elem4_alias_feb8(
    deque: *mut BlockDeque,
    value: *const u32,
) {
    let end = core::ptr::addr_of_mut!((*deque).end);
    if container_is_empty(deque.cast()) != 0 || (*end).cur == (*end).seg_end {
        (deque_push_back_elem4_alias_feb8_ops().push_back_aux)(deque, value);
    }

    let cursor = (*end).cur;
    if !cursor.is_null() {
        cursor.cast::<u32>().write(value.read());
    }
    (*end).cur = cursor.wrapping_add(4);
    (*deque).count = (*deque).count.wrapping_add(1);
}

#[cfg(test)]
mod alias_feb8_tests {
    use super::*;
    use crate::heap::block_deque::DequeIter;

    static OPS_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut AUX_CALLS: usize = 0;
    static mut AUX_STORAGE: *mut u32 = core::ptr::null_mut();

    struct OpsReset;
    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(DEQUE_PUSH_BACK_ELEM4_ALIAS_FEB8_OPS)
                    .write_volatile(DEFAULT_DEQUE_PUSH_BACK_ELEM4_ALIAS_FEB8_OPS);
            }
        }
    }

    unsafe extern "C" fn grow_one_slot(deque: *mut BlockDeque, _value: *const u32) {
        AUX_CALLS += 1;
        (*deque).end.cur = AUX_STORAGE.cast();
        (*deque).end.seg_end = AUX_STORAGE.add(1).cast();
    }

    #[test]
    fn fast_path_writes_without_calling_alias_growth_helper() {
        let mut storage = [0u32; 1];
        let mut deque = BlockDeque {
            begin: DequeIter::NULL,
            end: DequeIter {
                cur: storage.as_mut_ptr().cast(),
                seg_base: storage.as_mut_ptr().cast(),
                seg_end: storage.as_mut_ptr().wrapping_add(1).cast(),
                seg_slot: core::ptr::null_mut(),
            },
            count: 1,
            map: core::ptr::null_mut(),
            map_cap: 0,
        };

        unsafe { deque_push_back_elem4_alias_feb8(&mut deque, &0x1122_3344) };

        assert_eq!(storage, [0x1122_3344]);
        assert_eq!(deque.end.cur, storage.as_mut_ptr().wrapping_add(1).cast());
        assert_eq!(deque.count, 2);
    }

    #[test]
    fn empty_deque_uses_alias_growth_helper_then_appends() {
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
            core::ptr::addr_of_mut!(DEQUE_PUSH_BACK_ELEM4_ALIAS_FEB8_OPS).write_volatile(
                DequePushBackElem4Ops {
                    push_back_aux: grow_one_slot,
                },
            );
            deque_push_back_elem4_alias_feb8(&mut deque, &0xaabb_ccdd);
        }

        assert_eq!(unsafe { AUX_CALLS }, 1);
        assert_eq!(storage, [0xaabb_ccdd]);
        assert_eq!(deque.count, 1);
    }

    #[test]
    fn segment_boundary_uses_alias_growth_helper_and_wraps_count() {
        let _lock = OPS_LOCK.lock();
        let _reset = OpsReset;
        let mut old_storage = [0u32; 1];
        let mut new_storage = [0u32; 1];
        let mut deque = BlockDeque {
            begin: DequeIter::NULL,
            end: DequeIter {
                cur: old_storage.as_mut_ptr().wrapping_add(1).cast(),
                seg_base: old_storage.as_mut_ptr().cast(),
                seg_end: old_storage.as_mut_ptr().wrapping_add(1).cast(),
                seg_slot: core::ptr::null_mut(),
            },
            count: u32::MAX,
            map: core::ptr::null_mut(),
            map_cap: 0,
        };
        unsafe {
            AUX_CALLS = 0;
            AUX_STORAGE = new_storage.as_mut_ptr();
            core::ptr::addr_of_mut!(DEQUE_PUSH_BACK_ELEM4_ALIAS_FEB8_OPS).write_volatile(
                DequePushBackElem4Ops {
                    push_back_aux: grow_one_slot,
                },
            );
            deque_push_back_elem4_alias_feb8(&mut deque, &7);
        }

        assert_eq!(unsafe { AUX_CALLS }, 1);
        assert_eq!(new_storage, [7]);
        assert_eq!(deque.count, 0);
    }
}

/// deque_push_back_elem4 — original: `FUN_083df278` @ 0x083df278
/// (88 bytes; Ghidra reports 92 bytes).
///
/// Appends the four-byte word referenced by `value` to a `std::deque<u32>`.
/// An empty deque or an end iterator at its segment boundary first calls the
/// grow helper `FUN_083defc8` @ 0x083defc8. It then writes the word only when
/// the resulting end cursor is non-NULL, advances that cursor by four bytes,
/// and increments the element count with ARM's wrapping arithmetic.
///
/// Raw `osos.dec` establishes the exact 88-byte extent from the `push` at
/// 0x083df278 through `pop {r4,r5,r6,pc}` at 0x083df2d0; the independent
/// `push {r4,lr}` at 0x083df2d4 begins the next function. Whole-image ARM
/// branch decoding finds exactly three inbound direct calls, all plain `bl`
/// (0x08261870, 0x08261980, 0x083ea334), and no predicated `bl` calls. This
/// body has two plain `bl` calls (`container_is_empty` alias 0x083d7600 and
/// the grow helper) and no predicated calls.
///
/// Deliberate deviation: `FUN_083defc8` is unported, so its target call is
/// retained behind a volatile operations binding; the host default is inert
/// and tests install a faithful segment-growth model.
///
/// # Safety
///
/// `deque` must point to a writable valid four-byte-element [`BlockDeque`].
/// `value` must be readable when the helper or resulting cursor is non-NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_push_back_elem4")]
#[inline(never)]
pub unsafe extern "C" fn deque_push_back_elem4(deque: *mut BlockDeque, value: *const u32) {
    let end = core::ptr::addr_of_mut!((*deque).end);
    if container_is_empty(deque.cast()) != 0 || (*end).cur == (*end).seg_end {
        (deque_push_back_elem4_ops().push_back_aux)(deque, value);
    }

    let cursor = (*end).cur;
    if !cursor.is_null() {
        cursor.cast::<u32>().write(value.read());
    }
    (*end).cur = cursor.wrapping_add(4);
    (*deque).count = (*deque).count.wrapping_add(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::block_deque::DequeIter;

    static OPS_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut AUX_CALLS: usize = 0;
    static mut AUX_DEQUE: *mut BlockDeque = core::ptr::null_mut();
    static mut AUX_STORAGE: *mut u32 = core::ptr::null_mut();

    struct OpsReset;
    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(DEQUE_PUSH_BACK_ELEM4_OPS)
                    .write_volatile(DEFAULT_DEQUE_PUSH_BACK_ELEM4_OPS);
            }
        }
    }

    unsafe extern "C" fn grow_one_slot(deque: *mut BlockDeque, _value: *const u32) {
        AUX_CALLS += 1;
        AUX_DEQUE = deque;
        (*deque).end.cur = AUX_STORAGE.cast();
        (*deque).end.seg_end = AUX_STORAGE.add(1).cast();
    }

    #[test]
    fn fast_path_writes_and_advances_without_growth() {
        let mut storage = [0u32; 2];
        let mut deque = BlockDeque {
            begin: DequeIter::NULL,
            end: DequeIter { cur: storage.as_mut_ptr().cast(), seg_base: storage.as_mut_ptr().cast(), seg_end: storage.as_mut_ptr().wrapping_add(2).cast(), seg_slot: core::ptr::null_mut() },
            count: 1,
            map: core::ptr::null_mut(),
            map_cap: 0,
        };

        unsafe { deque_push_back_elem4(&mut deque, &0x1122_3344); }

        assert_eq!(storage, [0x1122_3344, 0]);
        assert_eq!(deque.end.cur, storage.as_mut_ptr().wrapping_add(1).cast());
        assert_eq!(deque.count, 2);
    }

    #[test]
    fn empty_deque_grows_then_appends() {
        let _lock = OPS_LOCK.lock();
        let _reset = OpsReset;
        let mut storage = [0u32; 1];
        let mut deque = BlockDeque { begin: DequeIter::NULL, end: DequeIter::NULL, count: 0, map: core::ptr::null_mut(), map_cap: 0 };
        unsafe {
            AUX_CALLS = 0;
            AUX_DEQUE = core::ptr::null_mut();
            AUX_STORAGE = storage.as_mut_ptr();
            core::ptr::addr_of_mut!(DEQUE_PUSH_BACK_ELEM4_OPS).write_volatile(DequePushBackElem4Ops { push_back_aux: grow_one_slot });
            deque_push_back_elem4(&mut deque, &0xaabb_ccdd);
        }
        assert_eq!(unsafe { AUX_CALLS }, 1);
        assert_eq!(unsafe { AUX_DEQUE as usize }, &mut deque as *mut BlockDeque as usize);
        assert_eq!(storage, [0xaabb_ccdd]);
        assert_eq!(deque.end.cur, storage.as_mut_ptr().wrapping_add(1).cast());
        assert_eq!(deque.count, 1);
    }

    #[test]
    fn segment_boundary_grows_even_when_not_empty() {
        let _lock = OPS_LOCK.lock();
        let _reset = OpsReset;
        let mut old_storage = [0u32; 1];
        let mut new_storage = [0u32; 1];
        let mut deque = BlockDeque {
            begin: DequeIter::NULL,
            end: DequeIter { cur: old_storage.as_mut_ptr().wrapping_add(1).cast(), seg_base: old_storage.as_mut_ptr().cast(), seg_end: old_storage.as_mut_ptr().wrapping_add(1).cast(), seg_slot: core::ptr::null_mut() },
            count: u32::MAX,
            map: core::ptr::null_mut(),
            map_cap: 0,
        };
        unsafe {
            AUX_CALLS = 0;
            AUX_STORAGE = new_storage.as_mut_ptr();
            core::ptr::addr_of_mut!(DEQUE_PUSH_BACK_ELEM4_OPS).write_volatile(DequePushBackElem4Ops { push_back_aux: grow_one_slot });
            deque_push_back_elem4(&mut deque, &7);
        }
        assert_eq!(unsafe { AUX_CALLS }, 1);
        assert_eq!(new_storage, [7]);
        assert_eq!(deque.count, 0, "count uses ARM wrapping add");
    }
}
