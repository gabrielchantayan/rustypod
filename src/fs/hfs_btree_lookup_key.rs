//! HFS B-tree key lookup wrapper.

use core::{mem::MaybeUninit, ptr::addr_of};

use crate::libc::bcopy::bcopy;

/// RetailOS load address of the key validator at `FUN_0804491c`.
pub const HFS_BTREE_KEY_VALIDATOR_ADDRESS: usize = 0x0804_491c;
/// RetailOS load address of the opaque lookup dispatcher at `FUN_0804112c`.
pub const HFS_BTREE_LOOKUP_DISPATCH_ADDRESS: usize = 0x0804_112c;

/// ABI of the key validator at `0x0804491c`.
pub type HfsBTreeKeyValidator = unsafe extern "C" fn(*const u8, *mut u8) -> i32;
/// ABI of the opaque lookup dispatcher at `0x0804112c`.
pub type HfsBTreeLookupDispatch = unsafe extern "C" fn(*mut u8, *mut u8, *const u8, *mut u8) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn resident_validate_key(key: *const u8, btree: *mut u8) -> i32 {
    unsafe { core::mem::transmute::<usize, HfsBTreeKeyValidator>(HFS_BTREE_KEY_VALIDATOR_ADDRESS)(key, btree) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn resident_lookup_dispatch(
    btree_handle: *mut u8,
    lookup_result: *mut u8,
    lookup_arguments: *const u8,
    operation_context: *mut u8,
) -> i32 {
    unsafe {
        core::mem::transmute::<usize, HfsBTreeLookupDispatch>(HFS_BTREE_LOOKUP_DISPATCH_ADDRESS)(
            btree_handle,
            lookup_result,
            lookup_arguments,
            operation_context,
        )
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_validate_key(_: *const u8, _: *mut u8) -> i32 {
    panic!("hfs_btree_lookup_key requires a host key-validator model")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup_dispatch(_: *mut u8, _: *mut u8, _: *const u8, _: *mut u8) -> i32 {
    panic!("hfs_btree_lookup_key requires a host lookup-dispatch model")
}

#[cfg(target_os = "none")]
pub static mut HFS_BTREE_KEY_VALIDATOR: HfsBTreeKeyValidator = resident_validate_key;
#[cfg(not(target_os = "none"))]
pub static mut HFS_BTREE_KEY_VALIDATOR: HfsBTreeKeyValidator = missing_validate_key;
#[cfg(target_os = "none")]
pub static mut HFS_BTREE_LOOKUP_DISPATCH: HfsBTreeLookupDispatch = resident_lookup_dispatch;
#[cfg(not(target_os = "none"))]
pub static mut HFS_BTREE_LOOKUP_DISPATCH: HfsBTreeLookupDispatch = missing_lookup_dispatch;

/// `hfs_btree_lookup_key` — original: `FUN_08058ba4` @ `0x08058ba4`
/// (152 bytes, `0x08058ba4..0x08058c3c`; 3 verified outgoing unconditional
/// plain `bl` calls at `0x08058be0`, `0x08058c0c`, and `0x08058c20`; zero
/// predicated `bl` calls).
///
/// Validates an HFS B-tree key, copies its length-prefixed encoding into the
/// original's 524-byte stack buffer, then forwards the lookup to the opaque
/// resident dispatcher. HFS uses a one-byte key length unless control-block
/// attributes `+0x30` has bit 1 set, in which case it uses a u16 length.
/// The returned status is sign-extended from 16 bits, and the output word is
/// written only after dispatch. Deliberate deviations: the two unported
/// direct calls are volatile host seams; target builds call their verified
/// retail addresses. The `MaybeUninit` stack record preserves the original's
/// sole initialization: its result word at `+0x04` is cleared while the
/// 524-byte key buffer begins at `+0x1c`.
///
/// # Safety
///
/// `btree_slot` must hold a valid target-width pointer to a B-tree handle;
/// that handle's first word must point to a control block readable through
/// `+0x30`. `key`, `lookup_arguments`, `operation_context`, and `result`
/// must satisfy the resident callees' ABI. The key must contain its declared
/// length plus its length prefix; like retailOS, this wrapper does not bound
/// that length against the 524-byte local buffer.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.hfs_btree_lookup_key")]
#[inline(never)]
pub unsafe extern "C" fn hfs_btree_lookup_key(
    btree_slot: *mut u8,
    key: *const u8,
    lookup_arguments: *const u8,
    operation_context: *mut u8,
    result: *mut u32,
) -> i32 {
    let btree_handle = unsafe { (btree_slot as *const u32).read_volatile() as *mut u8 };
    let control_block = unsafe { (btree_handle as *const u32).read_volatile() as *mut u8 };
    let validate = unsafe { addr_of!(HFS_BTREE_KEY_VALIDATOR).read_volatile() };
    let status = unsafe { validate(key, control_block) };
    if status != 0 {
        return (status as i16) as i32;
    }

    let mut lookup_state = MaybeUninit::<[u8; 552]>::uninit();
    let lookup_state = lookup_state.as_mut_ptr().cast::<u8>();
    unsafe { (lookup_state.add(4) as *mut u32).write(0) };
    let attributes = unsafe { (control_block.add(0x30) as *const u32).read_volatile() };
    let key_length = if attributes & 2 == 0 {
        unsafe { key.read() as usize + 1 }
    } else {
        unsafe { (key as *const u16).read() as usize + 2 }
    };
    unsafe { bcopy(key, lookup_state.add(28), key_length) };

    let dispatch = unsafe { addr_of!(HFS_BTREE_LOOKUP_DISPATCH).read_volatile() };
    let status = unsafe {
        dispatch(btree_handle, lookup_state, lookup_arguments, operation_context)
    };
    unsafe { result.write_volatile((lookup_state.add(4) as *const u32).read_volatile()) };
    (status as i16) as i32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut VALIDATE_STATUS: i32 = 0;
    static mut DISPATCH_STATUS: i32 = 0;
    static mut COPIED_KEY: [u8; 8] = [0; 8];
    static mut DISPATCH_COUNT: u32 = 0;

    unsafe extern "C" fn validate(_: *const u8, _: *mut u8) -> i32 { unsafe { VALIDATE_STATUS } }
    unsafe extern "C" fn dispatch(_: *mut u8, state: *mut u8, _: *const u8, _: *mut u8) -> i32 {
        unsafe {
            COPIED_KEY.copy_from_slice(core::slice::from_raw_parts(state.add(28), 8));
            (state.add(4) as *mut u32).write(0xdead_beef);
            DISPATCH_COUNT += 1;
            DISPATCH_STATUS
        }
    }

    unsafe fn with_ops(test: impl FnOnce(*mut u8)) {
        let _lock = OPS_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::HFS_BTREE_LOOKUP_KEY,
            0x1000,
        ) else {
            return;
        };
        let control = slab;
        let handle = unsafe { slab.add(0x100) };
        unsafe {
            (handle as *mut u32).write(control as u32);
            HFS_BTREE_KEY_VALIDATOR = validate;
            HFS_BTREE_LOOKUP_DISPATCH = dispatch;
            VALIDATE_STATUS = 0;
            DISPATCH_STATUS = 0;
            COPIED_KEY = [0; 8];
            DISPATCH_COUNT = 0;
            test(handle);
            HFS_BTREE_KEY_VALIDATOR = missing_validate_key;
            HFS_BTREE_LOOKUP_DISPATCH = missing_lookup_dispatch;
        }
    }

    #[test]
    fn validates_before_copy_or_dispatch() {
        unsafe { with_ops(|handle| {
            VALIDATE_STATUS = -123;
            let mut slot = handle as u32;
            let key = [3, 1, 2, 3];
            let mut result = 0xfeed_beef;
            assert_eq!(hfs_btree_lookup_key(&mut slot as *mut u32 as *mut u8, key.as_ptr(), core::ptr::null(), core::ptr::null_mut(), &mut result), -123);
            assert_eq!(DISPATCH_COUNT, 0);
            assert_eq!(result, 0xfeed_beef);
        }) }
    }

    #[test]
    fn copies_small_key_and_sign_extends_dispatch_status() {
        unsafe { with_ops(|handle| {
            DISPATCH_STATUS = 0xffff_8021u32 as i32;
            let mut slot = handle as u32;
            let key = [3, 0x11, 0x22, 0x33];
            let mut result = 0;
            assert_eq!(hfs_btree_lookup_key(&mut slot as *mut u32 as *mut u8, key.as_ptr(), core::ptr::null(), core::ptr::null_mut(), &mut result), -32735);
            assert_eq!(DISPATCH_COUNT, 1);
            assert_eq!(&COPIED_KEY[..4], &key);
            assert_eq!(result, 0xdead_beef);
        }) }
    }

    #[test]
    fn copies_big_key_using_the_u16_length_prefix() {
        unsafe { with_ops(|handle| {
            ((handle.sub(0x100).add(0x30)) as *mut u32).write(2);
            let mut slot = handle as u32;
            let key = [4, 0, 0x11, 0x22, 0x33, 0x44];
            let mut result = 0;
            assert_eq!(hfs_btree_lookup_key(&mut slot as *mut u32 as *mut u8, key.as_ptr(), core::ptr::null(), core::ptr::null_mut(), &mut result), 0);
            assert_eq!(DISPATCH_COUNT, 1);
            assert_eq!(&COPIED_KEY[..6], &key);
        }) }
    }
}
