//! Platform file close — `FUN_08278894` @ 0x08278894.
//! True extent: 164 bytes, next function at 0x08278938. Raw-word scan:
//! two incoming plain BLs (0x081e1e98, 0x08278f74), zero predicated BLs.
//! Acquires the interface counted mutex, processes the vector member at +0x40,
//! then returns cached status if the directory entry is -1. Otherwise invokes
//! facade selector 0 slot +0x18 with the entry index, optionally invokes
//! selector 1 slot +0x30 when byte +0x14 is zero, and resets index/status to
//! -1/8 before unlocking. The close result survives the optional callback.
//! Deviation: the unported member traversal crosses its verified firmware
//! address; host tests inject operations into the same state transition.

use crate::kernel::sync_mutex::{counted_mutex_guard_acquire, mutex_unlock_counted};
use crate::app::facade_for_selector::facade_for_selector;
use crate::app::path_probe::FacadeObject;

/// Close a live platform file. Requires its original target-layout object,
/// interface, vector member, and facade vtables to remain valid throughout.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn platform_file_close(file: *mut u8) -> u32 {
    let mut lock = core::ptr::null_mut();
    counted_mutex_guard_acquire(&mut lock, file.cast());
    let result = close_with(file, |member| {
        super::platform_file_flush::flush_buffer_collection(member);
    }, |selector| {
        let facade = facade_for_selector(file.cast(), selector);
        if selector == 0 {
            let index = file.add(0x18).cast::<i32>().read();
            let close: unsafe extern "C" fn(*mut FacadeObject, i32) -> u32 =
                core::mem::transmute((*(*facade).vtable).slots[0x18 / 4]);
            close(facade, index)
        } else {
            let finish: unsafe extern "C" fn(*mut FacadeObject) =
                core::mem::transmute((*(*facade).vtable).slots[0x30 / 4]);
            finish(facade);
            0
        }
    });
    mutex_unlock_counted(lock);
    result
}

unsafe fn close_with(
    file: *mut u8,
    mut process: impl FnMut(*mut u8),
    mut dispatch: impl FnMut(u32) -> u32,
) -> u32 {
    process(file.add(0x40));
    if crate::codegen::file_directory_entry::file_has_directory_entry(file) == 0 {
        return file.add(0x1c).cast::<u32>().read();
    }
    let result = dispatch(0);
    if file.add(0x14).read() == 0 {
        dispatch(1);
    }
    file.add(0x18).cast::<i32>().write(-1);
    file.add(0x1c).cast::<u32>().write(8);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn close_state_transitions_and_callback_order() {
        for index in [-1, 0, -2, i32::MIN, i32::MAX] {
            for flag in [0u8, 1, 255] {
                let mut words = [0xa5a5_a5a5u32; 0x54 / 4];
                words[6] = index as u32;
                words[7] = 0x1234;
                let file = words.as_mut_ptr().cast::<u8>();
                unsafe { file.add(0x14).write(flag) };
                let mut events = std::vec::Vec::new();
                let result = unsafe { close_with(file, |member| {
                    assert_eq!(member, file.add(0x40));
                    // Processing occurs before the sentinel check.
                    assert_eq!(file.add(0x18).cast::<i32>().read(), index);
                }, |selector| {
                    assert_eq!(file.add(0x18).cast::<i32>().read(), index);
                    assert_eq!(file.add(0x1c).cast::<u32>().read(), 0x1234);
                    events.push(selector);
                    if selector == 0 { 0xdead_beef } else { 0x5555 }
                }) };
                if index == -1 {
                    assert_eq!(result, 0x1234);
                    assert!(events.is_empty());
                    assert_eq!(words[7], 0x1234);
                } else {
                    assert_eq!(result, 0xdead_beef);
                    assert_eq!(events, if flag == 0 { std::vec![0, 1] } else { std::vec![0] });
                    assert_eq!(words[6], u32::MAX);
                    assert_eq!(words[7], 8);
                    // Closing again returns cached closed status, with no dispatch.
                    assert_eq!(unsafe { close_with(file, |_| {}, |_| panic!("closed dispatch")) }, 8);
                }
                assert_eq!(words[8], 0xa5a5_a5a5);
            }
        }
    }
}
