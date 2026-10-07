//! String/buffer state reset — FUN_0814955c @ 0x0814955c.
//! True extent [0x0814955c, 0x081495b4): 88 bytes (84 code + vtable literal).
//! Raw A32: one inbound BL at 0x08149628, one BLNE at 0x08149544;
//! outbound one BL (string_object_destroy) and two BLNE (NULL assignment,
//! free_wrapper). Clear the leading string, destroy an empty temporary,
//! free a non-NULL buffer with tag 0, then zero four words and byte +0x18.
//! Deviations: NULL assignment expands to verified virtual slot +0xc,
//! avoiding the existing helper's unwired clear seam. Omit the impossible
//! caller/stack-temporary self-alias check; repr(C) pointers widen on hosts.
//! No concrete class identity or meaning for the two middle words is inferred.

use crate::cxx::string_object::{string_object_destroy, StringObject, STRING_OBJECT_VTABLE};
use crate::heap::veneers::free_wrapper;

#[repr(C)]
pub struct StringBufferState {
    pub string: StringObject,
    pub buffer: *mut u8,
    pub buffer_words: [u32; 2],
    pub users: u32,
    pub pending: u8,
    pub padding: [u8; 3],
}

/// # Safety
/// `state` must be live, its string's vtable slot 3 callable, and its buffer
/// either NULL or owned by the default heap. Callbacks obey stock ownership.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_buffer_state_reset(state: *mut StringBufferState) {
    let string = core::ptr::addr_of_mut!((*state).string);
    let clear: unsafe extern "C" fn(*mut StringObject) =
        core::mem::transmute((*(*string).vtable).slots[3]);
    clear(string);
    let mut empty = StringObject { vtable: &STRING_OBJECT_VTABLE, payload: core::ptr::null_mut() };
    string_object_destroy(&mut empty);
    let buffer = (*state).buffer;
    if !buffer.is_null() { free_wrapper(buffer, 0); }
    (*state).buffer = core::ptr::null_mut();
    (*state).buffer_words = [0; 2];
    (*state).users = 0;
    (*state).pending = 0;
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(StringBufferState, buffer) == 8);
    assert!(core::mem::offset_of!(StringBufferState, pending) == 24);
};

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::cxx::string_object::StringObjectVtable;
    use crate::heap::types::{HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::HEAP_OPS;
    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    static STATE: AtomicPtr<StringBufferState> = AtomicPtr::new(core::ptr::null_mut());
    static FREES: AtomicUsize = AtomicUsize::new(0);
    static CLEARS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn clear(string: *mut StringObject) {
        let state = STATE.load(Ordering::Relaxed);
        assert_eq!(string, core::ptr::addr_of_mut!((*state).string));
        let repeated = CLEARS.load(Ordering::Relaxed) != 0;
        assert_eq!((*state).buffer_words, if repeated { [0; 2] } else { [17, 29] });
        assert_eq!((*state).users, if repeated { 0 } else { 3 });
        assert_eq!((*state).pending, if repeated { 0 } else { 0xff });
        (*string).payload = core::ptr::null_mut();
        CLEARS.fetch_add(1, Ordering::Relaxed);
    }
    unsafe extern "C" fn free(_heap: *mut HeapDescriptorDescriptor, buffer: *mut u8, tag: usize) {
        let state = STATE.load(Ordering::Relaxed);
        assert_eq!(buffer, (*state).buffer);
        assert_eq!(tag, 0);
        assert!((*state).string.payload.is_null());
        assert_eq!((*state).buffer_words, [17, 29]);
        assert_eq!((*state).users, 3);
        assert_eq!((*state).pending, 0xff);
        FREES.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn reset_preserves_vtable_and_padding_and_releases_before_zeroing() {
        // Subprocess isolates existing global heap ops from every other test.
        const CHILD: &str = "RUSTYPOD_STRING_BUFFER_RESET_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "app::string_buffer_state_reset::tests::reset_preserves_vtable_and_padding_and_releases_before_zeroing", "--nocapture"])
                .env(CHILD, "1").status().unwrap();
            assert!(result.success());
            return;
        }
        unsafe {
            let mut heap = HeapDescriptorDescriptor { desc: core::ptr::null_mut() };
            core::ptr::addr_of_mut!(DEFAULT_HEAP).write(&mut heap);
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = free;
            let vtable = StringObjectVtable { slots: [0, 0, 0, clear as *const () as usize, 0, 0] };
            for present in [false, true] {
                let mut buffer = [0xabu8; 4];
                let mut payload = [b'x', 0];
                let mut state = StringBufferState {
                    string: StringObject { vtable: &vtable, payload: payload.as_mut_ptr() },
                    buffer: if present { buffer.as_mut_ptr() } else { core::ptr::null_mut() },
                    buffer_words: [17, 29], users: 3, pending: 0xff, padding: [0xa5; 3],
                };
                STATE.store(&mut state, Ordering::Relaxed);
                FREES.store(0, Ordering::Relaxed);
                CLEARS.store(0, Ordering::Relaxed);
                string_buffer_state_reset(&mut state);
                assert_eq!(FREES.load(Ordering::Relaxed), usize::from(present));
                assert_eq!(CLEARS.load(Ordering::Relaxed), 1);
                assert_eq!(state.string.vtable, &vtable as *const _);
                assert!(state.string.payload.is_null() && state.buffer.is_null());
                assert_eq!(state.buffer_words, [0; 2]);
                assert_eq!((state.users, state.pending), (0, 0));
                assert_eq!(state.padding, [0xa5; 3]);
                string_buffer_state_reset(&mut state);
                assert_eq!(FREES.load(Ordering::Relaxed), usize::from(present));
                assert_eq!(CLEARS.load(Ordering::Relaxed), 2);
            }
        }
    }
}
