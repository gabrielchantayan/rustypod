//! `command_dispatch_by_name_single_arg` — original: `FUN_081df9ac` @
//! 0x081df9ac (**116 bytes**, 0x081df9ac..0x081dfa20; **11** direct
//! `bl` call sites, all unconditional).
//!
//! Ghidra reports only the leading four-byte `mov r0, r0` at 0x081df9ac.
//! Raw bytes show that this is a public NOP entry into the implementation at
//! 0x081df9b0; the next distinct function opens at 0x081dfa20. A separate
//! direct `bl` enters that 0x081df9b0 body. The count above is specifically
//! for the assigned 0x081df9ac entry, re-verified by decoding every ARM
//! `B`/`BL` word in `osos.dec`; there are no direct `b` or predicated calls.
//!
//! The command-dispatcher singleton owns a string-keyed map at `this + 4`.
//! This entry constructs a temporary COW string from `name`, finds its map
//! record, releases the temporary, and compares the found iterator with the
//! end sentinel at `this + 0x14`. A miss returns NULL. A hit requires the
//! record's `+0x14` callback slot to be non-NULL (else `heap_panic`) and
//! invokes it with `argument`, returning that callback's value untouched.
//!
//! # Deliberate deviations
//!
//! The ordered-map finder `FUN_083db41c` is unported, so it and the
//! record callback ride [`COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS`]. On the
//! target their defaults call 0x083db41c and the raw callback word directly;
//! host tests replace both slots. The original's `FUN_083cf800` iterator
//! comparator is exactly one word equality, reproduced directly rather than
//! given a second dispatch seam.

use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};
use crate::heap::veneers::heap_panic;
use core::ptr;

/// Target-width prefix of the 0x20-byte command dispatcher object.
///
/// `map` begins at `this + 4`; `map_end` is the map's header/sentinel word at
/// `this + 0x14`. These are `u32` fields because the retailOS object is
/// 32-bit even when host tests run on x86-64.
#[repr(C)]
struct CommandDispatcherLayout {
    _vtable: u32,
    map: [u32; 4],
    map_end: u32,
}

/// Target-width prefix of a record returned by the command map.
#[repr(C)]
struct CommandRecordLayout {
    _before_callback: [u32; 5],
    callback: u32,
}

/// Dependencies that remain in retailOS for
/// [`command_dispatch_by_name_single_arg`].
#[derive(Clone, Copy)]
pub struct CommandDispatchByNameSingleArgOps {
    /// `FUN_083db41c` @ 0x083db41c: find `key` in the ordered map and write
    /// either its record or the end sentinel to `out`.
    pub find: unsafe extern "C" fn(out: *mut *mut u8, map: *mut u8, key: *mut *mut u8),
    /// Invoke a live record's `+0x14` callback word with the caller argument.
    pub invoke: unsafe extern "C" fn(callback: u32, argument: *mut u8) -> *mut u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_find(
    out: *mut *mut u8,
    map: *mut u8,
    key: *mut *mut u8,
) {
    let find: unsafe extern "C" fn(*mut *mut u8, *mut u8, *mut *mut u8) =
        unsafe { core::mem::transmute(0x083d_b41cusize) };
    unsafe { find(out, map, key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_find(
    _out: *mut *mut u8,
    _map: *mut u8,
    _key: *mut *mut u8,
) {
    panic!("command_dispatch_by_name_single_arg requires map finder 0x083db41c")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_invoke(callback: u32, argument: *mut u8) -> *mut u8 {
    let invoke: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        unsafe { core::mem::transmute(callback as usize) };
    unsafe { invoke(argument) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_invoke(_callback: u32, _argument: *mut u8) -> *mut u8 {
    panic!("command_dispatch_by_name_single_arg requires a record callback")
}

/// Wired defaults for [`COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS`].
#[cfg(target_os = "none")]
pub const DEFAULT_COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS: CommandDispatchByNameSingleArgOps =
    CommandDispatchByNameSingleArgOps {
        find: firmware_find,
        invoke: firmware_invoke,
    };

/// Wired defaults for [`COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS`].
#[cfg(not(target_os = "none"))]
pub const DEFAULT_COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS: CommandDispatchByNameSingleArgOps =
    CommandDispatchByNameSingleArgOps {
        find: missing_find,
        invoke: missing_invoke,
    };

/// Active retailOS model. Host tests install a map/handler model; target
/// integration automatically calls the stock map finder and callback.
pub static mut COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS: CommandDispatchByNameSingleArgOps =
    DEFAULT_COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS;

#[inline(always)]
unsafe fn dispatch_ops() -> CommandDispatchByNameSingleArgOps {
    core::ptr::read_volatile(core::ptr::addr_of!(COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS))
}

/// command_dispatch_by_name_single_arg — original: `FUN_081df9ac` @
/// 0x081df9ac (116 bytes; **11** direct `bl` call sites, all unconditional).
///
/// Builds a temporary COW key from `name`, searches `dispatcher`'s map, and
/// returns NULL on a miss. On a hit, invokes the record's required `+0x14`
/// callback with `argument` and returns its answer untouched. `dispatcher`,
/// `name`, and the callback slot have no NULL guards beyond the original's
/// fatal callback-slot check.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn command_dispatch_by_name_single_arg(
    dispatcher: *mut u8,
    name: *const u8,
    argument: *mut u8,
) -> *mut u8 {
    let ops = dispatch_ops();
    let dispatcher_layout = dispatcher.cast::<CommandDispatcherLayout>();
    let mut found = dispatcher;
    let mut key = ptr::null_mut();
    cxx_string_from_cstr(ptr::addr_of_mut!(key), name);
    (ops.find)(
        ptr::addr_of_mut!(found),
        (*dispatcher_layout).map.as_mut_ptr().cast(),
        ptr::addr_of_mut!(key),
    );
    cxx_string_release(ptr::addr_of_mut!(key));

    let end = (*dispatcher_layout).map_end as usize as *mut u8;
    if found == end {
        return ptr::null_mut();
    }

    let callback = (*found.cast::<CommandRecordLayout>()).callback;
    if callback == 0 {
        heap_panic();
    }
    (ops.invoke)(callback, argument)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::slice;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SLAB: *mut u8 = ptr::null_mut();
    static mut FOUND: *mut u8 = ptr::null_mut();
    static mut CALLBACK_ANSWER: *mut u8 = ptr::null_mut();
    static mut FIND_MAP: *mut u8 = ptr::null_mut();
    static mut FIND_KEY: Vec<u8> = Vec::new();
    static mut CALLBACK_WORD: u32 = 0;
    static mut CALLBACK_ARGUMENT: *mut u8 = ptr::null_mut();
    static mut CALLBACK_CALLS: usize = 0;

    const SLAB_LEN: usize = 0x1000;
    const RECORD_OFFSET: usize = 0x100;
    const END_OFFSET: usize = 0x200;
    const ARGUMENT_OFFSET: usize = 0x300;
    const ANSWER_OFFSET: usize = 0x400;

    const STRING_ARENA_SIZE: usize = 256;

    #[repr(C, align(8))]
    struct StringArena([u8; STRING_ARENA_SIZE]);

    static mut STRING_ARENA: StringArena = StringArena([0; STRING_ARENA_SIZE]);
    static mut STRING_ARENA_USED: usize = 0;

    unsafe fn slab() -> *mut u8 {
        if SLAB.is_null() {
            match try_map_u32_slab(hints::COMMAND_DISPATCH_BY_NAME_SINGLE_ARG, SLAB_LEN) {
                Some(mapped) => SLAB = mapped,
                None => {
                    note_missing_u32_fixture("app::command_dispatch_name_callback");
                }
            }
        }
        SLAB
    }

    unsafe fn dispatcher() -> *mut CommandDispatcherLayout {
        slab().cast()
    }

    unsafe fn record() -> *mut CommandRecordLayout {
        slab().add(RECORD_OFFSET).cast()
    }

    unsafe fn end() -> *mut u8 {
        slab().add(END_OFFSET)
    }

    unsafe extern "C" fn string_arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = STRING_ARENA_USED;
        let aligned_size = (size + 7) & !7;
        if used + aligned_size > STRING_ARENA_SIZE {
            return ptr::null_mut();
        }
        STRING_ARENA_USED = used + aligned_size;
        ptr::addr_of_mut!(STRING_ARENA.0).cast::<u8>().add(used)
    }

    unsafe extern "C" fn string_arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        _allocation: *mut u8,
        _tag: usize,
    ) {
    }

    unsafe extern "C" fn string_arena_create(
        descriptor: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        descriptor.cast()
    }

    unsafe extern "C" fn mock_find(out: *mut *mut u8, map: *mut u8, key: *mut *mut u8) {
        FIND_MAP = map;
        let bytes = *key as *const u8;
        let mut length = 0;
        while *bytes.add(length) != 0 {
            length += 1;
        }
        FIND_KEY = slice::from_raw_parts(bytes, length).to_vec();
        *out = FOUND;
    }

    unsafe extern "C" fn mock_invoke(callback: u32, argument: *mut u8) -> *mut u8 {
        CALLBACK_WORD = callback;
        CALLBACK_ARGUMENT = argument;
        CALLBACK_CALLS += 1;
        CALLBACK_ANSWER
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous_ops: CommandDispatchByNameSingleArgOps,
        _heap_guard: MutexGuard<'static, ()>,
        available: bool,
    }

    fn bench() -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let heap_guard = crate::heap::veneers::tests::mock_heap();
        let available = unsafe { !slab().is_null() };
        let previous_ops = unsafe {
            ptr::read_volatile(ptr::addr_of!(COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS))
        };
        if available {
            unsafe {
                ptr::write_bytes(slab(), 0, SLAB_LEN);
                FOUND = ptr::null_mut();
                CALLBACK_ANSWER = ptr::null_mut();
                FIND_MAP = ptr::null_mut();
                FIND_KEY.clear();
                CALLBACK_WORD = 0;
                CALLBACK_ARGUMENT = ptr::null_mut();
                CALLBACK_CALLS = 0;
                STRING_ARENA_USED = 0;
                let heap_ops = ptr::addr_of_mut!(HEAP_OPS);
                (*heap_ops).alloc = string_arena_alloc;
                (*heap_ops).free = string_arena_free;
                (*heap_ops).create = string_arena_create;
                ptr::write_volatile(
                    ptr::addr_of_mut!(COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS),
                    CommandDispatchByNameSingleArgOps {
                        find: mock_find,
                        invoke: mock_invoke,
                    },
                );
            }
        }
        Bench {
            _lock: lock,
            previous_ops,
            _heap_guard: heap_guard,
            available,
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            if self.available {
                unsafe {
                    ptr::write_volatile(
                        ptr::addr_of_mut!(COMMAND_DISPATCH_BY_NAME_SINGLE_ARG_OPS),
                        self.previous_ops,
                    );
                }
            }
        }
    }

    #[test]
    fn hit_looks_up_name_and_forwards_the_distinct_callback_argument() {
        let bench = bench();
        if !bench.available {
            return;
        }

        unsafe {
            (*dispatcher()).map_end = end() as usize as u32;
            (*record()).callback = 0x1bad_b002;
            FOUND = record().cast();
            CALLBACK_ANSWER = slab().add(ANSWER_OFFSET);
            let argument = slab().add(ARGUMENT_OFFSET);

            let result = command_dispatch_by_name_single_arg(
                dispatcher().cast(),
                b"MediaNowPlayingCntlr\0".as_ptr(),
                argument,
            );

            assert_eq!(result, CALLBACK_ANSWER);
            assert_eq!(FIND_MAP, (*dispatcher()).map.as_mut_ptr().cast());
            assert_eq!(FIND_KEY, b"MediaNowPlayingCntlr");
            assert_eq!(CALLBACK_CALLS, 1);
            assert_eq!(CALLBACK_WORD, 0x1bad_b002);
            assert_eq!(CALLBACK_ARGUMENT, argument);
        }
    }

    #[test]
    fn miss_returns_null_without_invoking_a_callback() {
        let bench = bench();
        if !bench.available {
            return;
        }

        unsafe {
            (*dispatcher()).map_end = end() as usize as u32;
            FOUND = end();

            let result = command_dispatch_by_name_single_arg(
                dispatcher().cast(),
                b"AbsentController\0".as_ptr(),
                slab().add(ARGUMENT_OFFSET),
            );

            assert!(result.is_null());
            assert_eq!(FIND_KEY, b"AbsentController");
            assert_eq!(CALLBACK_CALLS, 0);
        }
    }
}
