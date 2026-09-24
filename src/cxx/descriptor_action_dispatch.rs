//! Descriptor action dispatch — original: `FUN_0806e95c` @ load address
//! `0x0806e95c` (84 bytes; `0x0806e95c..0x0806e9af`). Raw words establish
//! the next real function at `0x0806e9b0`.
//!
//! Raw ARM decoding finds two direct plain `bl` instructions, no predicated
//! `bl` instructions, and one indirect `blx` through action word `+0x14`.
//! The function resolves an opaque descriptor action from the owner, copies
//! source word `+0x08` to a stack-local argument, then either dispatches the
//! action callback when its word `+0x08` is clear or invokes the already
//! ported generic descriptor lookup with that word as its descriptor.
//!
//! Deliberate deviations: the action resolver at `0x0806e9b0` and the virtual
//! callback have no recovered identities, so host builds use typed seams.
//! Target pointers remain 32-bit words; host seams avoid treating 64-bit host
//! function pointers as ARM object fields.

#[cfg(not(target_os = "none"))]
use super::generic_descriptor_lookup::generic_descriptor_lookup;

type DescriptorActionLookup = unsafe extern "C" fn(*mut u32) -> *mut u32;
type DescriptorActionDispatch = unsafe extern "C" fn(*mut u32, *mut u32, u32) -> u32;

const ACTION_DESCRIPTOR_WORD: usize = 2;
const ACTION_CALLBACK_WORD: usize = 5;
const OWNER_SOURCE_WORD: usize = 2;
const SOURCE_INPUT_LENGTH_WORD: usize = 0;
const SOURCE_ARGUMENT_WORD: usize = 2;
#[cfg(target_os = "none")]
unsafe fn run_generic_descriptor_lookup(
    output: *mut u32, input: *mut u8, input_length: u32, descriptor: *mut u8,
) -> *mut u8 {
    unsafe extern "C" {
        fn generic_descriptor_lookup(
            output: *mut u32, input: *mut u8, input_length: u32, descriptor: *mut u8,
        ) -> *mut u8;
    }
    unsafe { generic_descriptor_lookup(output, input, input_length, descriptor) }
}

#[cfg(not(target_os = "none"))]
unsafe fn run_generic_descriptor_lookup(
    output: *mut u32, input: *mut u8, input_length: u32, descriptor: *mut u8,
) -> *mut u8 {
    unsafe { generic_descriptor_lookup(output, input, input_length, descriptor) }
}


#[cfg(target_os = "none")]
unsafe fn resolve_descriptor_action(owner: *mut u32) -> *mut u32 {
    let lookup: unsafe extern "C" fn(*mut u32) -> u32 = unsafe { core::mem::transmute(0x0806_e9b0usize) };
    unsafe { lookup(owner) as usize as *mut u32 }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_descriptor_action_lookup(_owner: *mut u32) -> *mut u32 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
pub static mut DESCRIPTOR_ACTION_LOOKUP: DescriptorActionLookup = missing_descriptor_action_lookup;

#[cfg(not(target_os = "none"))]
unsafe fn resolve_descriptor_action(owner: *mut u32) -> *mut u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DESCRIPTOR_ACTION_LOOKUP))(owner) }
}

#[cfg(target_os = "none")]
unsafe fn dispatch_descriptor_action(action: *mut u32, argument: *mut u32, input_length: u32) {
    let callback: DescriptorActionDispatch = unsafe {
        core::mem::transmute(action.add(ACTION_CALLBACK_WORD).read_volatile() as usize)
    };
    unsafe { callback(core::ptr::null_mut(), argument, input_length); }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_descriptor_action_dispatch(_action: *mut u32, _argument: *mut u32, _input_length: u32) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
pub static mut DESCRIPTOR_ACTION_DISPATCH: DescriptorActionDispatch = missing_descriptor_action_dispatch;

#[cfg(not(target_os = "none"))]
unsafe fn dispatch_descriptor_action(action: *mut u32, argument: *mut u32, input_length: u32) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DESCRIPTOR_ACTION_DISPATCH))(action, argument, input_length); }
}

/// Resolves an owner's descriptor action and either invokes it or parses its argument.
///
/// # Safety
///
/// `owner` must have an ARM-layout source pointer at word `+0x08`. When the
/// action resolver succeeds, both its descriptor/action object and the source
/// object must expose the words consumed by the selected firmware path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn descriptor_action_dispatch(owner: *mut u32) -> *mut u8 {
    let action = unsafe { resolve_descriptor_action(owner) };
    if action.is_null() {
        return core::ptr::null_mut();
    }

    let source = unsafe { owner.add(OWNER_SOURCE_WORD).read_volatile() as usize as *mut u32 };
    let mut argument = unsafe { source.add(SOURCE_ARGUMENT_WORD).read_volatile() };
    let descriptor = unsafe { action.add(ACTION_DESCRIPTOR_WORD).read_volatile() };
    let input_length = unsafe { source.add(SOURCE_INPUT_LENGTH_WORD).read_volatile() };

    if descriptor != 0 {
        unsafe {
            run_generic_descriptor_lookup(
                core::ptr::null_mut(),
                core::ptr::addr_of_mut!(argument).cast(),
                input_length,
                descriptor as usize as *mut u8,
            )
        }
    } else {
        unsafe { dispatch_descriptor_action(action, core::ptr::addr_of_mut!(argument), input_length); }
        core::ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::DESCRIPTOR_ACTION_DISPATCH, 0x1000).map(|pointer| pointer as usize)
    });
    static ACTION: AtomicUsize = AtomicUsize::new(0);
    static PARSER_RESULT: AtomicU32 = AtomicU32::new(0);
    static PARSER_DESCRIPTOR: AtomicUsize = AtomicUsize::new(0);
    static PARSER_ARGUMENT: AtomicU32 = AtomicU32::new(0);
    static CALLBACK_ARGUMENT: AtomicU32 = AtomicU32::new(0);
    static CALLBACK_LENGTH: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn lookup(_owner: *mut u32) -> *mut u32 {
        ACTION.load(Ordering::SeqCst) as *mut u32
    }

    unsafe extern "C" fn parser(
        output: *mut u32, input: *mut u8, input_length: u32, descriptor: *mut u8,
        _selector: i32, _option_a: u32, _option_b: u32, _status: *mut u8,
    ) -> i32 {
        PARSER_DESCRIPTOR.store(descriptor as usize, Ordering::SeqCst);
        PARSER_ARGUMENT.store((input as *const u32).read(), Ordering::SeqCst);
        assert_eq!(input_length, 7);
        output.write(PARSER_RESULT.load(Ordering::SeqCst));
        1
    }

    unsafe extern "C" fn callback(_receiver: *mut u32, argument: *mut u32, input_length: u32) -> u32 {
        CALLBACK_ARGUMENT.store(argument.read(), Ordering::SeqCst);
        CALLBACK_LENGTH.store(input_length, Ordering::SeqCst);
        0
    }

    struct Seams {
        lookup: DescriptorActionLookup,
        dispatch: DescriptorActionDispatch,
        parser: super::super::generic_descriptor_lookup::DescriptorParser,
    }

    impl Drop for Seams {
        fn drop(&mut self) {
            unsafe {
                DESCRIPTOR_ACTION_LOOKUP = self.lookup;
                DESCRIPTOR_ACTION_DISPATCH = self.dispatch;
                super::super::generic_descriptor_lookup::DESCRIPTOR_PARSER = self.parser;
            }
        }
    }

    fn install(action: *mut u32) -> Seams {
        ACTION.store(action as usize, Ordering::SeqCst);
        PARSER_RESULT.store(0, Ordering::SeqCst);
        PARSER_DESCRIPTOR.store(0, Ordering::SeqCst);
        PARSER_ARGUMENT.store(0, Ordering::SeqCst);
        CALLBACK_ARGUMENT.store(0, Ordering::SeqCst);
        CALLBACK_LENGTH.store(0, Ordering::SeqCst);
        unsafe {
            let seams = Seams {
                lookup: DESCRIPTOR_ACTION_LOOKUP,
                dispatch: DESCRIPTOR_ACTION_DISPATCH,
                parser: super::super::generic_descriptor_lookup::DESCRIPTOR_PARSER,
            };
            DESCRIPTOR_ACTION_LOOKUP = lookup;
            DESCRIPTOR_ACTION_DISPATCH = callback;
            super::super::generic_descriptor_lookup::DESCRIPTOR_PARSER = parser;
            seams
        }
    }

    #[test]
    fn absent_action_returns_null_without_accessing_owner_source() {
        let _lock = LOCK.lock();
        let _seams = install(core::ptr::null_mut());
        assert!(unsafe { descriptor_action_dispatch(core::ptr::null_mut()) }.is_null());
    }

    #[test]
    fn clear_action_dispatches_stack_argument_with_source_length() {
        let _lock = LOCK.lock();
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/descriptor_action_dispatch"));
            return;
        };
        let mut action = [0u32; 6];
        let owner = slab as *mut u32;
        let source = unsafe { owner.add(8) };
        unsafe {
            owner.write_bytes(0, 3);
            source.write(7);
            source.add(SOURCE_ARGUMENT_WORD).write(0xfeed_beef);
            owner.add(OWNER_SOURCE_WORD).write(source as usize as u32);
        }
        let _seams = install(action.as_mut_ptr());

        assert!(unsafe { descriptor_action_dispatch(owner) }.is_null());
        assert_eq!(CALLBACK_ARGUMENT.load(Ordering::SeqCst), 0xfeed_beef);
        assert_eq!(CALLBACK_LENGTH.load(Ordering::SeqCst), 7);
    }

    #[test]
    fn descriptor_action_uses_generic_lookup_result() {
        let _lock = LOCK.lock();
        let _parser_lock = super::super::generic_descriptor_lookup::DESCRIPTOR_PARSER_TEST_LOCK.lock();
        let Some(slab) = *SLAB else {
            assert!(note_missing_u32_fixture("cxx/descriptor_action_dispatch"));
            return;
        };
        let mut action = [0u32; 6];
        action[ACTION_DESCRIPTOR_WORD] = 0x1234_5000;
        let owner = slab as *mut u32;
        let source = unsafe { owner.add(8) };
        unsafe {
            owner.write_bytes(0, 3);
            source.write(7);
            source.add(SOURCE_ARGUMENT_WORD).write(0xfeed_beef);
            owner.add(OWNER_SOURCE_WORD).write(source as usize as u32);
        }
        let _seams = install(action.as_mut_ptr());
        PARSER_RESULT.store(0x7654_3000, Ordering::SeqCst);

        assert_eq!(unsafe { descriptor_action_dispatch(owner) as usize }, 0x7654_3000);
        assert_eq!(PARSER_DESCRIPTOR.load(Ordering::SeqCst), 0x1234_5000);
        assert_eq!(PARSER_ARGUMENT.load(Ordering::SeqCst), 0xfeed_beef);
        assert_eq!(CALLBACK_LENGTH.load(Ordering::SeqCst), 0);
    }
}
