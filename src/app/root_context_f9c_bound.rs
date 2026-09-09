//! Root-context `+0xf9c` bound-object construction.
//!
//! Port: [`root_context_f9c_bound_construct`] — original: `FUN_08168a8c` @
//! `0x08168a8c` (56 bytes: 48 bytes of code plus the two literal-pool words
//! at `0x08168ac4` and `0x08168ac8;` the next separately linked function
//! begins at `0x08168acc`).
//!
//! The constructor first calls the unported 0x48-byte base constructor
//! `FUN_0813e9ec(this, 0, 0)`. It uses that returned pointer, replaces its
//! vtable with the literal `0x089880f0`, copies the word at
//! `(*APP_ROOT_OBJECT + 0x30) + 0xf9c` to `+0x40`, then writes its byte mode
//! at `+0x44`. The object and vtable class names cannot be recovered: the
//! static vtable address contains C++ name-blob text rather than a valid
//! table, so this port deliberately names only the observable root-context
//! binding and does not invent a class identity.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` found 14 inbound direct
//! `bl` sites, all unconditional with no predicated `bl`, and one
//! unconditional tail `b` at `0x0825a024`.
//!
//! Deliberate deviation: `FUN_0813e9ec` is not yet ported. Device builds call
//! its retailOS load address; host tests replace the volatile boundary with a
//! recording implementation. The app-root global is the existing crate static
//! model of the runtime-initialized word at `0x089ca674`.

use crate::app::context_scope::app_root_object;

/// Literal vtable value loaded from the pool word at `0x08168ac4`.
pub const ROOT_CONTEXT_F9C_BOUND_VTABLE: u32 = 0x0898_80f0;

/// RetailOS entry address of the unported base constructor.
pub const ROOT_CONTEXT_F9C_BOUND_BASE_CONSTRUCT_ADDRESS: usize = 0x0813_e9ec;

const ROOT_CONTEXT_WORD_INDEX: usize = 0x30 / core::mem::size_of::<u32>();
const ROOT_CONTEXT_F9C_WORD_INDEX: usize = 0xf9c / core::mem::size_of::<u32>();

/// The 0x48-byte derived object as observed by this constructor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RootContextF9cBound {
    /// +0x00: replaced with [`ROOT_CONTEXT_F9C_BOUND_VTABLE`].
    pub vtable: u32,
    /// +0x04..+0x3f: initialized only by the base constructor.
    pub base_state: [u8; 0x3c],
    /// +0x40: copied from root context `+0xf9c`.
    pub root_context_f9c: u32,
    /// +0x44: constructor mode, copied from r1's low byte.
    pub mode: u8,
    /// +0x45..+0x47: untouched by this derived constructor.
    pub trailing: [u8; 3],
}

const _: [u8; 0x48] = [0; core::mem::size_of::<RootContextF9cBound>()];

/// ABI of the unported `FUN_0813e9ec` base constructor.
pub type RootContextF9cBoundBaseConstruct = unsafe extern "C" fn(
    *mut RootContextF9cBound,
    u8,
    u32,
) -> *mut RootContextF9cBound;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_root_context_f9c_bound_base_construct(
    this: *mut RootContextF9cBound,
    kind: u8,
    flags: u32,
) -> *mut RootContextF9cBound {
    let construct: RootContextF9cBoundBaseConstruct =
        core::mem::transmute(ROOT_CONTEXT_F9C_BOUND_BASE_CONSTRUCT_ADDRESS);
    construct(this, kind, flags)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_root_context_f9c_bound_base_construct(
    _this: *mut RootContextF9cBound,
    _kind: u8,
    _flags: u32,
) -> *mut RootContextF9cBound {
    panic!("root_context_f9c_bound_construct requires base constructor 0x0813e9ec")
}

/// Active boundary for the unported base constructor.
#[cfg(target_os = "none")]
pub static mut ROOT_CONTEXT_F9C_BOUND_BASE_CONSTRUCT: RootContextF9cBoundBaseConstruct =
    retail_root_context_f9c_bound_base_construct;

/// Active host boundary for the unported base constructor.
#[cfg(not(target_os = "none"))]
pub static mut ROOT_CONTEXT_F9C_BOUND_BASE_CONSTRUCT: RootContextF9cBoundBaseConstruct =
    missing_root_context_f9c_bound_base_construct;

#[inline(always)]
unsafe fn root_context_f9c_bound_base_construct() -> RootContextF9cBoundBaseConstruct {
    core::ptr::read_volatile(core::ptr::addr_of!(ROOT_CONTEXT_F9C_BOUND_BASE_CONSTRUCT))
}

/// root_context_f9c_bound_construct — original: `FUN_08168a8c` @
/// `0x08168a8c` (56 bytes).
///
/// Calls the base constructor with zero kind and flags, replaces the returned
/// object's vtable, snapshots the root context's `+0xf9c` word, and writes
/// `mode` at `+0x44`. Neither the base result nor either root-context pointer
/// is NULL-checked, matching the ARM loads and stores.
///
/// # Safety
///
/// `this` must meet `FUN_0813e9ec`'s 0x48-byte base-object requirements. Its
/// returned pointer must name a writable [`RootContextF9cBound`]. The runtime
/// app root, its `+0x30` u32 pointer, and that object's `+0xf9c` word must be
/// aligned and readable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn root_context_f9c_bound_construct(
    this: *mut RootContextF9cBound,
    mode: u8,
) -> *mut RootContextF9cBound {
    let bound = root_context_f9c_bound_base_construct()(this, 0, 0);
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*bound).vtable),
        ROOT_CONTEXT_F9C_BOUND_VTABLE,
    );

    let root_context = (app_root_object() as *const u32)
        .add(ROOT_CONTEXT_WORD_INDEX)
        .read() as usize as *const u32;
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*bound).root_context_f9c),
        root_context.add(ROOT_CONTEXT_F9C_WORD_INDEX).read(),
    );
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*bound).mode), mode);
    bound
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::context_scope::APP_ROOT_OBJECT;
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, APP_ROOT_TEST_LOCK,
    };
    use core::ptr;

    static mut BASE_CALLS: u32 = 0;
    static mut BASE_INPUTS: [*mut RootContextF9cBound; 2] = [ptr::null_mut(); 2];
    static mut BASE_RETURN: *mut RootContextF9cBound = ptr::null_mut();

    unsafe extern "C" fn recording_base_construct(
        this: *mut RootContextF9cBound,
        kind: u8,
        flags: u32,
    ) -> *mut RootContextF9cBound {
        assert_eq!(kind, 0);
        assert_eq!(flags, 0);
        let call = BASE_CALLS as usize;
        BASE_INPUTS[call] = this;
        BASE_CALLS += 1;
        BASE_RETURN
    }

    struct Restore {
        root: *mut u8,
        base_construct: RootContextF9cBoundBaseConstruct,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                APP_ROOT_OBJECT = self.root;
                ROOT_CONTEXT_F9C_BOUND_BASE_CONSTRUCT = self.base_construct;
                BASE_CALLS = 0;
                BASE_INPUTS = [ptr::null_mut(); 2];
                BASE_RETURN = ptr::null_mut();
            }
        }
    }

    fn object(vtable: u32, value: u32, mode: u8, trailing: [u8; 3]) -> RootContextF9cBound {
        RootContextF9cBound {
            vtable,
            base_state: [0xa5; 0x3c],
            root_context_f9c: value,
            mode,
            trailing,
        }
    }

    #[test]
    fn uses_the_base_return_and_snapshots_root_context_for_byte_mode_extremes() {
        let _guard = APP_ROOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slab) = try_map_u32_slab(hints::ROOT_CONTEXT_F9C_BOUND, 0x3000) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let root = slab;
        let context = unsafe { slab.add(0x1000) };
        let previous_root = unsafe { APP_ROOT_OBJECT };
        unsafe {
            root.cast::<u32>().add(ROOT_CONTEXT_WORD_INDEX).write(context as usize as u32);
        }

        let mut input = object(0x1111_1111, 0x2222_2222, 0x33, [0x44; 3]);
        let mut returned = object(0x5555_5555, 0x6666_6666, 0x77, [0x88; 3]);
        let restore = unsafe {
            let restore = Restore {
                root: previous_root,
                base_construct: ROOT_CONTEXT_F9C_BOUND_BASE_CONSTRUCT,
            };
            APP_ROOT_OBJECT = root;
            ROOT_CONTEXT_F9C_BOUND_BASE_CONSTRUCT = recording_base_construct;
            BASE_RETURN = ptr::addr_of_mut!(returned);
            restore
        };

        unsafe {
            context.cast::<u32>().add(ROOT_CONTEXT_F9C_WORD_INDEX).write(u32::MAX);
            let result = root_context_f9c_bound_construct(ptr::addr_of_mut!(input), u8::MAX);
            assert_eq!(result, ptr::addr_of_mut!(returned));
            assert_eq!(BASE_CALLS, 1);
            assert_eq!(BASE_INPUTS[0], ptr::addr_of_mut!(input));
            assert_eq!(input.vtable, 0x1111_1111, "writes follow the base return, not its input");
            assert_eq!(returned.vtable, ROOT_CONTEXT_F9C_BOUND_VTABLE);
            assert_eq!(returned.root_context_f9c, u32::MAX);
            assert_eq!(returned.mode, u8::MAX);
            assert_eq!(returned.trailing, [0x88; 3], "does not write past +0x44");

            context.cast::<u32>().add(ROOT_CONTEXT_F9C_WORD_INDEX).write(0);
            BASE_RETURN = ptr::addr_of_mut!(input);
            let result = root_context_f9c_bound_construct(ptr::addr_of_mut!(returned), 0);
            assert_eq!(result, ptr::addr_of_mut!(input));
            assert_eq!(BASE_CALLS, 2);
            assert_eq!(BASE_INPUTS[1], ptr::addr_of_mut!(returned));
            assert_eq!(input.vtable, ROOT_CONTEXT_F9C_BOUND_VTABLE);
            assert_eq!(input.root_context_f9c, 0);
            assert_eq!(input.mode, 0);
            assert_eq!(input.trailing, [0x44; 3], "the byte store preserves trailing padding");
        }

        drop(restore);
    }
}
