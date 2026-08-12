//! `silver_controller_transition_addon_destroy` — original:
//! `FUN_08278f60` @ 0x08278f60 (52 bytes: 48 code bytes plus the
//! 4-byte derived-class literal-pool word at 0x08278f94; 55 `bl` call
//! sites, binary-scanned).
//!
//! Source: `ipod-decomp/decomp/c/026/08278f60_FUN_08278f60.c`.
//!
//! The plain destructor of retailOS's as-yet-unidentified Silver-controller
//! transition-addon class. Its evidence-based name comes from the base-class
//! descriptor planted at +0 by the base constructor/destructor: the literal
//! 0x0898994c begins `TSilverCntlrTransitionAddon...`; the derived vtable
//! literal is 0x089a60bc. The paired constructor @ 0x08278e8c and all sampled
//! call sites establish the object as a scoped C++ object, not a deleting
//! destructor: callers construct it in caller-owned storage and later invoke
//! this function without an operator-delete call.
//!
//! Decoded from the raw ARM, rather than Ghidra's folded tail call:
//!
//! ```text
//! 08278f60: push {r4,lr}
//! 08278f64: mov  r4,r0
//! 08278f68: ldr  r0,[0x8278f94]       ; 0x089a60bc, derived vtable
//! 08278f6c: str  r0,[r4]
//! 08278f70: mov  r0,r4
//! 08278f74: bl   0x08278894           ; derived cleanup
//! 08278f78: add  r0,r4,#0x40
//! 08278f7c: bl   0x08278190           ; embedded vector destructor
//! 08278f80: sub  r0,r0,#0x34          ; its result -> StringObject +0x0c
//! 08278f84: bl   0x082792fc           ; string_object_destroy veneer
//! 08278f88: pop  {r4,lr}
//! 08278f8c: sub  r0,r0,#0x0c          ; StringObject result -> this
//! 08278f90: b    0x0818a0fc           ; base destructor tail call
//! ```
//!
//! The tail target @ 0x0818a0fc installs the base descriptor/vtable
//! 0x0898994c, then calls `FUN_081e1fe8(this[1] + 0x24, this)` and returns
//! `this`. Ghidra inlines that target into `FUN_08278f60`, which is why its
//! decompile appears to contain both stores and the final call. This port
//! makes that tail body explicit: it preserves the true dataflow through the
//! embedded vector destructor's return (`-0x34`) and the StringObject
//! destructor's return (`-0x0c`) before running the base teardown.
//!
//! Layout evidence from the paired constructor @ 0x08278e8c: a base
//! transition-addon subobject begins at +0x00; its owner pointer is +0x04;
//! the embedded [`StringObject`] begins at +0x0c; and the vector-like member
//! begins at +0x40 (its begin/end/capacity words are +0x48/+0x4c/+0x50).
//! `FUN_08278190` walks and releases that member's elements, returning its
//! argument. `FUN_08278894` performs derived cleanup before either member is
//! destroyed.
//!
//! Deviation: derived cleanup, vector destruction, and base deregistration
//! remain unported, so they cross [`TRANSITION_ADDON_DESTROY_OPS`] dispatch
//! slots. The vector default faithfully returns its argument but performs no
//! element destruction; the other defaults are no-ops. Consequently this
//! function is **not hook-ready** until those three callees are ported and
//! wired in. The raw target uses 32-bit words; raw object slots here use
//! pointer-sized unaligned reads/writes so the 32-bit offsets remain distinct
//! and testable on a 64-bit host (the crate's face-word model).

use super::string_object::{string_object_destroy_veneer, StringObject};

/// Literal-pool word at 0x08278f94, installed before derived cleanup.
pub const TRANSITION_ADDON_VTABLE_ADDRESS: usize = 0x089a_60bc;
/// Literal-pool word at 0x0818a124, installed by the base destructor.
pub const TRANSITION_ADDON_BASE_VTABLE_ADDRESS: usize = 0x0898_994c;

/// Byte offset of the owner pointer in the base transition-addon subobject.
pub const TRANSITION_ADDON_OWNER_OFFSET: usize = 0x04;
/// Byte offset of the embedded [`StringObject`] member.
pub const TRANSITION_ADDON_STRING_OFFSET: usize = 0x0c;
/// Byte offset of the vector-like member destroyed first.
pub const TRANSITION_ADDON_VECTOR_OFFSET: usize = 0x40;
/// The vector destructor result is this many bytes after the StringObject.
pub const VECTOR_RESULT_TO_STRING_OFFSET: usize = 0x34;
/// The StringObject destructor result is this many bytes after the outer object.
pub const STRING_RESULT_TO_OBJECT_OFFSET: usize = 0x0c;
/// The base destructor passes its owner's +0x24 member to deregistration.
pub const TRANSITION_ADDON_OWNER_MEMBER_OFFSET: usize = 0x24;

#[inline(always)]
unsafe fn read_u32_unaligned(address: *const u8) -> u32 {
    (address as *const u32).read_unaligned()
}

#[inline(always)]
unsafe fn write_u32_unaligned(address: *mut u8, value: u32) {
    (address as *mut u32).write_unaligned(value);
}

#[inline(always)]
unsafe fn read_word_unaligned(address: *const u8) -> usize {
    (address as *const usize).read_unaligned()
}

#[inline(always)]
unsafe fn write_word_unaligned(address: *mut u8, value: usize) {
    (address as *mut usize).write_unaligned(value);
}

/// Dispatch boundaries for the three unported calls in
/// [`silver_controller_transition_addon_destroy`].
#[derive(Clone, Copy)]
pub struct TransitionAddonDestroyOps {
    /// `FUN_08278894`: releases the derived class's own state before member
    /// destructors run; its return value is ignored by the caller.
    pub derived_cleanup: unsafe extern "C" fn(this: *mut u8),
    /// `FUN_08278190`: destroys the vector-like member at `this+0x40` and
    /// returns that member pointer. The caller derives the StringObject
    /// address from this *returned* pointer, not from its entry `this`.
    pub vector_destroy: unsafe extern "C" fn(member: *mut u8) -> *mut u8,
    /// `FUN_081e1fe8`, reached by the base destructor @ 0x0818a0fc with the
    /// owner's +0x24 member and the outer transition-addon object.
    pub base_deregister: unsafe extern "C" fn(owner_member: *mut u8, this: *mut u8),
}

unsafe extern "C" fn derived_cleanup_unported(_this: *mut u8) {}

/// The fully decoded vector destructor returns its entry pointer; its element
/// destruction is not yet available, so the default preserves just that
/// caller-visible return convention.
unsafe extern "C" fn vector_destroy_unported(member: *mut u8) -> *mut u8 {
    member
}

unsafe extern "C" fn base_deregister_unported(_owner_member: *mut u8, _this: *mut u8) {}

/// Wired defaults for the unresolved teardown boundaries.
pub const DEFAULT_TRANSITION_ADDON_DESTROY_OPS: TransitionAddonDestroyOps =
    TransitionAddonDestroyOps {
        derived_cleanup: derived_cleanup_unported,
        vector_destroy: vector_destroy_unported,
        base_deregister: base_deregister_unported,
    };

/// Active teardown boundaries. Host tests replace these slots with recording
/// mocks; future callee ports replace the defaults without changing this
/// destructor's offset/dataflow contract.
pub static mut TRANSITION_ADDON_DESTROY_OPS: TransitionAddonDestroyOps =
    DEFAULT_TRANSITION_ADDON_DESTROY_OPS;

#[inline(always)]
unsafe fn derived_cleanup_op() -> unsafe extern "C" fn(*mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_DESTROY_OPS.derived_cleanup
    ))
}

#[inline(always)]
unsafe fn vector_destroy_op() -> unsafe extern "C" fn(*mut u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_DESTROY_OPS.vector_destroy
    ))
}

#[inline(always)]
unsafe fn base_deregister_op() -> unsafe extern "C" fn(*mut u8, *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_DESTROY_OPS.base_deregister
    ))
}

/// silver_controller_transition_addon_destroy — original: `FUN_08278f60` @
/// 0x08278f60 (52 bytes; 55 `bl` call sites).
///
/// Plain destructor for a caller-owned Silver-controller transition addon.
/// Installs the derived vtable, performs derived cleanup, destroys the
/// vector-like member at +0x40, then derives and destroys the `StringObject`
/// member from that destructor chain's returns. It finally runs the base
/// destructor body: installs the base vtable and deregisters `this` through
/// the owner's +0x24 member. Returns the recovered `this` pointer. There is
/// no NULL guard, matching every unconditional object access in the ARM.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn silver_controller_transition_addon_destroy(
    this: *mut u8,
) -> *mut u8 {
    write_u32_unaligned(this, TRANSITION_ADDON_VTABLE_ADDRESS as u32);
    derived_cleanup_op()(this);

    let vector = vector_destroy_op()(this.add(TRANSITION_ADDON_VECTOR_OFFSET));
    let string = vector
        .sub(VECTOR_RESULT_TO_STRING_OFFSET)
        .cast::<StringObject>();
    let string = string_object_destroy_veneer(string).cast::<u8>();
    let this = string.sub(STRING_RESULT_TO_OBJECT_OFFSET);

    write_u32_unaligned(this, TRANSITION_ADDON_BASE_VTABLE_ADDRESS as u32);
    let owner = read_word_unaligned(this.add(TRANSITION_ADDON_OWNER_OFFSET)) as *mut u8;
    base_deregister_op()(owner.add(TRANSITION_ADDON_OWNER_MEMBER_OFFSET), this);
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::{sync::{Mutex, MutexGuard}, vec, vec::Vec};

    static DESTROY_OPS_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        Derived { this: usize, vtable: usize },
        Vector { member: usize },
        Deregister { owner_member: usize, this: usize },
    }

    static mut CALLS: Vec<Call> = Vec::new();
    static mut VECTOR_RETURN: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_derived_cleanup(this: *mut u8) {
        (*core::ptr::addr_of_mut!(CALLS)).push(Call::Derived {
            this: this as usize,
            vtable: read_u32_unaligned(this) as usize,
        });
    }

    unsafe extern "C" fn recording_vector_destroy(member: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(CALLS)).push(Call::Vector {
            member: member as usize,
        });
        core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_RETURN))
    }

    unsafe extern "C" fn recording_base_deregister(owner_member: *mut u8, this: *mut u8) {
        (*core::ptr::addr_of_mut!(CALLS)).push(Call::Deregister {
            owner_member: owner_member as usize,
            this: this as usize,
        });
    }

    struct DestroyOpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for DestroyOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(TRANSITION_ADDON_DESTROY_OPS)
                    .write_volatile(DEFAULT_TRANSITION_ADDON_DESTROY_OPS);
            }
        }
    }

    fn install_recorders(vector_return: *mut u8) -> DestroyOpsGuard {
        let lock = DESTROY_OPS_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(VECTOR_RETURN).write(vector_return);
            core::ptr::addr_of_mut!(TRANSITION_ADDON_DESTROY_OPS).write_volatile(
                TransitionAddonDestroyOps {
                    derived_cleanup: recording_derived_cleanup,
                    vector_destroy: recording_vector_destroy,
                    base_deregister: recording_base_deregister,
                },
            );
        }
        DestroyOpsGuard { _lock: lock }
    }

    fn calls() -> Vec<Call> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    #[repr(align(8))]
    struct Object([u8; 0x100]);

    #[test]
    fn destroy_routes_all_offsets_and_vtable_transitions_through_callee_returns() {
        let mut object = Object([0; 0x100]);
        let this = object.0.as_mut_ptr();

        // The vector mock returns a deliberately shifted member pointer. The
        // final result therefore proves both original container-of steps:
        // vector result - 0x34 -> StringObject, then string result - 0x0c
        // -> outer object. Keeping that StringObject 8-aligned also gives the
        // real, already-ported StringObject destructor a valid host object.
        let vector_return = unsafe { this.add(0x74) };
        let expected_string = unsafe { vector_return.sub(VECTOR_RESULT_TO_STRING_OFFSET) };
        let expected_this = unsafe { expected_string.sub(STRING_RESULT_TO_OBJECT_OFFSET) };
        let owner = 0x1234_5000usize as *mut u8;
        unsafe {
            write_word_unaligned(expected_this.add(TRANSITION_ADDON_OWNER_OFFSET), owner as usize);
        }
        let _guard = install_recorders(vector_return);

        let returned = unsafe { silver_controller_transition_addon_destroy(this) };

        assert_eq!(returned, expected_this);
        assert_eq!(
            calls(),
            vec![
                Call::Derived {
                    this: this as usize,
                    vtable: TRANSITION_ADDON_VTABLE_ADDRESS,
                },
                Call::Vector {
                    member: unsafe { this.add(TRANSITION_ADDON_VECTOR_OFFSET) } as usize,
                },
                Call::Deregister {
                    owner_member: unsafe { owner.add(TRANSITION_ADDON_OWNER_MEMBER_OFFSET) } as usize,
                    this: expected_this as usize,
                },
            ]
        );
        assert_eq!(
            unsafe { read_u32_unaligned(expected_this) as usize },
            TRANSITION_ADDON_BASE_VTABLE_ADDRESS,
            "the tail base destructor replaces the derived vtable"
        );
        assert_eq!(
            unsafe { read_word_unaligned(expected_string) },
            &super::super::string_object::STRING_OBJECT_VTABLE as *const _ as usize,
            "the direct StringObject veneer received vector_return - 0x34"
        );
    }

    #[test]
    fn default_unported_boundaries_preserve_the_destructor_dataflow() {
        let mut object = Object([0xa5; 0x100]);
        // With the default vector-return stub, string = this+0x0c. Offset the
        // host fixture by four bytes so that the embedded pointer-sized object
        // is naturally aligned on the 64-bit test host while retaining every
        // target byte offset.
        let this = unsafe { object.0.as_mut_ptr().add(4) };
        let owner = 0x7654_3000usize as *mut u8;
        unsafe {
            write_word_unaligned(this.add(TRANSITION_ADDON_OWNER_OFFSET), owner as usize);
            // The already-ported StringObject destructor reaches this host
            // payload field at string+8; make it NULL so no heap boundary is
            // intentionally exercised by this default-seam test.
            write_word_unaligned(this.add(TRANSITION_ADDON_STRING_OFFSET + 8), 0);
        }

        let returned = unsafe { silver_controller_transition_addon_destroy(this) };

        assert_eq!(returned, this);
        assert_eq!(
            unsafe { read_u32_unaligned(this) as usize },
            TRANSITION_ADDON_BASE_VTABLE_ADDRESS
        );
        assert_eq!(
            unsafe { read_word_unaligned(this.add(TRANSITION_ADDON_STRING_OFFSET)) },
            &super::super::string_object::STRING_OBJECT_VTABLE as *const _ as usize
        );
    }
}
