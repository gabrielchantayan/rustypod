//! Constructor for named registration nodes shared by application objects.

use core::ptr;

/// The base-node vtable loaded from the literal pool of `0x08207674`.
pub const BASE_VTABLE_ADDRESS: u32 = 0x0899_19a8;
/// The derived-node vtable loaded from the literal pool of this constructor.
pub const VTABLE_ADDRESS: u32 = 0x0898_f1b4;

/// The unported base constructor's ABI.
#[derive(Clone, Copy)]
pub struct RegistrationNodeOps {
    /// `FUN_08207674`: stores the base vtable at `this + 0x00`, stores
    /// `name` at `this + 0x04`, and returns `this` in retailOS.
    pub construct_base: unsafe extern "C" fn(this: *mut u8, name: *const u8) -> *mut u8,
}

/// Binary-verified default boundary for the unported base constructor.
///
/// This is `ldr r2, [pc, #8]; str r1, [r0, #4]; str r2, [r0]; bx lr` from
/// `0x08207674`, including its target-width name-pointer store.
unsafe extern "C" fn default_construct_base(this: *mut u8, name: *const u8) -> *mut u8 {
    unsafe {
        this.cast::<u32>().write(BASE_VTABLE_ADDRESS);
        this.add(4).cast::<u32>().write(name as usize as u32);
    }
    this
}

/// Default operations until `FUN_08207674` has its own port.
pub const DEFAULT_REGISTRATION_NODE_OPS: RegistrationNodeOps = RegistrationNodeOps {
    construct_base: default_construct_base,
};

/// Active boundary for the registration-node base constructor.
pub static mut REGISTRATION_NODE_OPS: RegistrationNodeOps = DEFAULT_REGISTRATION_NODE_OPS;

#[inline(always)]
unsafe fn ops() -> RegistrationNodeOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(REGISTRATION_NODE_OPS)) }
}

/// registration_node_construct — retailOS `FUN_081e73f8` @ **0x081e73f8**
/// (**32 bytes**, including the trailing vtable literal; **6 direct
/// unconditional `bl` call sites**, zero predicated forms, binary-scanned
/// over all ARM B/BL immediates in `osos.dec`).
///
/// Constructs a named registration node: invokes base constructor `0x08207674`
/// with `(this, name)`, overwrites the returned node's vtable with
/// `0x0898f1b4`, and stores `owner` at target offset `+0x08`. It returns the
/// base constructor's result. The constructor deliberately neither validates
/// `this` nor preserves a distinct incoming pointer after the base call;
/// retailOS writes through `r0` returned by the base constructor.
///
/// Deliberate deviation: the still-unported base constructor is represented by
/// a replaceable, binary-verified boundary. Its default has the retail base's
/// exact two target-word stores and return value.
///
/// # Safety
///
/// `this` and any pointer returned by the installed base constructor must
/// address at least 12 writable bytes, aligned for target-width words. `owner`
/// is a target pointer word, not a host pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registration_node_construct(
    this: *mut u8,
    owner: u32,
    name: *const u8,
) -> *mut u8 {
    let node = unsafe { (ops().construct_base)(this, name) };
    unsafe {
        ptr::write_volatile(node.cast::<u32>(), VTABLE_ADDRESS);
        ptr::write_volatile(node.add(8).cast::<u32>(), owner);
    }
    node
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut BASE_CALL: Option<(usize, usize)> = None;
    static mut BASE_RETURN: *mut u8 = ptr::null_mut();

    struct Restore;

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(REGISTRATION_NODE_OPS).write(DEFAULT_REGISTRATION_NODE_OPS) }
        }
    }

    unsafe extern "C" fn recording_base(this: *mut u8, name: *const u8) -> *mut u8 {
        unsafe {
            ptr::addr_of_mut!(BASE_CALL).write(Some((this as usize, name as usize)));
            ptr::read_volatile(ptr::addr_of!(BASE_RETURN))
        }
    }

    #[repr(C, align(4))]
    struct Node([u32; 4]);

    #[test]
    fn default_base_names_the_node_then_derived_fields_overwrite_only_words_zero_and_two() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _restore = Restore;
        let mut node = Node([0xfeed_face, 0xdead_beef, 0xabcd_0123, 0x1020_3040]);
        let name = b"TNotesApp\0";

        let returned = unsafe {
            registration_node_construct(node.0.as_mut_ptr().cast(), 0xcafe_babe, name.as_ptr())
        };

        assert_eq!(returned, node.0.as_mut_ptr().cast());
        assert_eq!(node.0[0], VTABLE_ADDRESS, "derived vtable replaces the base vtable");
        assert_eq!(node.0[1], name.as_ptr() as usize as u32, "base stores the name word");
        assert_eq!(node.0[2], 0xcafe_babe, "owner is the third target word");
        assert_eq!(node.0[3], 0x1020_3040, "the constructor does not clear adjacent state");
    }

    #[test]
    fn stores_on_the_base_return_value_and_forwards_it() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _restore = Restore;
        let mut input = Node([0x11; 4]);
        let mut returned_node = Node([0x22, 0x33, 0x44, 0x55]);
        let name = b"MeCCA RecordingBuffer\0";
        unsafe {
            ptr::addr_of_mut!(BASE_CALL).write(None);
            ptr::addr_of_mut!(BASE_RETURN).write(returned_node.0.as_mut_ptr().cast());
            ptr::addr_of_mut!(REGISTRATION_NODE_OPS).write(RegistrationNodeOps {
                construct_base: recording_base,
            });
        }

        let returned = unsafe {
            registration_node_construct(input.0.as_mut_ptr().cast(), 0x0bad_f00d, name.as_ptr())
        };

        assert_eq!(unsafe { BASE_CALL }, Some((input.0.as_mut_ptr() as usize, name.as_ptr() as usize)));
        assert_eq!(returned, returned_node.0.as_mut_ptr().cast());
        assert_eq!(returned_node.0, [VTABLE_ADDRESS, 0x33, 0x0bad_f00d, 0x55]);
        assert_eq!(input.0, [0x11; 4], "writes follow the base r0, not the original this");
    }
}
