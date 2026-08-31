//! `copy_first_entry_payload` — original: `FUN_08184bd4` @ 0x08184bd4
//! (104 bytes, 0x08184bd4..0x08184c3c; **28 `bl` call sites** found by
//! decoding every ARM B/BL word in `osos.dec`: 27 unconditional and one
//! `blne` at 0x0819ef48).
//!
//! Constructs a temporary vector owner through `FUN_08184b24`, then copies
//! the first entry's 12-byte payload (at entry + 8) to the supplied result.
//! An empty vector instead writes zero to the first two result words and the
//! empty marker 6 to byte +8, deliberately leaving bytes +9..+11 unchanged.
//! The temporary is released through its vtable's +4 slot when non-NULL.
//!
//! `FUN_08184b24` remains unported, so the target default calls its verified
//! load address. Host tests replace it and the dynamic release with recording
//! callbacks. The payload's field meanings are not recovered; this port names
//! only the observable first-entry copy operation.

use crate::cxx::templates::{vector_size_elem4_alias_78c4, VectorBounds};
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::util::ptr_vector::ptr_vector_at;

const VECTOR_OFFSET: usize = 0x14;
const ENTRY_PAYLOAD_OFFSET: usize = 8;
const PAYLOAD_SIZE: usize = 12;

/// Three-word result copied from the first temporary-vector entry.
///
/// The empty path writes `first` and `second` as zero and `kind` as 6, but it
/// intentionally does not write `tail`.
#[repr(C)]
pub struct FirstEntryPayload {
    pub first: u32,
    pub second: u32,
    pub kind: u8,
    pub tail: [u8; 3],
}

/// Calls that the retail function makes outside the already-ported vector and
/// runtime-copy helpers.
#[derive(Clone, Copy)]
pub struct FirstEntryPayloadOps {
    /// `FUN_08184b24(owner_input)`: constructs the temporary vector owner.
    pub create_owner: unsafe extern "C" fn(owner_input: *mut u8) -> *mut u8,
    /// The temporary owner's virtual destructor, loaded from vtable slot +4.
    pub release_owner: unsafe extern "C" fn(owner: *mut u8),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_create_owner(owner_input: *mut u8) -> *mut u8 {
    let create: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        unsafe { core::mem::transmute(0x0818_4b24usize) };
    unsafe { create(owner_input) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_create_owner(_owner_input: *mut u8) -> *mut u8 {
    panic!("copy_first_entry_payload requires temporary-owner factory 0x08184b24")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_release_owner(owner: *mut u8) {
    let vtable = unsafe { (owner as *const u32).read_volatile() as *const u32 };
    let release: unsafe extern "C" fn(*mut u8) =
        unsafe { core::mem::transmute(vtable.add(1).read_volatile() as usize) };
    unsafe { release(owner) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_owner(_owner: *mut u8) {
    panic!("copy_first_entry_payload requires temporary-owner virtual release")
}

#[cfg(target_os = "none")]
pub const DEFAULT_FIRST_ENTRY_PAYLOAD_OPS: FirstEntryPayloadOps = FirstEntryPayloadOps {
    create_owner: firmware_create_owner,
    release_owner: firmware_release_owner,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_FIRST_ENTRY_PAYLOAD_OPS: FirstEntryPayloadOps = FirstEntryPayloadOps {
    create_owner: missing_create_owner,
    release_owner: missing_release_owner,
};

/// Active boundary for the unported temporary-owner factory and its virtual
/// release. The vector-size, vector-access, and runtime-copy calls are
/// already-portable direct calls rather than re-stubbed seams.
pub static mut FIRST_ENTRY_PAYLOAD_OPS: FirstEntryPayloadOps = DEFAULT_FIRST_ENTRY_PAYLOAD_OPS;

#[inline(always)]
unsafe fn first_entry_payload_ops() -> FirstEntryPayloadOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(FIRST_ENTRY_PAYLOAD_OPS)) }
}

/// copy_first_entry_payload — original: `FUN_08184bd4` @ 0x08184bd4
/// (104 bytes; 28 direct `bl` sites, 27 unconditional and `blne` at
/// 0x0819ef48).
///
/// Builds a temporary owner from `owner_input`. When its vector at +0x14 is
/// non-empty, copies 12 bytes from its first entry +8 to `output`; otherwise
/// writes the three-field empty result. It then invokes the temporary owner's
/// vtable +4 release slot when the owner is non-NULL. There is no NULL guard
/// before dereferencing the factory result or a NULL first vector entry,
/// matching the ARM body.
///
/// # Safety
/// `owner_input` must be accepted by the temporary-owner factory, `output`
/// must designate 12 writable bytes, and every object reached by the factory
/// must satisfy the vector and release contracts above.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn copy_first_entry_payload(
    owner_input: *mut u8,
    output: *mut FirstEntryPayload,
) {
    let ops = unsafe { first_entry_payload_ops() };
    let temporary = unsafe { (ops.create_owner)(owner_input) };
    let vector = unsafe { temporary.add(VECTOR_OFFSET) as *const VectorBounds };

    if unsafe { vector_size_elem4_alias_78c4(vector) } == 0 {
        unsafe {
            core::ptr::addr_of_mut!((*output).first).write(0);
            core::ptr::addr_of_mut!((*output).second).write(0);
            core::ptr::addr_of_mut!((*output).kind).write(6);
        }
    } else {
        let first_entry = unsafe { ptr_vector_at(temporary, 0) };
        unsafe {
            __rt_memcpy(
                output.cast::<u8>(),
                first_entry.add(ENTRY_PAYLOAD_OFFSET),
                PAYLOAD_SIZE,
            );
        }
    }

    let release_target = unsafe { core::ptr::addr_of!(temporary).read_volatile() };
    if !release_target.is_null() {
        unsafe { (ops.release_owner)(release_target) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut FACTORY_OWNER: *mut u8 = core::ptr::null_mut();
    static mut FACTORY_INPUT: *mut u8 = core::ptr::null_mut();
    static mut RELEASED_OWNER: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_factory(owner_input: *mut u8) -> *mut u8 {
        unsafe {
            FACTORY_INPUT = owner_input;
            FACTORY_OWNER
        }
    }

    unsafe extern "C" fn record_release(owner: *mut u8) {
        unsafe { RELEASED_OWNER = owner }
    }

    unsafe fn install(owner: *mut u8) {
        unsafe {
            FACTORY_OWNER = owner;
            FACTORY_INPUT = core::ptr::null_mut();
            RELEASED_OWNER = core::ptr::null_mut();
            FIRST_ENTRY_PAYLOAD_OPS = FirstEntryPayloadOps {
                create_owner: record_factory,
                release_owner: record_release,
            };
        }
    }

    unsafe fn restore() {
        unsafe { FIRST_ENTRY_PAYLOAD_OPS = DEFAULT_FIRST_ENTRY_PAYLOAD_OPS }
    }

    /// Host-shaped owner: its vector head starts at the target's +0x14, while
    /// its pointer fields use host width so the direct ported helpers can read
    /// them without truncation.
    #[repr(align(8))]
    struct Owner([u8; VECTOR_OFFSET + 2 * core::mem::size_of::<*mut u8>()]);

    impl Owner {
        fn with_vector(begin: *mut u8, end: *mut u8) -> Self {
            let mut owner = Owner([0xa5; VECTOR_OFFSET + 2 * core::mem::size_of::<*mut u8>()]);
            owner.0[VECTOR_OFFSET..VECTOR_OFFSET + core::mem::size_of::<*mut u8>()]
                .copy_from_slice(&(begin as usize).to_ne_bytes());
            owner.0[VECTOR_OFFSET + core::mem::size_of::<*mut u8>()..]
                .copy_from_slice(&(end as usize).to_ne_bytes());
            owner
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    #[test]
    fn copies_the_first_entry_payload_and_releases_the_temporary() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            let mut entry = [0x5au8; ENTRY_PAYLOAD_OFFSET + PAYLOAD_SIZE];
            entry[ENTRY_PAYLOAD_OFFSET..].copy_from_slice(&[
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            ]);
            let mut slots = [entry.as_mut_ptr()];
            let begin = slots.as_mut_ptr() as *mut u8;
            // The target's element width is four bytes; only index zero is
            // loaded, but the declared span must still reproduce its size.
            let mut owner = Owner::with_vector(begin, begin.add(4));
            install(owner.ptr());

            let input = 0x1234_5678usize as *mut u8;
            let mut output = FirstEntryPayload {
                first: 0,
                second: 0,
                kind: 0,
                tail: [0; 3],
            };
            copy_first_entry_payload(input, &mut output);

            assert_eq!(FACTORY_INPUT, input);
            assert_eq!(RELEASED_OWNER, owner.ptr());
            let output_bytes = core::slice::from_raw_parts(
                (&output as *const FirstEntryPayload).cast::<u8>(),
                PAYLOAD_SIZE,
            );
            assert_eq!(output_bytes, &entry[ENTRY_PAYLOAD_OFFSET..]);
            restore();
        }
    }

    #[test]
    fn empty_vector_writes_marker_and_preserves_tail_before_releasing() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            let begin = 0x1234usize as *mut u8;
            let mut owner = Owner::with_vector(begin, begin);
            install(owner.ptr());
            let mut output = FirstEntryPayload {
                first: 0xffff_ffff,
                second: 0xeeee_eeee,
                kind: 0xdd,
                tail: [0xaa, 0xbb, 0xcc],
            };

            copy_first_entry_payload(core::ptr::null_mut(), &mut output);

            assert_eq!(output.first, 0);
            assert_eq!(output.second, 0);
            assert_eq!(output.kind, 6);
            assert_eq!(output.tail, [0xaa, 0xbb, 0xcc]);
            assert_eq!(FACTORY_INPUT, core::ptr::null_mut());
            assert_eq!(RELEASED_OWNER, owner.ptr());
            restore();
        }
    }
}
