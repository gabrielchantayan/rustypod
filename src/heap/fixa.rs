//! FixA owner destruction.
//!
//! `fixa_owner_destroy` — retailOS `FUN_08048f48` @ `0x08048f48` (60 bytes,
//! `0x08048f48..0x08048f84`; `0x08048f84` begins the next distinct function).
//!
//! A complete ARM B/BL decode of `osos.dec` finds seven inbound direct calls:
//! five unconditional `bl` at `0x080492ec`, `0x080d712c`, `0x080da97c`,
//! `0x080da990`, and `0x080e4334`, plus two `blne` calls at `0x08049184` and
//! `0x08049190`. The predicated callers gate this routine themselves; its
//! `FUN_080d21d0` validation call remains the only NULL/type guard here.
//!
//! Raw ARM calls `FUN_080d21d0`, which returns true only when word zero is the
//! literal `FixA`, then repeatedly calls `FUN_080d8750` on the owner `+0x0c`
//! head. That callee accepts only `FixL` nodes, unlinks one node, and tail-calls
//! `free_tag4`. Once the list is empty this routine clears the FixA word and
//! tail-calls `free_tag4` for the owner.
//!
//! Deliberate deviation: the two unported direct callees remain explicit
//! address-based dispatch boundaries. `FixA` and `FixL` are descriptions only
//! of their verified magic words, not inferred subsystem identities; target
//! builds invoke `0x080d21d0` and `0x080d8750`, while host tests install seams.

use core::ptr::{addr_of, addr_of_mut};

use crate::heap::veneers::free_tag4;

const RETAIL_VALIDATE_FIXA: usize = 0x080d_21d0;
const RETAIL_DESTROY_FIXL: usize = 0x080d_8750;

/// Owner layout observed by `FUN_08048f48`. Pointer fields remain target-width
/// words on every platform.
#[repr(C)]
pub struct FixaOwner {
    /// `0x46697841` (`FixA`) while the owner is valid; cleared before release.
    pub magic: u32,
    _unknown_04: u32,
    _unknown_08: u32,
    /// First FixL node, or zero when no nodes remain.
    pub first_fixl: u32,
}

const _: () = assert!(core::mem::size_of::<FixaOwner>() == 0x10);
const _: [u8; 0x0c] = [0; core::mem::offset_of!(FixaOwner, first_fixl)];

/// Host replacement for the two unresolved direct callees.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct FixaDestroyOps {
    /// `FUN_080d21d0(owner)`: validates a non-NULL owner against `FixA`.
    pub validate_fixa: unsafe extern "C" fn(owner: *mut FixaOwner) -> u32,
    /// `FUN_080d8750(fixl)`: unlinks and releases one `FixL` node.
    pub destroy_fixl: unsafe extern "C" fn(fixl: *mut u8),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_validate_fixa(_owner: *mut FixaOwner) -> u32 {
    panic!("fixa_owner_destroy requires unresolved FUN_080d21d0")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy_fixl(_fixl: *mut u8) {
    panic!("fixa_owner_destroy requires unresolved FUN_080d8750")
}

/// Default host boundary: calling this port outside a test requires models for
/// its two unresolved retailOS callees.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_FIXA_DESTROY_OPS: FixaDestroyOps = FixaDestroyOps {
    validate_fixa: missing_validate_fixa,
    destroy_fixl: missing_destroy_fixl,
};

/// Active host-only direct-callee boundary.
#[cfg(not(target_os = "none"))]
pub static mut FIXA_DESTROY_OPS: FixaDestroyOps = DEFAULT_FIXA_DESTROY_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn fixa_destroy_ops() -> FixaDestroyOps {
    unsafe { core::ptr::read_volatile(addr_of!(FIXA_DESTROY_OPS)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn validate_fixa(owner: *mut FixaOwner) -> u32 {
    let validate: unsafe extern "C" fn(*mut FixaOwner) -> u32 =
        unsafe { core::mem::transmute(RETAIL_VALIDATE_FIXA) };
    unsafe { validate(owner) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn validate_fixa(owner: *mut FixaOwner) -> u32 {
    unsafe { (fixa_destroy_ops().validate_fixa)(owner) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_fixl(fixl: *mut u8) {
    let destroy: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(RETAIL_DESTROY_FIXL) };
    unsafe { destroy(fixl) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy_fixl(fixl: *mut u8) {
    unsafe { (fixa_destroy_ops().destroy_fixl)(fixl) }
}

/// Destroys a validated FixA owner, all of its FixL nodes, and then the owner.
///
/// # Safety
///
/// `owner` may be NULL, but any non-NULL pointer accepted by
/// `FUN_080d21d0` must have the target-word layout above. Each nonzero head
/// must be a valid `FixL` node consumable by `FUN_080d8750`; as in retailOS, a
/// non-FixL head does not make progress and leaves the loop nonterminating.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fixa_owner_destroy")]
#[inline(never)]
pub unsafe extern "C" fn fixa_owner_destroy(owner: *mut FixaOwner) {
    if unsafe { validate_fixa(owner) } == 0 {
        return;
    }

    while unsafe { addr_of!((*owner).first_fixl).read_volatile() } != 0 {
        let first_fixl = unsafe { addr_of!((*owner).first_fixl).read_volatile() } as usize as *mut u8;
        unsafe { destroy_fixl(first_fixl) };
    }

    unsafe { addr_of_mut!((*owner).magic).write_volatile(0) };
    unsafe { free_tag4(owner.cast()) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec::Vec;

    const FIXA_MAGIC: u32 = 0x4669_7841;
    const FIXL_MAGIC: u32 = 0x4669_784c;
    const FIXTURE_LEN: usize = 0x400;

    #[repr(C)]
    struct FixlLink {
        magic: u32,
        owner: u32,
        next: u32,
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::FIXA_OWNER_DESTROY, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static mut DESTROYED: Option<Vec<usize>> = None;
    static mut VALIDATED: Option<Vec<usize>> = None;

    unsafe extern "C" fn validate_magic(owner: *mut FixaOwner) -> u32 {
        unsafe {
            VALIDATED.as_mut().unwrap().push(owner as usize);
            (!owner.is_null() && addr_of!((*owner).magic).read() == FIXA_MAGIC) as u32
        }
    }

    /// Behavioral model of the observed `FixL` unlink and tag-4 release path.
    unsafe extern "C" fn unlink_and_destroy_fixl(fixl: *mut u8) {
        unsafe {
            let fixl = fixl.cast::<FixlLink>();
            assert_eq!(addr_of!((*fixl).magic).read(), FIXL_MAGIC);
            let owner = addr_of!((*fixl).owner).read() as usize as *mut FixaOwner;
            let next = addr_of!((*fixl).next).read();
            let first = addr_of_mut!((*owner).first_fixl);
            if first.read() == fixl as usize as u32 {
                first.write(next);
            } else {
                let mut previous = first.read() as usize as *mut FixlLink;
                while addr_of!((*previous).next).read() != fixl as usize as u32 {
                    previous = addr_of!((*previous).next).read() as usize as *mut FixlLink;
                }
                addr_of_mut!((*previous).next).write(next);
            }
            DESTROYED.as_mut().unwrap().push(fixl as usize);
            free_tag4(fixl.cast());
        }
    }

    const RECORDING_OPS: FixaDestroyOps = FixaDestroyOps {
        validate_fixa: validate_magic,
        destroy_fixl: unlink_and_destroy_fixl,
    };

    unsafe fn install_recorders() {
        unsafe {
            DESTROYED = Some(Vec::new());
            VALIDATED = Some(Vec::new());
            FIXA_DESTROY_OPS = RECORDING_OPS;
        }
    }

    unsafe fn restore_defaults() {
        unsafe {
            FIXA_DESTROY_OPS = DEFAULT_FIXA_DESTROY_OPS;
            DESTROYED = None;
            VALIDATED = None;
        }
    }

    unsafe fn reset_fixture(base: *mut u8) {
        unsafe { ptr::write_bytes(base, 0, FIXTURE_LEN) };
    }

    #[test]
    fn validated_owner_releases_each_link_then_clears_and_releases_owner() {
        let _test_guard = TEST_LOCK.lock();
        let _heap_guard = mock_heap();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("heap/fixa"));
            return;
        };
        let base = base as *mut u8;
        let owner = unsafe { base.add(0x40).cast::<FixaOwner>() };
        let first = unsafe { base.add(0x80).cast::<FixlLink>() };
        let second = unsafe { base.add(0xa0).cast::<FixlLink>() };

        unsafe {
            reset_fixture(base);
            install_recorders();
            addr_of_mut!((*owner).magic).write(FIXA_MAGIC);
            addr_of_mut!((*owner).first_fixl).write(first as usize as u32);
            ptr::write(first, FixlLink {
                magic: FIXL_MAGIC,
                owner: owner as usize as u32,
                next: second as usize as u32,
            });
            ptr::write(second, FixlLink {
                magic: FIXL_MAGIC,
                owner: owner as usize as u32,
                next: 0,
            });

            fixa_owner_destroy(owner);

            assert_eq!(addr_of!((*owner).magic).read(), 0);
            assert_eq!(addr_of!((*owner).first_fixl).read(), 0);
            assert_eq!(VALIDATED.as_ref().unwrap(), &[owner as usize]);
            assert_eq!(DESTROYED.as_ref().unwrap(), &[first as usize, second as usize]);
            assert_eq!(free_log(), (3, owner.cast(), 4));
            restore_defaults();
        }
    }

    #[test]
    fn null_and_wrong_magic_return_before_list_or_heap_access() {
        let _test_guard = TEST_LOCK.lock();
        let _heap_guard = mock_heap();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("heap/fixa"));
            return;
        };
        let owner = unsafe { (base as *mut u8).add(0x40).cast::<FixaOwner>() };

        unsafe {
            reset_fixture(base as *mut u8);
            install_recorders();
            addr_of_mut!((*owner).magic).write(0xdead_beef);
            addr_of_mut!((*owner).first_fixl).write(0xffff_ffff);

            fixa_owner_destroy(ptr::null_mut());
            fixa_owner_destroy(owner);

            assert_eq!(addr_of!((*owner).magic).read(), 0xdead_beef);
            assert_eq!(addr_of!((*owner).first_fixl).read(), 0xffff_ffff);
            assert_eq!(VALIDATED.as_ref().unwrap(), &[0, owner as usize]);
            assert!(DESTROYED.as_ref().unwrap().is_empty());
            assert_eq!(free_log().0, 0);
            restore_defaults();
        }
    }
}
