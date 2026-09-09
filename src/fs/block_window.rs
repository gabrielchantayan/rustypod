//! Filesystem mapped-block window completion.
//!
//! `mapped_block_window_finish` — original: `FUN_0806448c` @ **0x0806448c**
//! (84 raw bytes: 21 ARM instructions, ending at the literal word
//! `0x08adc510` @ 0x080644e0; 0x080644e4 starts the distinct next function).
//! A complete decode of every ARM B/BL word in `osos.dec` finds 14 direct call
//! sites: 10 unconditional `bl` and 4 predicated `blne`. The predicated forms
//! are caller-side guards; this routine has no unmapped-window NULL guard.
//!
//! The global window at 0x08adc510 supplies a 0x200-byte mapped block followed
//! by its block number, owner, dirty byte, and mapped byte. Completion walks
//! `owner+0x15c -> +0x08 -> +0x04`; the stock dispatch thunk @ 0x08149e10
//! then follows one further `+0x04` handle link and invokes vtable slot 3 with
//! `(block_number, 1, window, 0)`. Regardless of that callback's status, the
//! routine clears all four bookkeeping fields and returns the callback result
//! truncated to a signed 16-bit value.
//!
//! Deliberate deviations: target code dispatches the recovered raw vtable slot
//! directly instead of branching through unported thunk 0x08149e10. Host tests
//! replace only that dynamic vtable call: a native host function pointer cannot
//! reside in the firmware's target-width u32 vtable word. The firmware global
//! remains the fixed 0x08adc510 address on target; host tests install a fixture.

use core::ptr;

/// Firmware-owned block window, physically located at 0x08adc510.
///
/// The first 0x200 bytes are the mapped block. The remaining fields are the
/// complete part of the object this routine observes. Pointer-valued target
/// fields stay u32 so their offsets remain exact on both ARM and 64-bit hosts.
#[repr(C)]
pub struct MappedBlockWindow {
    pub block: [u8; 0x200],
    pub block_number: u32,
    pub owner: u32,
    pub dirty: u8,
    pub mapped: u8,
}

/// Owner fields traversed to reach the block-window virtual interface.
#[repr(C)]
pub struct MappedBlockWindowOwner {
    _before_dispatch_context: [u32; 0x15c / 4],
    dispatch_context: u32,
}

/// First link after the owner (`owner+0x15c`, then `+0x08`).
#[repr(C)]
pub struct MappedBlockDispatchContext {
    _before_link: [u32; 2],
    link: u32,
}

/// Second link before the thunk's handle dereference (`+0x04`).
#[repr(C)]
pub struct MappedBlockDispatchLink {
    _before_handle: u32,
    handle: u32,
}

/// The thunk @ 0x08149e10 dereferences this handle's `+0x04` object word.
#[repr(C)]
pub struct MappedBlockVirtualHandle {
    _before_object: u32,
    object: u32,
}

/// The C++ object carrying the vtable selected by the completion thunk.
#[repr(C)]
pub struct MappedBlockVirtualObject {
    vtable: u32,
}

/// ABI of vtable slot 3 reached through stock thunk 0x08149e10.
pub type MappedBlockFinishFn = unsafe extern "C" fn(
    object: *mut MappedBlockVirtualObject,
    block_number: u32,
    mode: u32,
    window: *mut MappedBlockWindow,
    trailing: u32,
) -> i32;

#[cfg(target_os = "none")]
const MAPPED_BLOCK_WINDOW: *mut MappedBlockWindow = 0x08ad_c510 as *mut MappedBlockWindow;

#[cfg(not(target_os = "none"))]
static mut HOST_MAPPED_BLOCK_WINDOW: *mut MappedBlockWindow = ptr::null_mut();

/// Host-only replacement for the dynamic target-width vtable slot.
#[cfg(not(target_os = "none"))]
static mut HOST_MAPPED_BLOCK_FINISH: Option<MappedBlockFinishFn> = None;

#[inline(always)]
unsafe fn mapped_block_window() -> *mut MappedBlockWindow {
    #[cfg(target_os = "none")]
    {
        MAPPED_BLOCK_WINDOW
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(HOST_MAPPED_BLOCK_WINDOW))
    }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn finish_mapped_block(
    handle: *mut MappedBlockVirtualHandle,
    block_number: u32,
    window: *mut MappedBlockWindow,
) -> i32 {
    let object = ptr::read_volatile(ptr::addr_of!((*handle).object)) as usize
        as *mut MappedBlockVirtualObject;
    let vtable = ptr::read_volatile(ptr::addr_of!((*object).vtable)) as usize as *const u32;
    let finish_word = ptr::read_volatile(vtable.add(3));
    let finish: MappedBlockFinishFn = core::mem::transmute(finish_word as usize);
    finish(object, block_number, 1, window, 0)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn finish_mapped_block(
    handle: *mut MappedBlockVirtualHandle,
    block_number: u32,
    window: *mut MappedBlockWindow,
) -> i32 {
    let object = ptr::read_volatile(ptr::addr_of!((*handle).object)) as usize
        as *mut MappedBlockVirtualObject;
    let finish = ptr::read_volatile(ptr::addr_of!(HOST_MAPPED_BLOCK_FINISH))
        .expect("mapped block completion needs a host dispatch fixture");
    finish(object, block_number, 1, window, 0)
}

/// mapped_block_window_finish — original: `FUN_0806448c` @ 0x0806448c
/// (84 bytes; 14 direct call sites: 10 `bl`, 4 `blne`).
///
/// Calls the active mapped block's vtable slot 3 with mode one, clears the
/// window's block number, owner, dirty, and mapped bookkeeping unconditionally,
/// then returns the callback result sign-extended from its low 16 bits.
///
/// # Safety
///
/// The fixed firmware window must describe a live mapping: its owner and every
/// recovered link through the virtual object must be valid. The stock code
/// dereferences every link without a NULL guard, and this port preserves that.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mapped_block_window_finish() -> i32 {
    let window = mapped_block_window();
    let owner = ptr::read_volatile(ptr::addr_of!((*window).owner)) as usize
        as *mut MappedBlockWindowOwner;
    let context = ptr::read_volatile(ptr::addr_of!((*owner).dispatch_context)) as usize
        as *mut MappedBlockDispatchContext;
    let link = ptr::read_volatile(ptr::addr_of!((*context).link)) as usize
        as *mut MappedBlockDispatchLink;
    let handle = ptr::read_volatile(ptr::addr_of!((*link).handle)) as usize
        as *mut MappedBlockVirtualHandle;
    let block_number = ptr::read_volatile(ptr::addr_of!((*window).block_number));
    let status = finish_mapped_block(handle, block_number, window);

    ptr::write_volatile(ptr::addr_of_mut!((*window).block_number), 0);
    ptr::write_volatile(ptr::addr_of_mut!((*window).owner), 0);
    ptr::write_volatile(ptr::addr_of_mut!((*window).dirty), 0);
    ptr::write_volatile(ptr::addr_of_mut!((*window).mapped), 0);

    (status as i16) as i32
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab,
    };
    use core::ptr;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MAPPED_BLOCK_WINDOW_FINISH, 0x1000).map(|p| p as usize)
    });
    static mut CALLBACK_STATUS: i32 = 0;
    static mut CALLBACK_CALL: Option<(usize, u32, u32, usize, u32, u32, u32, u8, u8)> = None;

    unsafe extern "C" fn record_finish(
        object: *mut MappedBlockVirtualObject,
        block_number: u32,
        mode: u32,
        window: *mut MappedBlockWindow,
        trailing: u32,
    ) -> i32 {
        CALLBACK_CALL = Some((
            object as usize,
            block_number,
            mode,
            window as usize,
            trailing,
            ptr::read_volatile(ptr::addr_of!((*window).block_number)),
            ptr::read_volatile(ptr::addr_of!((*window).owner)),
            ptr::read_volatile(ptr::addr_of!((*window).dirty)),
            ptr::read_volatile(ptr::addr_of!((*window).mapped)),
        ));
        CALLBACK_STATUS
    }

    fn fixture_slab() -> Option<*mut u8> {
        (*FIXTURE_SLAB).map(|p| p as *mut u8)
    }

    unsafe fn install_fixture(block_number: u32, dirty: u8, mapped: u8) -> Option<(*mut MappedBlockWindow, usize)> {
        let slab = fixture_slab()?;
        ptr::write_bytes(slab, 0, 0x1000);

        let window = slab as *mut MappedBlockWindow;
        let owner = slab.add(0x300) as *mut MappedBlockWindowOwner;
        let context = slab.add(0x500) as *mut MappedBlockDispatchContext;
        let link = slab.add(0x520) as *mut MappedBlockDispatchLink;
        let handle = slab.add(0x540) as *mut MappedBlockVirtualHandle;
        let object = slab.add(0x560) as *mut MappedBlockVirtualObject;

        ptr::write(owner, MappedBlockWindowOwner {
            _before_dispatch_context: [0; 0x15c / 4],
            dispatch_context: context as usize as u32,
        });
        ptr::write(context, MappedBlockDispatchContext {
            _before_link: [0; 2],
            link: link as usize as u32,
        });
        ptr::write(link, MappedBlockDispatchLink {
            _before_handle: 0,
            handle: handle as usize as u32,
        });
        ptr::write(handle, MappedBlockVirtualHandle {
            _before_object: 0,
            object: object as usize as u32,
        });
        ptr::write(object, MappedBlockVirtualObject { vtable: 0 });
        (*window).block_number = block_number;
        (*window).owner = owner as usize as u32;
        (*window).dirty = dirty;
        (*window).mapped = mapped;
        HOST_MAPPED_BLOCK_WINDOW = window;
        HOST_MAPPED_BLOCK_FINISH = Some(record_finish);
        Some((window, object as usize))
    }

    unsafe fn reset_host_fixture() {
        HOST_MAPPED_BLOCK_WINDOW = ptr::null_mut();
        HOST_MAPPED_BLOCK_FINISH = None;
        CALLBACK_CALL = None;
    }

    #[test]
    fn finish_dispatches_full_chain_before_clearing_and_sign_extends_status() {
        let _lock = TEST_LOCK.lock();
        let Some((window, object)) = (unsafe { install_fixture(0x1234_5678, 1, 1) }) else {
            assert!(note_missing_u32_fixture("fs::block_window"));
            return;
        };
        unsafe { CALLBACK_STATUS = 0x4567_fffeu32 as i32 };
        let owner = unsafe { (*window).owner };

        let result = unsafe { mapped_block_window_finish() };

        assert_eq!(result, -2);
        assert_eq!(unsafe { CALLBACK_CALL }, Some((
            object, 0x1234_5678, 1, window as usize, 0,
            0x1234_5678, owner, 1, 1,
        )));
        assert_eq!(unsafe { (*window).block_number }, 0);
        assert_eq!(unsafe { (*window).owner }, 0);
        assert_eq!(unsafe { (*window).dirty }, 0);
        assert_eq!(unsafe { (*window).mapped }, 0);
        unsafe { reset_host_fixture() };
    }

    #[test]
    fn finish_clears_bookkeeping_after_nonzero_callback_status() {
        let _lock = TEST_LOCK.lock();
        let Some((window, _)) = (unsafe { install_fixture(7, 1, 1) }) else {
            assert!(note_missing_u32_fixture("fs::block_window"));
            return;
        };
        unsafe { CALLBACK_STATUS = 0x4321_8001u32 as i32 };

        let result = unsafe { mapped_block_window_finish() };

        assert_eq!(result, -32767);
        assert_eq!(unsafe { (*window).block_number }, 0);
        assert_eq!(unsafe { (*window).owner }, 0);
        assert_eq!(unsafe { (*window).dirty }, 0);
        assert_eq!(unsafe { (*window).mapped }, 0);
        unsafe { reset_host_fixture() };
    }
}
