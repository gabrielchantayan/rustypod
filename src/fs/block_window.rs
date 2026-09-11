//! Filesystem mapped-block window helpers.
//!
//! `allocation_bitmap_block_map` — original: `FUN_08063918` @ **0x08063918**
//! (128 raw bytes: 32 ARM instructions; 0x08063998 begins the distinct next
//! function). A complete decode of every ARM B/BL word in `osos.dec` finds 14
//! direct call sites, all unconditional `bl`; callers uniformly inspect the
//! returned status themselves.
//!
//! It selects a mapped allocation-bitmap block for a bit index. Owners tagged
//! 0x4244 provide a signed direct block base at +0x10; every other owner calls
//! the unported range resolver @ 0x0805cb18 with the byte index, then passes
//! the resulting block number to the mapped-window begin helper @ 0x08051578.
//! The latter installs the shared window in the caller's output pointer.
//!
//! Deliberate deviation: both unported direct callees are explicit dispatch
//! seams. Target builds invoke their stock addresses; host tests install
//! recorders. Their pointer-valued target ABI fields remain u32 on 64-bit
//! hosts, avoiding a target-layout drift.
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

use core::{mem::MaybeUninit, ptr};

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

/// Owner layout shared by the allocation-bitmap mapper and window completion.
///
/// The direct-base fields are only read for owners tagged 0x4244. The
/// completion path observes only `dispatch_context`.
#[repr(C)]
pub struct MappedBlockWindowOwner {
    _before_kind: [u8; 2],
    pub kind: u16,
    _before_direct_block_base: [u8; 0xc],
    pub direct_block_base: i16,
    _before_dispatch_context: [u8; 0x14a],
    pub dispatch_context: u32,
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

/// ABI of the unported block-index resolver @ 0x0805cb18.
pub type AllocationBitmapBlockIndexResolveFn = unsafe extern "C" fn(
    owner: *mut MappedBlockWindowOwner,
    device_context: u32,
    request_kind: u32,
    scratch: *mut u32,
    byte_index: u32,
    zero: u32,
    block_number: *mut u32,
    scratch_tail: *mut u32,
) -> i32;

/// ABI of the mapped-window begin helper @ 0x08051578.
pub type MappedBlockWindowBeginFn = unsafe extern "C" fn(
    ignored: u32,
    block_number: u32,
    out_window: *mut *mut MappedBlockWindow,
    trailing: u32,
    owner: *mut MappedBlockWindowOwner,
) -> i32;

#[cfg(target_os = "none")]
const MAPPED_BLOCK_WINDOW: *mut MappedBlockWindow = 0x08ad_c510 as *mut MappedBlockWindow;
const ALLOCATION_BITMAP_BLOCK_INDEX_RESOLVE: usize = 0x0805_cb18;
const MAPPED_BLOCK_WINDOW_BEGIN: usize = 0x0805_1578;

#[cfg(not(target_os = "none"))]
static mut HOST_MAPPED_BLOCK_WINDOW: *mut MappedBlockWindow = ptr::null_mut();

/// Host-only replacement for the dynamic target-width vtable slot.
#[cfg(not(target_os = "none"))]
static mut HOST_MAPPED_BLOCK_FINISH: Option<MappedBlockFinishFn> = None;
#[cfg(not(target_os = "none"))]
static mut HOST_ALLOCATION_BITMAP_BLOCK_INDEX_RESOLVE: Option<AllocationBitmapBlockIndexResolveFn> = None;

#[cfg(not(target_os = "none"))]
static mut HOST_MAPPED_BLOCK_WINDOW_BEGIN: Option<MappedBlockWindowBeginFn> = None;

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
/// mapped_block_window_mark_dirty — original: `FUN_0805cdd0` @ 0x0805cdd0
/// (16 ARM bytes; the `0x08adc510` literal follows at 0x0805cde0 and the
/// next function starts at 0x0805cde4).
///
/// A complete decode of every ARM B/BL word in `osos.dec` finds nine direct
/// call sites, all unconditional `bl`; there are no predicated or tail-call
/// branches. It stores one to the shared mapped block window's `+0x208` dirty
/// byte. The incoming `r0` from each caller is not read by the original.
///
/// Deliberate deviation: none. Host tests install the same window fixture
/// used by [`mapped_block_window_finish`]; target code uses the fixed firmware
/// address 0x08adc510.
///
/// # Safety
///
/// The firmware's shared mapped block window must be writable. The stock
/// function has no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mapped_block_window_mark_dirty() {
    ptr::write_volatile(ptr::addr_of_mut!((*mapped_block_window()).dirty), 1);
}


#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn resolve_allocation_bitmap_block_index(
    owner: *mut MappedBlockWindowOwner,
    device_context: u32,
    scratch: *mut u32,
    byte_index: u32,
    block_number: *mut u32,
    scratch_tail: *mut u32,
) -> i32 {
    let resolve: AllocationBitmapBlockIndexResolveFn =
        core::mem::transmute(ALLOCATION_BITMAP_BLOCK_INDEX_RESOLVE);
    resolve(owner, device_context, 1, scratch, byte_index, 0, block_number, scratch_tail)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn resolve_allocation_bitmap_block_index(
    owner: *mut MappedBlockWindowOwner,
    device_context: u32,
    scratch: *mut u32,
    byte_index: u32,
    block_number: *mut u32,
    scratch_tail: *mut u32,
) -> i32 {
    let resolve = ptr::read_volatile(ptr::addr_of!(HOST_ALLOCATION_BITMAP_BLOCK_INDEX_RESOLVE))
        .expect("allocation bitmap mapping needs a host resolver fixture");
    resolve(owner, device_context, 1, scratch, byte_index, 0, block_number, scratch_tail)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn begin_mapped_block_window(
    block_number: u32,
    out_window: *mut *mut MappedBlockWindow,
    owner: *mut MappedBlockWindowOwner,
) -> i32 {
    let begin: MappedBlockWindowBeginFn = core::mem::transmute(MAPPED_BLOCK_WINDOW_BEGIN);
    begin(0, block_number, out_window, 0, owner)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn begin_mapped_block_window(
    block_number: u32,
    out_window: *mut *mut MappedBlockWindow,
    owner: *mut MappedBlockWindowOwner,
) -> i32 {
    let begin = ptr::read_volatile(ptr::addr_of!(HOST_MAPPED_BLOCK_WINDOW_BEGIN))
        .expect("allocation bitmap mapping needs a host begin fixture");
    begin(0, block_number, out_window, 0, owner)
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

/// Maps the allocation-bitmap block containing `bit_index` — original:
/// `FUN_08063918` @ 0x08063918 (128 bytes; 14 direct unconditional `bl`
/// call sites).
///
/// Owners with kind 0x4244 derive their block number by adding
/// `bit_index >> 12` to the signed base at +0x10. Other owners resolve the
/// byte index (`bit_index >> 3`) before beginning the shared mapped window.
/// Resolver failure returns immediately without invoking the begin helper.
///
/// # Safety
///
/// `owner` and its dispatch-context pointer must be valid. `out_window` must
/// be writable because the stock begin helper stores the shared window there.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn allocation_bitmap_block_map(
    owner: *mut MappedBlockWindowOwner,
    bit_index: u32,
    out_window: *mut *mut MappedBlockWindow,
) -> i32 {
    let block_number = if ptr::read_volatile(ptr::addr_of!((*owner).kind)) == 0x4244 {
        (ptr::read_volatile(ptr::addr_of!((*owner).direct_block_base)) as i32 as u32)
            .wrapping_add(bit_index >> 12)
    } else {
        let device_context_pointer =
            ptr::read_volatile(ptr::addr_of!((*owner).dispatch_context)) as usize as *const u32;
        let device_context = ptr::read_volatile(device_context_pointer);
        let mut scratch = MaybeUninit::<u32>::uninit();
        let mut resolved_block_number = MaybeUninit::<u32>::uninit();
        let status = resolve_allocation_bitmap_block_index(
            owner,
            device_context,
            scratch.as_mut_ptr(),
            bit_index >> 3,
            resolved_block_number.as_mut_ptr(),
            scratch.as_mut_ptr(),
        );
        if status != 0 {
            return status;
        }
        resolved_block_number.assume_init()
    };

    begin_mapped_block_window(block_number, out_window, owner)
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
            _before_kind: [0; 2],
            kind: 0,
            _before_direct_block_base: [0; 0xc],
            direct_block_base: 0,
            _before_dispatch_context: [0; 0x14a],
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
    static MAP_FIXTURE_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ALLOCATION_BITMAP_BLOCK_MAP, 0x1000).map(|p| p as usize)
    });
    static mut RESOLVER_STATUS: i32 = 0;
    static mut RESOLVED_BLOCK_NUMBER: u32 = 0;
    static mut RESOLVER_CALL: Option<(usize, u32, u32, usize, u32, u32, usize, usize)> = None;
    static mut BEGIN_STATUS: i32 = 0;
    static mut BEGIN_OUTPUT: *mut MappedBlockWindow = ptr::null_mut();
    static mut BEGIN_CALL: Option<(u32, u32, usize, u32, usize)> = None;

    unsafe extern "C" fn record_resolver(
        owner: *mut MappedBlockWindowOwner,
        device_context: u32,
        request_kind: u32,
        scratch: *mut u32,
        byte_index: u32,
        zero: u32,
        block_number: *mut u32,
        scratch_tail: *mut u32,
    ) -> i32 {
        RESOLVER_CALL = Some((
            owner as usize, device_context, request_kind, scratch as usize, byte_index, zero,
            block_number as usize, scratch_tail as usize,
        ));
        if RESOLVER_STATUS == 0 {
            ptr::write(block_number, RESOLVED_BLOCK_NUMBER);
        }
        RESOLVER_STATUS
    }

    unsafe extern "C" fn record_begin(
        ignored: u32,
        block_number: u32,
        out_window: *mut *mut MappedBlockWindow,
        trailing: u32,
        owner: *mut MappedBlockWindowOwner,
    ) -> i32 {
        BEGIN_CALL = Some((ignored, block_number, out_window as usize, trailing, owner as usize));
        ptr::write(out_window, BEGIN_OUTPUT);
        BEGIN_STATUS
    }

    unsafe fn install_map_fixture(
        kind: u16,
        direct_block_base: i16,
        device_context: u32,
    ) -> Option<*mut MappedBlockWindowOwner> {
        let slab = (*MAP_FIXTURE_SLAB)? as *mut u8;
        ptr::write_bytes(slab, 0, 0x1000);
        let owner = slab as *mut MappedBlockWindowOwner;
        let device_context_pointer = slab.add(0x200) as *mut u32;
        ptr::write(device_context_pointer, device_context);
        ptr::write(owner, MappedBlockWindowOwner {
            _before_kind: [0; 2],
            kind,
            _before_direct_block_base: [0; 0xc],
            direct_block_base,
            _before_dispatch_context: [0; 0x14a],
            dispatch_context: device_context_pointer as usize as u32,
        });
        HOST_ALLOCATION_BITMAP_BLOCK_INDEX_RESOLVE = Some(record_resolver);
        HOST_MAPPED_BLOCK_WINDOW_BEGIN = Some(record_begin);
        Some(owner)
    }

    unsafe fn reset_map_fixture() {
        HOST_ALLOCATION_BITMAP_BLOCK_INDEX_RESOLVE = None;
        HOST_MAPPED_BLOCK_WINDOW_BEGIN = None;
        RESOLVER_CALL = None;
        BEGIN_CALL = None;
    }

    #[test]
    fn map_uses_signed_direct_base_without_resolving() {
        let _lock = TEST_LOCK.lock();
        let Some(owner) = (unsafe { install_map_fixture(0x4244, -2, 0xfeed_beef) }) else {
            assert!(note_missing_u32_fixture("fs::block_window"));
            return;
        };
        unsafe {
            BEGIN_STATUS = -9;
            BEGIN_OUTPUT = 0x1234_5000usize as *mut MappedBlockWindow;
        }
        let mut out_window = ptr::null_mut();

        let result = unsafe { allocation_bitmap_block_map(owner, 0x3fff, &mut out_window) };

        assert_eq!(result, -9);
        assert_eq!(unsafe { RESOLVER_CALL }, None);
        assert_eq!(unsafe { BEGIN_CALL }, Some((0, 1, &mut out_window as *mut _ as usize, 0, owner as usize)));
        assert_eq!(out_window, unsafe { BEGIN_OUTPUT });
        unsafe { reset_map_fixture() };
    }

    #[test]
    fn map_resolves_byte_index_then_begins_window() {
        let _lock = TEST_LOCK.lock();
        let Some(owner) = (unsafe { install_map_fixture(0x1111, 0, 0xa5a5_5a5a) }) else {
            assert!(note_missing_u32_fixture("fs::block_window"));
            return;
        };
        unsafe {
            RESOLVER_STATUS = 0;
            RESOLVED_BLOCK_NUMBER = 0x8765_4321;
            BEGIN_STATUS = 0;
            BEGIN_OUTPUT = 0x3456_7000usize as *mut MappedBlockWindow;
        }
        let mut out_window = ptr::null_mut();

        let result = unsafe { allocation_bitmap_block_map(owner, 0x12345, &mut out_window) };

        assert_eq!(result, 0);
        let resolver_call = unsafe { RESOLVER_CALL }.expect("resolver was called");
        assert_eq!(resolver_call.0, owner as usize);
        assert_eq!(resolver_call.1, 0xa5a5_5a5a);
        assert_eq!(resolver_call.2, 1);
        assert_ne!(resolver_call.3, 0);
        assert_eq!(resolver_call.4, 0x2468);
        assert_eq!(resolver_call.5, 0);
        assert_ne!(resolver_call.6, 0);
        assert_eq!(resolver_call.7, resolver_call.3);
        assert_eq!(unsafe { BEGIN_CALL }, Some((0, 0x8765_4321, &mut out_window as *mut _ as usize, 0, owner as usize)));
        assert_eq!(out_window, unsafe { BEGIN_OUTPUT });
        unsafe { reset_map_fixture() };
    }

    #[test]
    fn map_returns_resolver_error_without_beginning_window() {
        let _lock = TEST_LOCK.lock();
        let Some(owner) = (unsafe { install_map_fixture(0x1111, 0, 0) }) else {
            assert!(note_missing_u32_fixture("fs::block_window"));
            return;
        };
        unsafe {
            RESOLVER_STATUS = -0x34;
            BEGIN_CALL = None;
        }
        let original = 0x7654_3000usize as *mut MappedBlockWindow;
        let mut out_window = original;

        let result = unsafe { allocation_bitmap_block_map(owner, 7, &mut out_window) };

        assert_eq!(result, -0x34);
        assert_eq!(unsafe { RESOLVER_CALL }.map(|call| call.4), Some(0));
        assert_eq!(unsafe { BEGIN_CALL }, None);
        assert_eq!(out_window, original);
        unsafe { reset_map_fixture() };
    }
    #[test]
    fn mark_dirty_overwrites_every_prior_dirty_value_only() {
        let _lock = TEST_LOCK.lock();
        let mut window = MappedBlockWindow {
            block: [0xa5; 0x200],
            block_number: 0x1234_5678,
            owner: 0x89ab_cdef,
            dirty: 0,
            mapped: 0x5a,
        };

        unsafe {
            HOST_MAPPED_BLOCK_WINDOW = &mut window;
            for prior_dirty in [0, 1, 0x80, 0xff] {
                window.dirty = prior_dirty;

                mapped_block_window_mark_dirty();

                assert_eq!(window.dirty, 1, "prior dirty byte {prior_dirty:#x}");
                assert_eq!(window.block[0], 0xa5);
                assert_eq!(window.block[0x1ff], 0xa5);
                assert_eq!(window.block_number, 0x1234_5678);
                assert_eq!(window.owner, 0x89ab_cdef);
                assert_eq!(window.mapped, 0x5a);
            }
            HOST_MAPPED_BLOCK_WINDOW = ptr::null_mut();
        }
    }
}

