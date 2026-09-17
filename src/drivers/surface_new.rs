//! `surface_new` — original: `FUN_081066a8` @ 0x081066a8 (64 bytes;
//! 23 `bl` call sites, binary-scanned over every BL word in osos.dec —
//! all plain `bl`, zero predicated forms, so callers never NULL-gate
//! or flag-gate the factory itself). Ghidra's 64-byte extent is exact:
//! the next function @ 0x081066e8 opens with `push {r4, lr}`.
//!
//! Factory for the **display surface object** — the refcounted,
//! vtable'd pixel-buffer owner whose plane accessor
//! `surface_plane_address` @ 0x082978bc (ported in
//! `drivers/display_layer.rs`) reads the format byte at +0x08 and the
//! plane words +0x24/+0x28/+0x2c. That layout match is what identifies
//! the class: the constructor @ 0x08106a8c stores the vtable word
//! 0x08980b70 at +0x00, 1 at +0x04, the format byte at +0x08, the
//! geometry words at +0x0c/+0x10/+0x14, width*height at +0x1c, the
//! plane base at +0x24 (allocated from the graphics pool
//! `FUN_081e6d58` unless the caller supplies one), +0x28/+0x2c zeroed,
//! a 4-byte pool allocation at +0x38, and an RTXC mutex @ +0x40 plus a
//! bound condvar @ +0x48 — 0x54 bytes total, exactly the
//! `mov r0, #0x54` immediate below. The screen-size callers pass the
//! Classic 6G panel geometry, e.g. `surface_new(3, 0xf0, 0x140, 0x140,
//! 2, plane, 0, 0, 0)` from `FUN_0815643c` @ 0x08156570.
//!
//! Algorithm (the whole body; reference `decomp/osos.asm` @
//! 0x081066a8-0x081066e4):
//!
//! ```text
//! push {r0-r3, r4-fp, lr}        @ spill the 4 register args
//! sub  sp, sp, #28
//! ldm  r9, {r5-r9}               @ reload the 5 stack args
//! mov  r0, #0x54
//! bl   0x082aadd4                @ operator_new(0x54) — ported, called directly
//! stm  sp, {r4-r9}               @ forward arg4 + the 5 stack args
//! ldr  r1, [sp, #28]             @ r1 = arg1
//! mov  r2, r2 ; mov r3, r3       @ (arg2/arg3 kept in sl/fp)
//! bl   0x08106a8c                @ surface_ctor — unported, dispatch slot
//! add  sp, sp, #44 ; pop {...pc}
//! ```
//!
//! The constructor's `this` return survives in r0 through the
//! epilogue, so the factory RETURNS the constructed object — Ghidra's
//! `void` return in `decomp/c/009/081066a8_FUN_081066a8.c` is wrong;
//! every one of the 23 callers stores the result (e.g.
//! `*(undefined4 *)(param_1 + 0xc0) = uVar1;`). There is no NULL check
//! between `operator_new` and the ctor: a failed allocation faults in
//! the ctor's first store, and the port reproduces that by passing the
//! block through untouched.
//!
//! Argument mapping (factory → ctor, per the stm/ldm sequence):
//! r0=this, then the factory's nine arguments in order become the
//! ctor's `format, width, stride, height, flags, plane0, plane1,
//! plane2, plane3` — `plane0..plane3` are caller-supplied external
//! plane bases (all zero ⇒ the ctor allocates; `surface_plane_address`
//! documents the per-format plane counts: format 0 planar YUV 4:2:0,
//! 1 two-plane, 2/3/4 packed single-plane).
//!
//! ## Deviations (the util/service_manager_get.rs contract)
//!
//! - The constructor @ 0x08106a8c is unported (a 460-byte C++
//!   constructor chaining the graphics-pool allocation
//!   `FUN_081e6c38`/`FUN_081e6d58`, the RTXC mutex create @
//!   0x080744a4 and `condvar_bind` @ 0x080ed9c8), so it rides the
//!   [`SURFACE_CTOR`] dispatch slot with a documented zeroing stub
//!   default. `operator new` @ 0x082aadd4 is ported
//!   (`heap::veneers::operator_new`) and called directly.
//! - The vtable word 0x08980b70 is stored by the real ctor, not the
//!   stub: the image bytes at 0x08980b70 do not decode as code
//!   pointers (first word 0x80c00010, into DRAM past the osos
//!   extent), so the table is presumably runtime-initialized; the
//!   stub installs no vtable at all.
//!
//! **Not hook-ready**: until the constructor is ported the default
//! hands out a zeroed block — no vtable, no plane storage, no mutex —
//! so branching stock code at 0x081066a8 would break all 23 callers.

use crate::heap::veneers::operator_new;
use core::ptr;


/// Prefix of the 0x54-byte display surface reached by
/// [`surface_set_external_planes_if_empty`].
///
/// The class constructor stores the format at `+0x08`; its external plane
/// base words begin at `+0x24`. The byte arrays deliberately name and retain
/// the unrecovered fields while keeping the target's 32-bit word layout on
/// 64-bit host test builds.
#[repr(C)]
struct SurfacePlaneSlots {
    _before_format: [u8; 0x08],
    format: u8,
    _before_planes: [u8; 0x1b],
    plane0: u32,
    plane1: u32,
    plane2: u32,
}

const _: [u8; 0x30] = [0; core::mem::size_of::<SurfacePlaneSlots>()];
const _: [u8; 0x08] = [0; core::mem::offset_of!(SurfacePlaneSlots, format)];
const _: [u8; 0x24] = [0; core::mem::offset_of!(SurfacePlaneSlots, plane0)];
const _: [u8; 0x28] = [0; core::mem::offset_of!(SurfacePlaneSlots, plane1)];
const _: [u8; 0x2c] = [0; core::mem::offset_of!(SurfacePlaneSlots, plane2)];

/// `surface_set_external_planes_if_empty` — original: `FUN_081065dc` @
/// `0x081065dc` (160 bytes; 6 verified `bl` call sites).
///
/// Raw ARM spans `0x081065dc..0x0810667c`; the next separately linked
/// function opens at `0x0810667c` with `push {r4-r6, lr}`. It accepts only
/// format 0 (three planar bases) or format 1 (two bases). In either case,
/// all three stored plane slots must first be zero. Format 0 then requires
/// three nonzero input bases and a zero fourth argument before writing all
/// three slots; format 1 requires two nonzero bases and zero third/fourth
/// arguments before writing its first two slots. Every other combination
/// leaves the surface untouched.
///
/// Decoding every ARM `BL` immediate in osos.dec found six unconditional
/// calls (0x0811eb94, 0x08144c18, 0x08199b64, 0x08199bb4, 0x081f5b10,
/// 0x081f5ed4) and no predicated calls. Deliberate deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn surface_set_external_planes_if_empty(
    surface: *mut u8,
    plane0: u32,
    plane1: u32,
    plane2: u32,
    plane3: u32,
) {
    let surface = surface.cast::<SurfacePlaneSlots>();
    let format = unsafe { ptr::addr_of!((*surface).format).read_volatile() };
    if format != 0 && format != 1 {
        return;
    }

    let has_planes = unsafe {
        ptr::addr_of!((*surface).plane0).read_volatile() != 0
            || ptr::addr_of!((*surface).plane1).read_volatile() != 0
            || ptr::addr_of!((*surface).plane2).read_volatile() != 0
    };
    if has_planes {
        return;
    }

    if format == 0 {
        if plane0 != 0 && plane1 != 0 && plane2 != 0 && plane3 == 0 {
            unsafe {
                ptr::addr_of_mut!((*surface).plane0).write_volatile(plane0);
                ptr::addr_of_mut!((*surface).plane1).write_volatile(plane1);
                ptr::addr_of_mut!((*surface).plane2).write_volatile(plane2);
            }
        }
    } else if plane0 != 0 && plane1 != 0 && plane2 == 0 && plane3 == 0 {
        unsafe {
            ptr::addr_of_mut!((*surface).plane0).write_volatile(plane0);
            ptr::addr_of_mut!((*surface).plane1).write_volatile(plane1);
        }
    }
}
/// Allocation size of the surface object (`mov r0, #0x54`).
pub const SURFACE_SIZE: usize = 0x54;

/// An ADS C++ constructor: takes the raw block plus the factory's nine
/// arguments, returns `this`.
pub type SurfaceCtor = unsafe extern "C" fn(
    this: *mut u8,
    format: u32,
    width: u32,
    stride: u32,
    height: u32,
    flags: u32,
    plane0: u32,
    plane1: u32,
    plane2: u32,
    plane3: u32,
) -> *mut u8;

/// The default constructor stub: zeroes the block and returns it. A
/// faithful *subset* — the original is dominated by field stores — but
/// it installs no vtable, no plane storage and no mutex, which is why
/// the module header calls this symbol not hook-ready. Volatile
/// stores: a plain loop is rewritten by LLVM into a call to
/// `__aeabi_memclr`, a symbol that does not exist in this build (the
/// strcat.rs trap).
unsafe extern "C" fn zeroing_surface_ctor(
    this: *mut u8,
    _format: u32,
    _width: u32,
    _stride: u32,
    _height: u32,
    _flags: u32,
    _plane0: u32,
    _plane1: u32,
    _plane2: u32,
    _plane3: u32,
) -> *mut u8 {
    let mut cursor = this;
    let end = unsafe { this.add(SURFACE_SIZE) };
    while cursor < end {
        unsafe { ptr::write_volatile(cursor, 0) };
        cursor = unsafe { cursor.add(1) };
    }
    this
}

/// The active constructor (original: the direct `bl 0x08106a8c`). Host
/// tests install a recording mock; the real port replaces the default
/// when it exists.
pub static mut SURFACE_CTOR: SurfaceCtor = zeroing_surface_ctor;

/// surface_new — original: `FUN_081066a8` @ 0x081066a8 (64 bytes; 23
/// `bl` call sites).
///
/// Allocates the 0x54-byte surface object with `operator_new` and
/// constructs it in place, forwarding all nine arguments unchanged,
/// and returns the constructor's result (`this`). A NULL allocation is
/// NOT checked — the original calls the ctor unconditionally.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn surface_new(
    format: u32,
    width: u32,
    stride: u32,
    height: u32,
    flags: u32,
    plane0: u32,
    plane1: u32,
    plane2: u32,
    plane3: u32,
) -> *mut u8 {
    let block = unsafe { operator_new(SURFACE_SIZE) };
    // The slot read stays between the allocation and the call, exactly
    // where the original's `bl` is — the service_manager_get.rs
    // contract.
    let ctor = unsafe { ptr::read_volatile(ptr::addr_of!(SURFACE_CTOR)) };
    unsafe { ctor(block, format, width, stride, height, flags, plane0, plane1, plane2, plane3) }
}

/// `render_context_create_image_surface` — original: `FUN_0828d458` @
/// `0x0828d458` (136 bytes; 2 verified BL instructions: one plain `bl` and
/// one predicated `blne`).
///
/// Raw ARM spans `0x0828d458..0x0828d4e0`; the next real function starts at
/// `0x0828d4e0` with `push {r4, lr}`. Binary decoding finds four direct
/// callers, all plain `bl`: `0x0828c7cc`, `0x0828cc98`, `0x0828e1b4`, and
/// `0x0828e3b4`. It maps image format RGB565 (`0x0565`) to surface format 2
/// and grayscale (`0x0065`) or packed 24-bit-alpha (`0x1888`) to format 3.
/// Any other image format takes the predicated fatal `heap_panic` call. It
/// constructs a surface with the image's `+0x04` plane base, width
/// `+0x2c - +0x24`, stride `+0x28 - +0x20`, height `image + 0x08`, and
/// fixed flags 2. Deliberate deviations: none.
///
/// Both pointers must be four-byte aligned; `image` must also contain an
/// aligned format halfword at `+0x14`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn render_context_create_image_surface(
    render_context: *const u8,
    image: *const u8,
) -> *mut u8 {
    let image_format = unsafe { (image.add(0x14) as *const u16).read() };
    let surface_format = match image_format {
        0x0565 => 2,
        0x0065 | 0x1888 => 3,
        _ => unsafe { crate::heap::veneers::heap_panic() },
    };
    let plane0 = unsafe { (image.add(4) as *const u32).read() };
    let width = unsafe {
        (render_context.add(0x2c) as *const u32)
            .read()
            .wrapping_sub((render_context.add(0x24) as *const u32).read())
    };
    let stride = unsafe {
        (render_context.add(0x28) as *const u32)
            .read()
            .wrapping_sub((render_context.add(0x20) as *const u32).read())
    };
    let height = unsafe { (image.add(8) as *const u32).read() };

    unsafe { surface_new(surface_format, width, stride, height, 2, plane0, 0, 0, 0) }
}

/// A rectangle consumed by the unported surface rasterizer
/// `FUN_0810674c`. The original passes this four-word record as
/// `{x_min, x_max, y_min, y_max}`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceRectangle {
    pub x_min: u32,
    pub x_max: u32,
    pub y_min: u32,
    pub y_max: u32,
}

/// The unported rectangle rasterizer at 0x0810674c. It takes the
/// surface, pixel-color record, and inclusive rectangle.
pub type SurfaceFillRect = unsafe extern "C" fn(*mut u8, *const u8, *const SurfaceRectangle);

/// Default until `FUN_0810674c` is ported. It intentionally preserves
/// memory, so [`surface_fill`] is not hook-ready by itself.
unsafe extern "C" fn unported_surface_fill_rect(
    _surface: *mut u8,
    _color: *const u8,
    _rect: *const SurfaceRectangle,
) {
}

/// Active implementation of the direct `bl 0x0810674c`. Host tests
/// replace this slot; a future rasterizer port replaces the default.
pub static mut SURFACE_FILL_RECT: SurfaceFillRect = unported_surface_fill_rect;

/// surface_fill — original: `FUN_0810671c` @ 0x0810671c (48 bytes; 7
/// `bl` call sites, decoded over every ARM `bl` word in osos.dec).
///
/// Constructs the inclusive full-surface rectangle
/// `{0, *(surface + 0x10) - 1, 0, *(surface + 0x0c) - 1}` on its stack,
/// invokes the rectangle rasterizer at 0x0810674c with that rectangle
/// and `color`, then returns the original surface pointer in r0. The
/// callee itself validates its two maxima against those same fields; a
/// zero extent intentionally wraps to `u32::MAX` before that validation.
///
/// The Ghidra extent is exact: 0x0810674c immediately opens the next
/// function. Callers make one plain call (0x080cd184) and six `blne`
/// calls (0x080cd19c, 0x081202f8, 0x08120308, 0x08120318, 0x08120330,
/// 0x08120340), so the wrapper has no NULL guard and callers gate
/// optional surfaces themselves.
///
/// Deliberate deviation: the direct rasterizer call uses
/// [`SURFACE_FILL_RECT`] until that 560-byte callee is ported. Its
/// default is a documented no-op, so this function is not hook-ready.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn surface_fill(surface: *mut u8, color: *const u8) -> *mut u8 {
    let rect = SurfaceRectangle {
        x_min: 0,
        x_max: (surface.add(0x10) as *const u32).read_volatile().wrapping_sub(1),
        y_min: 0,
        y_max: (surface.add(0x0c) as *const u32).read_volatile().wrapping_sub(1),
    };
    let fill_rect = ptr::read_volatile(ptr::addr_of!(SURFACE_FILL_RECT));
    fill_rect(surface, color, &rect);
    surface
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::HEAP_OPS;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that swaps the globals below (the
    /// cxx/settings.rs SETTINGS_LOCK pattern).
    static SURFACE_NEW_LOCK: Mutex<()> = Mutex::new(());

    /// Serializes tests that replace [`SURFACE_FILL_RECT`].
    static SURFACE_FILL_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Debug, Eq, PartialEq)]
    struct SurfaceFillCall {
        surface: usize,
        color: usize,
        rect: SurfaceRectangle,
    }

    static mut SURFACE_FILL_CALLS: Vec<SurfaceFillCall> = Vec::new();

    unsafe extern "C" fn recording_surface_fill_rect(
        surface: *mut u8,
        color: *const u8,
        rect: *const SurfaceRectangle,
    ) {
        (*ptr::addr_of_mut!(SURFACE_FILL_CALLS)).push(SurfaceFillCall {
            surface: surface as usize,
            color: color as usize,
            rect: ptr::read_volatile(rect),
        });
    }

    fn mock_surface_fill() -> MutexGuard<'static, ()> {
        let guard = SURFACE_FILL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            SURFACE_FILL_RECT = recording_surface_fill_rect;
            (*ptr::addr_of_mut!(SURFACE_FILL_CALLS)).clear();
        }
        guard
    }

    fn restore_surface_fill(guard: MutexGuard<'static, ()>) {
        unsafe { SURFACE_FILL_RECT = unported_surface_fill_rect };
        drop(guard);
    }

    fn set_word(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn plane_slots(format: u8, plane0: u32, plane1: u32, plane2: u32) -> SurfacePlaneSlots {
        SurfacePlaneSlots {
            _before_format: [0; 0x08],
            format,
            _before_planes: [0; 0x1b],
            plane0,
            plane1,
            plane2,
        }
    }

    /// The block the stub allocator hands out.
    static mut ARENA: [u8; SURFACE_SIZE] = [0xa5; SURFACE_SIZE];

    /// Sizes passed to `operator new`, in order.
    static mut ALLOC_SIZES: Vec<usize> = Vec::new();

    /// Arguments the recording constructor saw, `this` first.
    static mut CTOR_ARGS: Vec<usize> = Vec::new();

    /// What the recording constructor returns.
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn stub_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        (*ptr::addr_of_mut!(ALLOC_SIZES)).push(size);
        ptr::addr_of_mut!(ARENA) as *mut u8
    }

    unsafe extern "C" fn stub_create(
        _desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        unreachable!("DEFAULT_HEAP is pre-seeded, so the lazy init must not run");
    }

    #[allow(clippy::too_many_arguments)]
    unsafe extern "C" fn recording_ctor(
        this: *mut u8,
        format: u32,
        width: u32,
        stride: u32,
        height: u32,
        flags: u32,
        plane0: u32,
        plane1: u32,
        plane2: u32,
        plane3: u32,
    ) -> *mut u8 {
        let args = &mut *ptr::addr_of_mut!(CTOR_ARGS);
        args.push(this as usize);
        args.push(format as usize);
        args.push(width as usize);
        args.push(stride as usize);
        args.push(height as usize);
        args.push(flags as usize);
        args.push(plane0 as usize);
        args.push(plane1 as usize);
        args.push(plane2 as usize);
        args.push(plane3 as usize);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    /// A non-NULL dummy heap handle so `lazy_init_default_heap` is a
    /// no-op and `stub_create` is never reached.
    static mut FAKE_HEAP: usize = 0;

    fn arena() -> *mut u8 {
        ptr::addr_of_mut!(ARENA) as *mut u8
    }

    /// Installs the stub allocator plus the recording constructor.
    fn mock(ctor_result: *mut u8) -> MutexGuard<'static, ()> {
        let guard = SURFACE_NEW_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = stub_alloc;
            ops.create = stub_create;
            HEAP_OPS = ops;
            DEFAULT_HEAP = ptr::addr_of_mut!(FAKE_HEAP) as *mut HeapDescriptorDescriptor;
            SURFACE_CTOR = recording_ctor;
            CTOR_RESULT = ctor_result;
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CTOR_ARGS)).clear();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
            DEFAULT_HEAP = ptr::null_mut();
            SURFACE_CTOR = zeroing_surface_ctor;
        }
        drop(guard);
    }

    #[test]
    fn allocates_0x54_constructs_and_returns_the_object() {
        let constructed = unsafe { arena().add(16) };
        let guard = mock(constructed);
        unsafe {
            // The boot-screen caller's argument tuple, verbatim.
            let result = surface_new(3, 0xf0, 0x140, 0x140, 2, 0xdead_beef, 0, 0, 0);
            assert_eq!(result, constructed, "the ctor's `this` return is the factory's r0");
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![SURFACE_SIZE],
                "the `mov r0, #0x54` immediate"
            );
            assert_eq!(
                *ptr::addr_of!(CTOR_ARGS),
                std::vec![
                    arena() as usize,
                    3,
                    0xf0,
                    0x140,
                    0x140,
                    2,
                    0xdead_beef,
                    0,
                    0,
                    0,
                ],
                "the raw block, then all nine arguments in order"
            );
        }
        restore(guard);
    }

    #[test]
    fn argument_order_is_not_shuffled() {
        let guard = mock(arena());
        unsafe {
            surface_new(11, 22, 33, 44, 55, 66, 77, 88, 99);
            let args = &*ptr::addr_of!(CTOR_ARGS);
            assert_eq!(
                args[1..],
                [11, 22, 33, 44, 55, 66, 77, 88, 99],
                "register args lead, the five stack args follow"
            );
        }
        restore(guard);
    }

    #[test]
    fn default_stub_zeroes_the_block_and_returns_it() {
        let guard = SURFACE_NEW_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ARENA = [0xa5; SURFACE_SIZE];
            let this = arena();
            assert_eq!(zeroing_surface_ctor(this, 1, 2, 3, 4, 5, 6, 7, 8, 9), this);
            assert!(
                (*ptr::addr_of!(ARENA)).iter().all(|&b| b == 0),
                "all 0x54 bytes zeroed"
            );
            ARENA = [0xa5; SURFACE_SIZE];
        }
        drop(guard);
    }

    #[test]
    fn fills_the_inclusive_surface_bounds_and_returns_surface() {
        let guard = mock_surface_fill();
        let mut surface = [0u8; 0x18];
        set_word(&mut surface, 0x10, 320);
        set_word(&mut surface, 0x0c, 240);
        let color = [0x12, 0x34, 0x56, 0x78];
        let surface_ptr = surface.as_mut_ptr();

        unsafe {
            assert_eq!(surface_fill(surface_ptr, color.as_ptr()), surface_ptr);
            assert_eq!(
                *ptr::addr_of!(SURFACE_FILL_CALLS),
                std::vec![SurfaceFillCall {
                    surface: surface_ptr as usize,
                    color: color.as_ptr() as usize,
                    rect: SurfaceRectangle {
                        x_min: 0,
                        x_max: 319,
                        y_min: 0,
                        y_max: 239,
                    },
                }],
                "the wrapper forwards the full inclusive rectangle"
            );
        }
        restore_surface_fill(guard);
    }

    #[test]
    fn zero_extent_wraps_before_the_rasterizer_validates_it() {
        let guard = mock_surface_fill();
        let mut surface = [0u8; 0x18];
        set_word(&mut surface, 0x10, 0);
        set_word(&mut surface, 0x0c, 1);
        let color = [0u8; 4];

        unsafe {
            surface_fill(surface.as_mut_ptr(), color.as_ptr());
            assert_eq!(
                (&*ptr::addr_of!(SURFACE_FILL_CALLS))[0].rect,
                SurfaceRectangle {
                    x_min: 0,
                    x_max: u32::MAX,
                    y_min: 0,
                    y_max: 0,
                },
                "the two raw `sub #1` instructions do not guard zero"
            );
        }
        restore_surface_fill(guard);
    }

    #[test]
    fn planar_surface_installs_three_nonzero_planes_once() {
        let mut surface = plane_slots(0, 0, 0, 0);

        unsafe {
            surface_set_external_planes_if_empty(
                (&mut surface as *mut SurfacePlaneSlots).cast(),
                0x1111_0000,
                0x2222_0000,
                0x3333_0000,
                0,
            );
        }

        assert_eq!(
            (surface.plane0, surface.plane1, surface.plane2),
            (0x1111_0000, 0x2222_0000, 0x3333_0000),
            "format 0 accepts precisely its three required plane words"
        );
    }

    #[test]
    fn two_plane_surface_requires_unused_inputs_and_empty_all_slots() {
        let mut surface = plane_slots(1, 0, 0, 0);
        unsafe {
            surface_set_external_planes_if_empty((&mut surface as *mut SurfacePlaneSlots).cast(), 0x4444_0000, 0x5555_0000, 0, 0);
        }
        assert_eq!(
            (surface.plane0, surface.plane1, surface.plane2),
            (0x4444_0000, 0x5555_0000, 0),
            "format 1 owns only the first two slots"
        );

        let mut nonempty = plane_slots(1, 0, 0, 0x9999_0000);
        unsafe {
            surface_set_external_planes_if_empty((&mut nonempty as *mut SurfacePlaneSlots).cast(), 1, 2, 0, 0);
        }
        assert_eq!(
            (nonempty.plane0, nonempty.plane1, nonempty.plane2),
            (0, 0, 0x9999_0000),
            "even its unused third plane blocks a second allocation"
        );

        let mut unexpected_plane = plane_slots(1, 0, 0, 0);
        unsafe {
            surface_set_external_planes_if_empty((&mut unexpected_plane as *mut SurfacePlaneSlots).cast(), 1, 2, 3, 0);
        }
        assert_eq!(
            (unexpected_plane.plane0, unexpected_plane.plane1, unexpected_plane.plane2),
            (0, 0, 0),
            "format 1 rejects third-plane input"
        );
    }

    #[test]
    fn unsupported_or_incomplete_plane_sets_leave_the_surface_unchanged() {
        let mut unsupported = plane_slots(2, 0, 0, 0);
        let mut missing_planar_plane = plane_slots(0, 0, 0, 0);
        let mut unexpected_fourth_plane = plane_slots(0, 0, 0, 0);

        unsafe {
            surface_set_external_planes_if_empty((&mut unsupported as *mut SurfacePlaneSlots).cast(), 1, 2, 3, 0);
            surface_set_external_planes_if_empty((&mut missing_planar_plane as *mut SurfacePlaneSlots).cast(), 1, 0, 3, 0);
            surface_set_external_planes_if_empty((&mut unexpected_fourth_plane as *mut SurfacePlaneSlots).cast(), 1, 2, 3, 4);
        }

        assert_eq!(
            (unsupported.plane0, unsupported.plane1, unsupported.plane2),
            (0, 0, 0),
            "formats other than 0 and 1 return before considering inputs"
        );
        assert_eq!(
            (missing_planar_plane.plane0, missing_planar_plane.plane1, missing_planar_plane.plane2),
            (0, 0, 0),
            "format 0 requires every supplied plane to be nonzero"
        );
        assert_eq!(
            (unexpected_fourth_plane.plane0, unexpected_fourth_plane.plane1, unexpected_fourth_plane.plane2),
            (0, 0, 0),
            "format 0 requires its fourth argument to remain zero"
        );
    }
    #[repr(align(4))]
    struct AlignedBytes<const N: usize>([u8; N]);

    #[test]
    fn image_bounds_forward_geometry_plane_and_recognized_formats() {
        let mut bounds = AlignedBytes([0; 0x30]);
        let mut image = AlignedBytes([0; 0x18]);
        set_word(&mut bounds.0, 0x20, 0xffff_fffe);
        set_word(&mut bounds.0, 0x24, 0x0000_0010);
        set_word(&mut bounds.0, 0x28, 0x0000_0003);
        set_word(&mut bounds.0, 0x2c, 0x0000_0030);
        set_word(&mut image.0, 4, 0xdead_beef);
        set_word(&mut image.0, 8, 0x0000_0140);
        image.0[0x14..0x16].copy_from_slice(&0x0565u16.to_le_bytes());

        let constructed = unsafe { arena().add(12) };
        let guard = mock(constructed);
        unsafe {
            assert_eq!(
                render_context_create_image_surface(bounds.0.as_ptr(), image.0.as_ptr()),
                constructed
            );
            assert_eq!(
                *ptr::addr_of!(CTOR_ARGS),
                std::vec![
                    arena() as usize, 2, 0x20, 5, 0x140, 2, 0xdead_beef, 0, 0, 0,
                ],
                "RGB565 maps to surface format 2; geometry and plane preserve raw argument order"
            );

            (*ptr::addr_of_mut!(CTOR_ARGS)).clear();
            set_word(&mut bounds.0, 0x20, 5);
            set_word(&mut bounds.0, 0x28, 3);
            image.0[0x14..0x16].copy_from_slice(&0x0065u16.to_le_bytes());
            render_context_create_image_surface(bounds.0.as_ptr(), image.0.as_ptr());
            assert_eq!(
                (&*ptr::addr_of!(CTOR_ARGS))[1..5],
                [3, 0x20, (u32::MAX - 1) as usize, 0x140],
                "grayscale maps to surface format 3 and subtraction intentionally wraps"
            );
        }
        restore(guard);
    }
}
