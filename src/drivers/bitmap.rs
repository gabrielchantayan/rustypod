//! The **bitmap-resource wrapper** cluster (0x08299xxx) — the lazy
//! "BMap" handle UI code passes around by pointer and the accessors
//! that query or draw it.
//!
//! A wrapper is a caller-owned block laid out as:
//!
//! ```text
//! +0x00 ptr  resource-provider chain head (resource_chain_find's
//!            first argument, app/resource_chain.rs)
//! +0x04 u32  resource id within the chain
//! +0x08 u8   loaded flag — clear until the lazy loader resolves and
//!            parses the resource
//! +0x0c ..   inline argument block handed to the bitmap parser
//!            (FUN_082645a0) by the loader
//! +0xc4 ptr  the parsed bitmap object, stored by the loader
//! ```
//!
//! The loader `FUN_082993b4` @ 0x082993b4 (80 bytes total: 76 bytes of
//! code plus the "BMap" literal @ 0x08299400; 8 `bl` call sites) is a lazy
//! initializer: if the +0x08 flag is clear it resolves the (head, id) pair through
//! `resource_chain_find` @ 0x0827216c with the kind literal
//! 0x424d6170 ("BMap" big-endian — `ResourceKind::BITMAP` in
//! app/resource_chain.rs), allocates 0x44 bytes via `operator_new`,
//! parses the resource into it with FUN_082645a0, stores the object at
//! +0xc4 and raises the flag. A failed lookup leaves the flag clear,
//! which is exactly the state the query below treats as "no bounds".
//!
//! [`BitmapWrapper`] represents those fields directly. On the 32-bit target
//! the fields are exactly at their decoded addresses. Its native pointer
//! fields expand on a 64-bit host, so host fixtures use the matching
//! `#[repr(C)]` layout instead of overlapping a pointer and the next u32.

use crate::app::resource_chain::{resource_chain_find, ResourceKind, ResourceProvider};
use crate::heap::veneers::operator_new;

/// The target's 0xC8-byte bitmap-resource wrapper. `#[repr(C)]` preserves
/// the target's four-byte resource-head field, id, flag, argument block, and
/// result pointer placements on ARM; its native pointer layout is also valid
/// for host fixtures.
#[repr(C)]
struct BitmapWrapper {
    resource_head: *mut ResourceProvider,
    resource_id: u32,
    loaded: u8,
    _padding_after_loaded: [u8; 3],
    parser_args: [u8; 0xb8],
    object: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xc4] = [0; core::mem::offset_of!(BitmapWrapper, object)];

#[inline(always)]
unsafe fn wrapper_mut(wrapper: *mut u8) -> *mut BitmapWrapper {
    wrapper.cast()
}

/// Runs the parser for a resolved "BMap" resource. The parser at
/// `FUN_082645a0` is still unported, so this is the cluster's remaining
/// dispatch seam.
pub type BitmapParseFn = unsafe extern "C" fn(
    object: *mut u8,
    args: *mut u8,
    resource: *mut u8,
) -> *mut u8;

/// Parsed bitmap prefix ending in its inner-object pointer at +0x1c on ARM.
/// `#[repr(C)]` naturally inserts the four host-only alignment bytes before
/// the native-width pointer.
#[repr(C)]
struct ParsedBitmap {
    _prefix: [u8; 0x1c],
    inner: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::offset_of!(ParsedBitmap, inner)];

/// +0x98 within the inner object: the first of four bounds words.
const INNER_BOUNDS: usize = 0x98;

/// Indirect dispatch for this cluster's unported callees (the house
/// pattern — see `drivers/display_layer.rs`'s `LayerDriverHooks`).
#[derive(Clone, Copy)]
pub struct BitmapHooks {
    /// `FUN_082645a0`: parses a resolved bitmap resource into the freshly
    /// allocated 0x44-byte object. The stock parser is still unported, so
    /// this is the sole loader dependency that remains indirect. Default:
    /// return the allocation unchanged; this preserves the loader's result
    /// flow but is NOT hook-ready for an actual bitmap resource.
    pub parse: BitmapParseFn,
    /// `FUN_08262bdc` @ 0x08262bdc (224 bytes; 60 `bl` call sites,
    /// binary-scanned): the rect-offsetting draw helper — adds the draw
    /// context's +0x2c/+0x30 origin into both four-word rects and the
    /// object's, then invokes the text/layout draw engine `0x080f1600`
    /// with the surface pointers `*(ctx + 0x1c) + 4` and
    /// `*(object + 0x1c) + 4`, the two colours at ctx +0x11/+0x15, the
    /// ctx +0x10 style byte, the ctx +0x34 clip rect, and the two
    /// trailing words (`alpha`, `reserved`) verbatim.
    /// Default: no-op — an unloaded wrapper never reaches it, and for a
    /// loaded one the wired build simply draws nothing. NOT hook-ready:
    /// the helper (and the engine beneath it) must be ported before the
    /// draw path can run on target.
    pub draw: unsafe extern "C" fn(
        ctx: *mut u8,
        object: *mut u8,
        rect_a: *const u32,
        rect_b: *const u32,
        alpha: u32,
        reserved: u32,
    ),
}

unsafe extern "C" fn bitmap_parse_stub(
    object: *mut u8,
    _args: *mut u8,
    _resource: *mut u8,
) -> *mut u8 {
    object
}

unsafe extern "C" fn draw_stub(
    _ctx: *mut u8,
    _object: *mut u8,
    _rect_a: *const u32,
    _rect_b: *const u32,
    _alpha: u32,
    _reserved: u32,
) {
}

/// Wired defaults: a pass-through parser for the unported parser and a no-op
/// draw helper for the unported renderer.
pub(crate) const DEFAULT_BITMAP_HOOKS: BitmapHooks = BitmapHooks {
    parse: bitmap_parse_stub,
    draw: draw_stub,
};

/// The active hooks. Host tests swap in recording mocks and restore.
pub static mut BITMAP_HOOKS: BitmapHooks = DEFAULT_BITMAP_HOOKS;

/// Volatile read so LLVM cannot fold the default stubs in and delete
/// the dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn hooks() -> BitmapHooks {
    core::ptr::read_volatile(core::ptr::addr_of!(BITMAP_HOOKS))
}

/// bitmap_ensure_loaded — original: `FUN_082993b4` @ 0x082993b4
/// (80 bytes: 76 bytes of code plus the `"BMap"` literal at 0x08299400;
/// **8 plain `bl` call sites**, zero predicated calls and no direct tail
/// branch, binary-scanned from osos.dec).
///
/// Lazily resolves the wrapper's `(resource_head, resource_id)` as a
/// `"BMap"` resource. If the loaded byte is already non-zero it returns
/// unchanged. Otherwise a failed lookup also returns unchanged; a successful
/// lookup allocates 0x44 bytes through `operator_new`, invokes the bitmap
/// parser on the allocation, wrapper-owned parser arguments, and resource,
/// stores the parser result, then raises the loaded byte. Like the original,
/// allocation failure is passed to the parser without a NULL check.
///
/// Deliberate deviation: `FUN_082645a0` remains behind
/// [`BitmapHooks::parse`]. Its default returns the allocation unchanged,
/// which preserves this loader's result and flag stores but cannot initialize
/// bitmap contents; a wired resource provider is therefore not hook-ready
/// until the parser itself is ported.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bitmap_ensure_loaded(wrapper: *mut u8) {
    let wrapper = &mut *wrapper_mut(wrapper);
    if core::ptr::addr_of!(wrapper.loaded).read_volatile() != 0 {
        return;
    }

    let resource = resource_chain_find(
        core::ptr::addr_of!(wrapper.resource_head).read_volatile(),
        ResourceKind::BITMAP,
        core::ptr::addr_of!(wrapper.resource_id).read_volatile(),
    );
    if resource.is_null() {
        return;
    }

    let object = operator_new(0x44);
    let parsed = (hooks().parse)(object, wrapper.parser_args.as_mut_ptr(), resource);
    core::ptr::addr_of_mut!(wrapper.object).write_volatile(parsed);
    core::ptr::addr_of_mut!(wrapper.loaded).write_volatile(1);
}

/// bitmap_object_read_bounds — original: `FUN_082a1dbc` @ 0x082a1dbc
/// (24 bytes; 25 plain `bl` call sites, no predicated branches or tail
/// branches, binary-scanned).
///
/// Reads the parsed bitmap's inner-object pointer at +0x1c, then copies
/// its four bounds words at +0x98..+0xa4 into `out`. The original loads
/// all four words with `ldm` before storing with `stm`; loading every
/// word before the first store preserves that behavior when `out`
/// aliases the source bounds.
///
/// Deliberate deviation: the target's 4-byte +0x1c pointer is stored
/// at +0x20 in 64-bit host fixtures to retain alignment; it remains
/// exactly +0x1c in the ARM build.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bitmap_object_read_bounds(object: *mut u8, out: *mut u32) {
    let parsed = &*object.cast::<ParsedBitmap>();
    let inner = core::ptr::addr_of!(parsed.inner).read_volatile();
    let bounds = inner.add(INNER_BOUNDS) as *mut u32;
    let word0 = bounds.read_volatile();
    let word1 = bounds.add(1).read_volatile();
    let word2 = bounds.add(2).read_volatile();
    let word3 = bounds.add(3).read_volatile();
    out.write_volatile(word0);
    out.add(1).write_volatile(word1);
    out.add(2).write_volatile(word2);
    out.add(3).write_volatile(word3);
}

/// bitmap_query_bounds — original: `FUN_08299368` @ 0x08299368
/// (76 bytes; 59 `bl` call sites, no tail branches, binary-scanned).
///
/// The bitmap wrapper's bounding-rectangle query: fills the 16-byte
/// block at `out` with the four bounds words of the wrapper's parsed
/// bitmap object. The algorithm:
///
/// 1. Run [`bitmap_ensure_loaded`] **first, unconditionally** — a wrapper
///    whose resource has not been resolved yet is loaded on demand here.
/// 2. If the loaded flag (+0x08) is still clear (no resource, or the
///    lookup failed), zero all four words of `out` with four word
///    stores (`streq`).
/// 3. Otherwise invoke the parsed object's bounds getter
///    (`FUN_082a1dbc`) on the +0xc4 object, filling a 16-byte stack
///    block, then copy the four words into `out` (`ldmia`/`stmia`).
///
/// Callers read the result as a rectangle of four signed words — the
/// layout code @ 0x08141e30 subtracts word\[1\] from word\[3\] for a
/// height and hands the block to the draw-in-rect helper
/// `FUN_082991a4`, i.e. the words are edges, not an origin/size pair
/// [INFERENCE from that caller's arithmetic].
///
/// Return convention: the original's stack block *is* its r0..r3 spill
/// (`stmdb sp!,{r0,r1,r2,r3,...}` at the entry), and the epilogue pops
/// the first two slots back into r0/r1 — a small-struct return of the
/// first two bounds words on the query path. On the zero path the spill
/// slots are never written, so r0/r1 come back as the function's own
/// first two arguments (`out`, `wrapper`) — a quirk the port keeps
/// verbatim, packing word0 into the low half and word1 into the high
/// half of the returned `u64` (r0/r1 on the 32-bit target).
///
/// Deviations:
///
/// - `arg3`/`arg4` exist only because the original spills all four
///   argument registers and uses the spill slots as the query block;
///   the getter always overwrites all four words, making them
///   unobservable.
/// - The `#[repr(C)]` wrapper layout retains the exact target +0xc4 object
///   field while moving it to the naturally aligned +0xc8 on 64-bit hosts.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bitmap_query_bounds(
    out: *mut u32,
    wrapper: *mut u8,
    arg3: u32,
    arg4: u32,
) -> u64 {
    // The original's r0..r3 spill slots double as the query block.
    let mut bounds: [u32; 4] = [out as u32, wrapper as u32, arg3, arg4];
    bitmap_ensure_loaded(wrapper);
    let wrapper = &mut *wrapper_mut(wrapper);
    if core::ptr::addr_of!(wrapper.loaded).read_volatile() == 0 {
        for slot in 0..4 {
            (out.add(slot)).write_volatile(0);
        }
    } else {
        let object = core::ptr::addr_of!(wrapper.object).read_volatile();
        bitmap_object_read_bounds(object, bounds.as_mut_ptr());
        for slot in 0..4 {
            (out.add(slot)).write_volatile(bounds[slot]);
        }
    }
    ((bounds[1] as u64) << 32) | bounds[0] as u64
}

/// bitmap_draw_in_rect — original: `FUN_082991a4` @ 0x082991a4
/// (76 bytes; 42 `bl` call sites, all plain `bl`, no tail branches,
/// no data-word references — binary-scanned).
///
/// The bitmap wrapper's draw-in-rect accessor, the sibling of
/// [`bitmap_query_bounds`] running the same loader-then-flag-check
/// shape. The algorithm:
///
/// 1. Run [`bitmap_ensure_loaded`] **first, unconditionally** — exactly as
///    the bounds query does.
/// 2. If the loaded flag (+0x08) is still clear, return without
///    drawing anything.
/// 3. Otherwise dispatch the rect-offsetting draw helper
///    `FUN_08262bdc` (through [`BITMAP_HOOKS`]) as
///    `draw(ctx, *(wrapper + 0xc4), rect_a, rect_b, alpha, 0)` — the
///    helper re-bases both four-word rects and the object's by the
///    context's +0x2c/+0x30 origin and invokes the text/layout draw
///    engine @ 0x080f1600. The original passes a hard zero for the
///    helper's sixth word (`mov r3, #0; str r3, [sp, #4]`).
///
/// Argument order: the wrapper is `this` (r0) — it is consumed by the
/// loader and the field reads, and is NOT forwarded; the draw helper
/// receives the caller's second argument (`ctx`) as its first. Every
/// sampled call site (0x08141f7c, 0x081989fc, 0x082130a8, 0x0829930c,
/// ...) passes `0xff` for `alpha`, so the word is the draw opacity
/// [INFERENCE from the uniform constant]; `rect_a`/`rect_b` are two
/// four-word rect blocks (0x08141f7c passes the same block twice, the
/// bounds block [`bitmap_query_bounds`] just filled).
///
/// Return convention: the original's epilogue (`pop {r2, r3, ...pc}`)
/// leaves r0 holding the draw helper's return on the draw path and
/// the zero flag byte on the skip path — but every sampled call site
/// overwrites r0 with its very next instruction, so the port is
/// `void` (the string_id_record.rs setter precedent).
///
/// Deviations:
///
/// - The `#[repr(C)]` wrapper layout retains the exact target +0xc4 object
///   field while moving it to the naturally aligned +0xc8 on 64-bit hosts.
/// - The draw helper rides the [`BITMAP_HOOKS`] seam with a no-op
///   default (documented, NOT hook-ready — the stock helper and the
///   engine beneath it must be ported before the draw path runs on
///   target). With the default hooks a loaded wrapper draws nothing.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bitmap_draw_in_rect(
    wrapper: *mut u8,
    ctx: *mut u8,
    rect_a: *const u32,
    rect_b: *const u32,
    alpha: u32,
) {
    bitmap_ensure_loaded(wrapper);
    let wrapper = &mut *wrapper_mut(wrapper);
    if core::ptr::addr_of!(wrapper.loaded).read_volatile() != 0 {
        let object = core::ptr::addr_of!(wrapper.object).read_volatile();
        (hooks().draw)(ctx, object, rect_a, rect_b, alpha, 0);
    }
}

/// bitmap_get_loaded_object — original: `FUN_082991f0` @ 0x082991f0
/// (28 bytes; **9 plain `bl` call sites**, no predicated or tail branches,
/// binary-scanned by decoding every B/BL word in osos.dec).
///
/// object. [`bitmap_ensure_loaded`] always runs first. If it leaves the
/// +0x08 loaded flag clear, the original returns zero; otherwise it returns
/// the pointer stored at +0xc4.
///
/// The single data-word reference at 0x089b0b20 places this accessor in a
/// bitmap-wrapper vtable, so callers may dispatch it virtually. All nine
/// direct call sites are plain `bl`; each checks its result before consuming
/// the parsed object.
///
/// Deliberate deviation: the `#[repr(C)]` wrapper places this native pointer
/// at +0xc8 in 64-bit host fixtures; it remains exactly +0xc4 on ARM.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bitmap_get_loaded_object(wrapper: *mut u8) -> *mut u8 {
    bitmap_ensure_loaded(wrapper);
    let wrapper = &mut *wrapper_mut(wrapper);
    if core::ptr::addr_of!(wrapper.loaded).read_volatile() == 0 {
        core::ptr::null_mut()
    } else {
        core::ptr::addr_of!(wrapper.object).read_volatile()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Mutex as StdMutex, MutexGuard};

    /// A native-layout bitmap wrapper. The structure keeps every target
    /// field distinct on both ARM and the 64-bit host.
    #[repr(align(8))]
    struct Wrapper(BitmapWrapper);

    impl Wrapper {
        fn new() -> Self {
            Wrapper(BitmapWrapper {
                resource_head: core::ptr::null_mut(),
                resource_id: 0,
                loaded: 0,
                _padding_after_loaded: [0; 3],
                parser_args: [0; 0xb8],
                object: core::ptr::null_mut(),
            })
        }
        fn ptr(&mut self) -> *mut u8 {
            core::ptr::addr_of_mut!(self.0).cast()
        }
        fn set_loaded(&mut self, value: u8) {
            self.0.loaded = value;
        }
        fn set_object(&mut self, value: *mut u8) {
            self.0.object = value;
        }
        fn set_resource(&mut self, head: *mut ResourceProvider, id: u32) {
            self.0.resource_head = head;
            self.0.resource_id = id;
        }
    }

    /// The parsed object has its inner-object pointer at +0x1c on target.
    /// The shared [`ParsedBitmap`] layout supplies host alignment.
    #[repr(align(8))]
    struct ParsedBitmapFixture([u8; 0x44]);

    impl ParsedBitmapFixture {
        fn new() -> Self {
            ParsedBitmapFixture([0; 0x44])
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn set_inner_object(&mut self, inner: *mut u8) {
            unsafe {
                core::ptr::addr_of_mut!((*self.ptr().cast::<ParsedBitmap>()).inner)
                    .write_volatile(inner);
            }
        }
    }

    /// Four recognizable inner-object bounds words.
    const BOUNDS: [u32; 4] = [0x1111_0000, 0x2222_0000, 0x3333_0000, 0x4444_0000];

    /// Full inner-object fixture: the getter reads its four-word bounds
    /// block at +0x98, so it must extend through +0xa4.
    #[repr(align(8))]
    struct BitmapInner([u32; (INNER_BOUNDS + 16) / 4]);

    impl BitmapInner {
        fn new(bounds: [u32; 4]) -> Self {
            let mut inner = BitmapInner([0; (INNER_BOUNDS + 16) / 4]);
            inner.0[INNER_BOUNDS / 4..INNER_BOUNDS / 4 + 4].copy_from_slice(&bounds);
            inner
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr() as *mut u8
        }
        fn bounds_ptr(&mut self) -> *mut u32 {
            unsafe { self.0.as_mut_ptr().add(INNER_BOUNDS / 4) }
        }
        fn bounds(&self) -> [u32; 4] {
            [
                self.0[INNER_BOUNDS / 4],
                self.0[INNER_BOUNDS / 4 + 1],
                self.0[INNER_BOUNDS / 4 + 2],
                self.0[INNER_BOUNDS / 4 + 3],
            ]
        }
    }

    /// The parsed object and inner bounds that loader fixtures return.
    static mut FAKE_OBJECT: ParsedBitmapFixture = ParsedBitmapFixture([0; 0x44]);
    static mut FAKE_INNER: BitmapInner = BitmapInner([0; (INNER_BOUNDS + 16) / 4]);

    /// Serializes tests that swap [`BITMAP_HOOKS`] or use the fake parsed
    /// object.
    static HOOK_LOCK: StdMutex<()> = StdMutex::new(());

    static PARSES: AtomicU32 = AtomicU32::new(0);
    static PARSE_OBJECT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static PARSE_ARGS: AtomicUsize = AtomicUsize::new(usize::MAX);
    static PARSE_RESOURCE: AtomicUsize = AtomicUsize::new(usize::MAX);

    static DRAWS: AtomicU32 = AtomicU32::new(0);
    static LAST_DRAW_CTX: AtomicUsize = AtomicUsize::new(usize::MAX);
    static LAST_DRAW_OBJECT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static LAST_DRAW_RECT_A: AtomicUsize = AtomicUsize::new(usize::MAX);
    static LAST_DRAW_RECT_B: AtomicUsize = AtomicUsize::new(usize::MAX);
    static LAST_DRAW_ALPHA: AtomicU32 = AtomicU32::new(u32::MAX);
    static LAST_DRAW_RESERVED: AtomicU32 = AtomicU32::new(u32::MAX);

    static mut BITMAP_RESOURCE: [u8; 1] = [0];

    static mut LOADER_ALLOCATION: [u8; 0x44] = [0; 0x44];
    static ALLOC_SIZE: AtomicUsize = AtomicUsize::new(usize::MAX);
    static ALLOC_TAG: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn recording_alloc(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        ALLOC_SIZE.store(size, Ordering::SeqCst);
        ALLOC_TAG.store(tag, Ordering::SeqCst);
        core::ptr::addr_of_mut!(LOADER_ALLOCATION).cast()
    }

    unsafe extern "C" fn find_test_bitmap(
        _provider: *mut ResourceProvider,
        kind: ResourceKind,
        id: u32,
        found: *mut *mut u8,
    ) -> u32 {
        if kind == ResourceKind::BITMAP && id == 0x51 {
            found.write(core::ptr::addr_of_mut!(BITMAP_RESOURCE).cast());
            1
        } else {
            0
        }
    }

    unsafe extern "C" fn unused_read(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn replacement_allowed(
        _provider: *mut ResourceProvider,
        _replacement: *mut ResourceProvider,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn unused_write(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
        _value: u32,
        _flags: u32,
    ) -> u32 {
        0
    }

    const BITMAP_VTABLE: crate::app::resource_chain::ResourceProviderVTable =
        crate::app::resource_chain::ResourceProviderVTable {
            slots_below: [None; 22],
            read: unused_read,
            slot_5c: None,
            replacement_allowed,
            find: find_test_bitmap,
            write: unused_write,
        };

    unsafe extern "C" fn recording_parse(
        object: *mut u8,
        args: *mut u8,
        resource: *mut u8,
    ) -> *mut u8 {
        PARSES.fetch_add(1, Ordering::SeqCst);
        PARSE_OBJECT.store(object as usize, Ordering::SeqCst);
        PARSE_ARGS.store(args as usize, Ordering::SeqCst);
        PARSE_RESOURCE.store(resource as usize, Ordering::SeqCst);
        object
    }


    unsafe extern "C" fn recording_draw(
        ctx: *mut u8,
        object: *mut u8,
        rect_a: *const u32,
        rect_b: *const u32,
        alpha: u32,
        reserved: u32,
    ) {
        DRAWS.fetch_add(1, Ordering::SeqCst);
        LAST_DRAW_CTX.store(ctx as usize, Ordering::SeqCst);
        LAST_DRAW_OBJECT.store(object as usize, Ordering::SeqCst);
        LAST_DRAW_RECT_A.store(rect_a as usize, Ordering::SeqCst);
        LAST_DRAW_RECT_B.store(rect_b as usize, Ordering::SeqCst);
        LAST_DRAW_ALPHA.store(alpha, Ordering::SeqCst);
        LAST_DRAW_RESERVED.store(reserved, Ordering::SeqCst);
    }


    /// Configures the stock-sized parsed-object fixture with recognizable
    /// bounds. Every caller holds [`HOOK_LOCK`] before touching it.
    unsafe fn fake_object() -> *mut u8 {
        let inner = core::ptr::addr_of_mut!(FAKE_INNER);
        *inner = BitmapInner::new(BOUNDS);
        let object = core::ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8;
        set_bitmap_inner_object(object, (*inner).ptr());
        object
    }

    /// Plants the parsed object's inner-object pointer.
    unsafe fn set_bitmap_inner_object(object: *mut u8, inner: *mut u8) {
        core::ptr::addr_of_mut!((*object.cast::<ParsedBitmap>()).inner).write_volatile(inner);
    }

    /// Installs the recording hooks and hands back the guard; the
    /// caller restores with [`restore_hooks`] (the seek_core.rs rule:
    /// never shadow a guard).
    fn with_recording_hooks() -> MutexGuard<'static, ()> {
        let guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        PARSES.store(0, Ordering::SeqCst);
        PARSE_OBJECT.store(usize::MAX, Ordering::SeqCst);
        PARSE_ARGS.store(usize::MAX, Ordering::SeqCst);
        PARSE_RESOURCE.store(usize::MAX, Ordering::SeqCst);
        ALLOC_SIZE.store(usize::MAX, Ordering::SeqCst);
        ALLOC_TAG.store(usize::MAX, Ordering::SeqCst);
        DRAWS.store(0, Ordering::SeqCst);
        LAST_DRAW_CTX.store(usize::MAX, Ordering::SeqCst);
        LAST_DRAW_OBJECT.store(usize::MAX, Ordering::SeqCst);
        LAST_DRAW_RECT_A.store(usize::MAX, Ordering::SeqCst);
        LAST_DRAW_RECT_B.store(usize::MAX, Ordering::SeqCst);
        LAST_DRAW_ALPHA.store(u32::MAX, Ordering::SeqCst);
        LAST_DRAW_RESERVED.store(u32::MAX, Ordering::SeqCst);
        unsafe {
            BITMAP_HOOKS = BitmapHooks {
                parse: recording_parse,
                draw: recording_draw,
            }
        };
        guard
    }

    fn restore_hooks(guard: MutexGuard<'static, ()>) {
        unsafe { BITMAP_HOOKS = DEFAULT_BITMAP_HOOKS };
        drop(guard);
    }

    /// The out block, as four plain words.
    #[repr(align(8))]
    struct Out([u32; 4]);

    impl Out {
        fn new() -> Self {
            Out([0xdead_beef; 4])
        }
        fn ptr(&mut self) -> *mut u32 {
            self.0.as_mut_ptr()
        }
    }

    #[test]
    fn bitmap_object_read_bounds_copies_all_words_before_an_aliasing_store() {
        let mut object = ParsedBitmapFixture::new();
        let mut inner = BitmapInner::new(BOUNDS);
        object.set_inner_object(inner.ptr());
        let mut out = Out::new();

        unsafe { bitmap_object_read_bounds(object.ptr(), out.ptr()) };
        assert_eq!(out.0, BOUNDS, "the four +0x98 words retain their order");

        // `ldm` fetches all four registers before `stm` starts. The
        // in-place destination is therefore a valid exact-alias edge case.
        unsafe { bitmap_object_read_bounds(object.ptr(), inner.bounds_ptr()) };
        assert_eq!(inner.bounds(), BOUNDS);
    }

    #[test]
    fn an_unloaded_wrapper_zeroes_all_four_words_without_copying_bounds() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new(); // +0x08 clear: not loaded
        let mut out = Out::new();

        unsafe { bitmap_query_bounds(out.ptr(), wrapper.ptr(), 0, 0) };

        assert_eq!(out.0, [0; 4], "every bounds word is zeroed");
        assert_eq!(wrapper.0.loaded, 0, "a failed lookup leaves the wrapper unloaded");
        assert_eq!(PARSES.load(Ordering::SeqCst), 0, "the parser is not called");
        restore_hooks(guard);
    }

    #[test]
    fn a_loaded_wrapper_copies_the_query_words_verbatim() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new();
        wrapper.set_loaded(1);
        let object = unsafe { fake_object() };
        wrapper.set_object(object);
        let mut out = Out::new();

        unsafe { bitmap_query_bounds(out.ptr(), wrapper.ptr(), 0, 0) };

        assert_eq!(out.0, BOUNDS, "the four getter words land in order");
        restore_hooks(guard);
    }

    #[test]
    fn the_first_two_words_come_back_as_the_return_value() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new();
        wrapper.set_loaded(1);
        wrapper.set_object(unsafe { fake_object() });
        let mut out = Out::new();

        let ret = unsafe { bitmap_query_bounds(out.ptr(), wrapper.ptr(), 0, 0) };

        assert_eq!(ret as u32, BOUNDS[0], "r0 is bounds word 0");
        assert_eq!((ret >> 32) as u32, BOUNDS[1], "r1 is bounds word 1");
        restore_hooks(guard);
    }

    #[test]
    fn bitmap_ensure_loaded_resolves_parses_and_caches_once() {
        let guard = with_recording_hooks();
        let mut provider = ResourceProvider {
            vtable: &BITMAP_VTABLE,
            state_below_next: [core::ptr::null_mut(); 4],
            next: core::ptr::null_mut(),
        };
        let mut wrapper = Wrapper::new();
        wrapper.set_resource(&mut provider, 0x51);

        let saved_heap_ops = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(crate::heap::veneers::HEAP_OPS))
        };
        let saved_default_heap = unsafe { crate::heap::types::DEFAULT_HEAP };
        let mut heap_ops = saved_heap_ops;
        heap_ops.alloc = recording_alloc;
        unsafe {
            crate::heap::veneers::HEAP_OPS = heap_ops;
            crate::heap::types::DEFAULT_HEAP =
                core::ptr::addr_of_mut!(LOADER_ALLOCATION).cast();
            bitmap_ensure_loaded(wrapper.ptr());
        }

        assert_eq!(wrapper.0.loaded, 1, "successful lookup raises the loaded byte");
        assert!(!wrapper.0.object.is_null(), "parser result is stored in the wrapper");
        assert_eq!(ALLOC_SIZE.load(Ordering::SeqCst), 0x44, "allocation size is exact");
        assert_eq!(ALLOC_TAG.load(Ordering::SeqCst), 2, "operator_new keeps tag 2");
        assert_eq!(PARSES.load(Ordering::SeqCst), 1, "the parser runs once");
        assert_eq!(
            PARSE_OBJECT.load(Ordering::SeqCst),
            wrapper.0.object as usize,
            "the parser receives the 0x44-byte allocation"
        );
        assert_eq!(
            PARSE_ARGS.load(Ordering::SeqCst),
            wrapper.0.parser_args.as_mut_ptr() as usize,
            "the parser receives the wrapper's inline argument block"
        );
        assert_eq!(
            PARSE_RESOURCE.load(Ordering::SeqCst),
            core::ptr::addr_of_mut!(BITMAP_RESOURCE) as *mut u8 as usize,
            "the BMap resource passes through unchanged"
        );

        unsafe { bitmap_ensure_loaded(wrapper.ptr()) };
        assert_eq!(PARSES.load(Ordering::SeqCst), 1, "a loaded wrapper is untouched");
        unsafe {
            crate::heap::veneers::HEAP_OPS = saved_heap_ops;
            crate::heap::types::DEFAULT_HEAP = saved_default_heap;
        }
        restore_hooks(guard);
    }

    #[test]
    fn the_zero_path_returns_the_first_two_arguments() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new(); // not loaded
        let mut out = Out::new();
        let out_addr = out.ptr() as u32;
        let wrapper_addr = wrapper.ptr() as u32;

        let ret = unsafe { bitmap_query_bounds(out.ptr(), wrapper.ptr(), 0, 0) };

        // The spill slots are never written on this path, so the
        // epilogue pops the incoming r0/r1 straight back.
        assert_eq!(ret as u32, out_addr, "r0 is the incoming out pointer");
        assert_eq!((ret >> 32) as u32, wrapper_addr, "r1 is the incoming wrapper");
        restore_hooks(guard);
    }

    #[test]
    fn the_default_hooks_take_the_zeroed_path_for_a_fresh_wrapper() {
        let mut wrapper = Wrapper::new();
        let mut out = Out::new();

        unsafe { bitmap_query_bounds(out.ptr(), wrapper.ptr(), 0, 0) };

        assert_eq!(out.0, [0; 4], "an empty resource chain leaves the wrapper unloaded");
    }

    #[test]
    fn an_unloaded_wrapper_returns_null_after_running_the_loader() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new();

        let object = unsafe { bitmap_get_loaded_object(wrapper.ptr()) };

        assert!(object.is_null(), "a loader that leaves +0x08 clear yields null");
        restore_hooks(guard);
    }

    #[test]
    fn a_loaded_wrapper_returns_its_exact_stored_object_for_any_nonzero_flag() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new();
        let object = core::ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8;
        wrapper.set_object(object);
        wrapper.set_loaded(0x80);

        let returned = unsafe { bitmap_get_loaded_object(wrapper.ptr()) };

        assert_eq!(returned, object, "the +0xc4 pointer passes through unchanged");
        restore_hooks(guard);
    }


    /// A fake draw context; only its identity (the pointer value
    /// reaching `draw`) matters to these tests.
    static mut FAKE_CTX: [u8; 8] = [0; 8];

    #[test]
    fn an_unloaded_wrapper_skips_the_draw() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new(); // +0x08 clear: not loaded
        let rect = Out::new();

        unsafe {
            bitmap_draw_in_rect(
                wrapper.ptr(),
                core::ptr::addr_of_mut!(FAKE_CTX) as *mut u8,
                rect.0.as_ptr(),
                rect.0.as_ptr(),
                0xff,
            )
        };

        assert_eq!(DRAWS.load(Ordering::SeqCst), 0, "nothing is drawn");
        restore_hooks(guard);
    }

    #[test]
    fn a_loaded_wrapper_draws_with_the_object_and_a_hard_zero_reserved_word() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new();
        wrapper.set_loaded(1);
        let object = core::ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8;
        wrapper.set_object(object);
        let ctx = core::ptr::addr_of_mut!(FAKE_CTX) as *mut u8;
        let rect_a = Out::new();
        let rect_b = Out::new();

        unsafe {
            bitmap_draw_in_rect(wrapper.ptr(), ctx, rect_a.0.as_ptr(), rect_b.0.as_ptr(), 0xff)
        };

        assert_eq!(DRAWS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_DRAW_CTX.load(Ordering::SeqCst), ctx as usize, "ctx is forwarded first");
        assert_eq!(
            LAST_DRAW_OBJECT.load(Ordering::SeqCst),
            object as usize,
            "the draw receives the +0xc4 object, not the wrapper"
        );
        assert_eq!(LAST_DRAW_RECT_A.load(Ordering::SeqCst), rect_a.0.as_ptr() as usize);
        assert_eq!(LAST_DRAW_RECT_B.load(Ordering::SeqCst), rect_b.0.as_ptr() as usize);
        assert_eq!(LAST_DRAW_ALPHA.load(Ordering::SeqCst), 0xff, "alpha passes through");
        assert_eq!(
            LAST_DRAW_RESERVED.load(Ordering::SeqCst),
            0,
            "the sixth word is the original's hard zero"
        );
        restore_hooks(guard);
    }


    #[test]
    fn the_default_hooks_draw_nothing_for_a_fresh_wrapper() {
        let mut wrapper = Wrapper::new();
        let rect = Out::new();

        // An empty resource chain leaves the flag clear, so the draw stub is
        // never reached.
        unsafe {
            bitmap_draw_in_rect(
                wrapper.ptr(),
                core::ptr::addr_of_mut!(FAKE_CTX) as *mut u8,
                rect.0.as_ptr(),
                rect.0.as_ptr(),
                0xff,
            )
        };
    }
}
