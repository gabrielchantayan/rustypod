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
//! The loader `FUN_082993b4` @ 0x082993b4 (80 bytes + the "BMap"
//! literal @ 0x08299400; 8 `bl` call sites) is the lazy initializer:
//! if the +0x08 flag is clear it resolves the (head, id) pair through
//! `resource_chain_find` @ 0x0827216c with the kind literal
//! 0x424d6170 ("BMap" big-endian — `ResourceKind::BITMAP` in
//! app/resource_chain.rs), allocates 0x44 bytes via `operator_new`,
//! parses the resource into it with FUN_082645a0, stores the object at
//! +0xc4 and raises the flag. A failed lookup leaves the flag clear,
//! which is exactly the state the query below treats as "no bounds".
//!
//! Offsets are literal byte offsets into a `*mut u8`, the
//! drivers/surface.rs / drivers/display_layer.rs precedent. The only
//! pointer field the query reads (+0xc4) is native-width — exactly the
//! 4-byte field on target — but 0xc4 is not eight-aligned, so on a
//! 64-bit host it is parked at 0xc8, the first aligned slot behind it,
//! in the wrapper's unaccounted tail (the display_layer.rs
//! parked-pointer rule; the tests size the block to 0xd0 to leave that
//! slack). On the 32-bit target every offset is the literal one and
//! the codegen is unaffected. See [`BITMAP_OBJECT`].

/// +0x08: the loaded flag byte the lazy loader raises.
const LOADED: usize = 0x08;

/// +0xc4 on target: the parsed bitmap object the loader stores. 0xc4
/// is not eight-aligned, so on 64-bit hosts the native-width field is
/// parked at 0xc8, in the unaccounted tail behind the literal field
/// (the module header's parked-pointer rule).
#[cfg(target_pointer_width = "32")]
const BITMAP_OBJECT: usize = 0xc4;
#[cfg(target_pointer_width = "64")]
const BITMAP_OBJECT: usize = 0xc8;
/// +0x1c on target: the bitmap's inner data object. This is a 4-byte
/// pointer on target but is parked at +0x20 in the aligned 64-bit
/// host fixture, just as [`BITMAP_OBJECT`] is parked above.
#[cfg(target_pointer_width = "32")]
const BITMAP_INNER_OBJECT: usize = 0x1c;
#[cfg(target_pointer_width = "64")]
const BITMAP_INNER_OBJECT: usize = 0x20;

/// +0x98 within the inner object: the first of four bounds words.
const INNER_BOUNDS: usize = 0x98;


#[inline(always)]
unsafe fn byte(wrapper: *mut u8, offset: usize) -> u8 {
    wrapper.add(offset).read_volatile()
}

/// A stored pointer field, native-width at the given offset — the
/// [`crate::drivers::display_layer`] precedent.
#[inline(always)]
unsafe fn ptr_field(wrapper: *mut u8, offset: usize) -> *mut u8 {
    (wrapper.add(offset) as *const *mut u8).read_volatile()
}

/// Indirect dispatch for this cluster's unported callees (the house
/// pattern — see `drivers/display_layer.rs`'s `LayerDriverHooks`).
#[derive(Clone, Copy)]
pub struct BitmapHooks {
    /// `FUN_082993b4` @ 0x082993b4 (8 `bl` call sites): the lazy
    /// loader — resolves the wrapper's ("BMap", id) resource, parses
    /// it into a fresh 0x44-byte object stored at +0xc4 and raises the
    /// +0x08 loaded flag; a failed lookup leaves the flag clear.
    /// Default: no-op — a wrapper starts unloaded, so the wired build
    /// takes the zeroed-bounds path exactly as the original does for a
    /// resource that fails to resolve. NOT hook-ready: the stock
    /// loader must be ported (or the wrapper pre-loaded) before the
    /// query path can run on target.
    pub ensure_loaded: unsafe extern "C" fn(wrapper: *mut u8),
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

unsafe extern "C" fn ensure_loaded_stub(_wrapper: *mut u8) {}


unsafe extern "C" fn draw_stub(
    _ctx: *mut u8,
    _object: *mut u8,
    _rect_a: *const u32,
    _rect_b: *const u32,
    _alpha: u32,
    _reserved: u32,
) {
}

/// Wired defaults: no-op stubs for the unported originals.
pub(crate) const DEFAULT_BITMAP_HOOKS: BitmapHooks = BitmapHooks {
    ensure_loaded: ensure_loaded_stub,
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
    let inner = ptr_field(object, BITMAP_INNER_OBJECT);
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
/// 1. Run the lazy loader (`FUN_082993b4`, through
///    [`BITMAP_HOOKS`]) **first, unconditionally** — a wrapper whose
///    resource has not been resolved yet is loaded on demand here.
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
/// - +0xc4 is read as a native-width pointer (parked at 0xc8 on
///   64-bit hosts — see the module header); on target it is exactly
///   the 4-byte field at +0xc4.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bitmap_query_bounds(
    out: *mut u32,
    wrapper: *mut u8,
    arg3: u32,
    arg4: u32,
) -> u64 {
    // The original's r0..r3 spill slots double as the query block.
    let mut bounds: [u32; 4] = [out as u32, wrapper as u32, arg3, arg4];
    (hooks().ensure_loaded)(wrapper);
    if byte(wrapper, LOADED) == 0 {
        for slot in 0..4 {
            (out.add(slot)).write_volatile(0);
        }
    } else {
        let object = ptr_field(wrapper, BITMAP_OBJECT);
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
/// 1. Run the lazy loader (`FUN_082993b4`, through
///    [`BITMAP_HOOKS`]) **first, unconditionally** — exactly as the
///    bounds query does.
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
/// - +0xc4 is read as a native-width pointer (parked at 0xc8 on
///   64-bit hosts — see the module header); on target it is exactly
///   the 4-byte field at +0xc4.
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
    (hooks().ensure_loaded)(wrapper);
    if byte(wrapper, LOADED) != 0 {
        let object = ptr_field(wrapper, BITMAP_OBJECT);
        (hooks().draw)(ctx, object, rect_a, rect_b, alpha, 0);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Mutex as StdMutex, MutexGuard};

    /// The wrapper is addressed by literal byte offset, so a plain
    /// aligned byte block stands in for it on the host. Aligned to 8 so
    /// the native-width +0xc4 pointer is well aligned on a 64-bit host
    /// too (on target the block is word-aligned).
    #[repr(align(8))]
    struct Wrapper([u8; 0xd0]);

    impl Wrapper {
        fn new() -> Self {
            Wrapper([0; 0xd0])
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn set_byte(&mut self, offset: usize, value: u8) {
            self.0[offset] = value;
        }
        fn set_ptr(&mut self, offset: usize, value: *mut u8) {
            self.0[offset..offset + core::mem::size_of::<*mut u8>()]
                .copy_from_slice(&(value as usize).to_ne_bytes());
        }
    }

    /// The parsed object has an inner-object pointer at +0x1c on target.
    /// It is parked at +0x20 here, leaving the host's native-width
    /// pointer aligned; 0x44 is the stock parser allocation size.
    #[repr(align(8))]
    struct ParsedBitmap([u8; 0x44]);

    impl ParsedBitmap {
        fn new() -> Self {
            ParsedBitmap([0; 0x44])
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn set_inner_object(&mut self, inner: *mut u8) {
            unsafe {
                (self.ptr().add(BITMAP_INNER_OBJECT) as *mut *mut u8).write_volatile(inner);
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

    /// The parsed object and inner bounds that the loader mock resolves.
    static mut FAKE_OBJECT: ParsedBitmap = ParsedBitmap([0; 0x44]);
    static mut FAKE_INNER: BitmapInner = BitmapInner([0; (INNER_BOUNDS + 16) / 4]);

    /// Serializes the tests that swap [`BITMAP_HOOKS`] or use the fake
    /// parsed object.
    static HOOK_LOCK: StdMutex<()> = StdMutex::new(());
    static LOADS: AtomicU32 = AtomicU32::new(0);
    /// Set by a test to make the loader mock resolve the wrapper
    /// (store the fake object at +0xc4, raise the +0x08 flag).
    static LOAD_RESOLVES: AtomicU32 = AtomicU32::new(0);

    static DRAWS: AtomicU32 = AtomicU32::new(0);
    static LAST_DRAW_CTX: AtomicUsize = AtomicUsize::new(usize::MAX);
    static LAST_DRAW_OBJECT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static LAST_DRAW_RECT_A: AtomicUsize = AtomicUsize::new(usize::MAX);
    static LAST_DRAW_RECT_B: AtomicUsize = AtomicUsize::new(usize::MAX);
    static LAST_DRAW_ALPHA: AtomicU32 = AtomicU32::new(u32::MAX);
    static LAST_DRAW_RESERVED: AtomicU32 = AtomicU32::new(u32::MAX);

    unsafe extern "C" fn recording_ensure_loaded(wrapper: *mut u8) {
        LOADS.fetch_add(1, Ordering::SeqCst);
        if LOAD_RESOLVES.load(Ordering::SeqCst) != 0 {
            set_bitmap_object(wrapper, fake_object());
            wrapper.add(LOADED).write_volatile(1);
        }
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

    /// Plants the +0xc4 object pointer the way the loader's store does.
    unsafe fn set_bitmap_object(wrapper: *mut u8, object: *mut u8) {
        (wrapper.add(BITMAP_OBJECT) as *mut *mut u8).write_volatile(object);
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

    /// Plants the parsed object's +0x1c inner-object pointer.
    unsafe fn set_bitmap_inner_object(object: *mut u8, inner: *mut u8) {
        (object.add(BITMAP_INNER_OBJECT) as *mut *mut u8).write_volatile(inner);
    }

    /// Installs the recording hooks and hands back the guard; the
    /// caller restores with [`restore_hooks`] (the seek_core.rs rule:
    /// never shadow a guard).
    fn with_recording_hooks() -> MutexGuard<'static, ()> {
        let guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        LOADS.store(0, Ordering::SeqCst);
        LOAD_RESOLVES.store(0, Ordering::SeqCst);
        DRAWS.store(0, Ordering::SeqCst);
        LAST_DRAW_CTX.store(usize::MAX, Ordering::SeqCst);
        LAST_DRAW_OBJECT.store(usize::MAX, Ordering::SeqCst);
        LAST_DRAW_RECT_A.store(usize::MAX, Ordering::SeqCst);
        LAST_DRAW_RECT_B.store(usize::MAX, Ordering::SeqCst);
        LAST_DRAW_ALPHA.store(u32::MAX, Ordering::SeqCst);
        LAST_DRAW_RESERVED.store(u32::MAX, Ordering::SeqCst);
        unsafe {
            BITMAP_HOOKS = BitmapHooks {
                ensure_loaded: recording_ensure_loaded,
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
        let mut object = ParsedBitmap::new();
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
        assert_eq!(LOADS.load(Ordering::SeqCst), 1, "the loader still runs first");
        restore_hooks(guard);
    }

    #[test]
    fn a_loaded_wrapper_copies_the_query_words_verbatim() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new();
        wrapper.set_byte(LOADED, 1);
        let object = unsafe { fake_object() };
        wrapper.set_ptr(BITMAP_OBJECT, object);
        let mut out = Out::new();

        unsafe { bitmap_query_bounds(out.ptr(), wrapper.ptr(), 0, 0) };

        assert_eq!(out.0, BOUNDS, "the four getter words land in order");
        restore_hooks(guard);
    }

    #[test]
    fn the_first_two_words_come_back_as_the_return_value() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new();
        wrapper.set_byte(LOADED, 1);
        wrapper.set_ptr(BITMAP_OBJECT, unsafe { fake_object() });
        let mut out = Out::new();

        let ret = unsafe { bitmap_query_bounds(out.ptr(), wrapper.ptr(), 0, 0) };

        assert_eq!(ret as u32, BOUNDS[0], "r0 is bounds word 0");
        assert_eq!((ret >> 32) as u32, BOUNDS[1], "r1 is bounds word 1");
        restore_hooks(guard);
    }

    #[test]
    fn the_loader_runs_before_the_flag_check() {
        let guard = with_recording_hooks();
        // Starts unloaded; the loader mock resolves it mid-call, so the
        // query path must run on the strength of the loader's stores.
        LOAD_RESOLVES.store(1, Ordering::SeqCst);
        let mut wrapper = Wrapper::new();
        let mut out = Out::new();

        let ret = unsafe { bitmap_query_bounds(out.ptr(), wrapper.ptr(), 0, 0) };

        assert_eq!(out.0, BOUNDS, "a just-loaded wrapper yields real bounds");
        assert_eq!(ret as u32, BOUNDS[0]);
        assert_eq!((ret >> 32) as u32, BOUNDS[1]);
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

        assert_eq!(out.0, [0; 4], "the no-op loader leaves the wrapper unloaded");
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

        assert_eq!(LOADS.load(Ordering::SeqCst), 1, "the loader still runs first");
        assert_eq!(DRAWS.load(Ordering::SeqCst), 0, "nothing is drawn");
        restore_hooks(guard);
    }

    #[test]
    fn a_loaded_wrapper_draws_with_the_object_and_a_hard_zero_reserved_word() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new();
        wrapper.set_byte(LOADED, 1);
        let object = core::ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8;
        wrapper.set_ptr(BITMAP_OBJECT, object);
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
    fn the_loader_runs_before_the_draw_flag_check() {
        let guard = with_recording_hooks();
        // Starts unloaded; the loader mock resolves it mid-call, so the
        // draw path must run on the strength of the loader's stores.
        LOAD_RESOLVES.store(1, Ordering::SeqCst);
        let mut wrapper = Wrapper::new();
        let rect = Out::new();

        unsafe {
            bitmap_draw_in_rect(
                wrapper.ptr(),
                core::ptr::addr_of_mut!(FAKE_CTX) as *mut u8,
                rect.0.as_ptr(),
                rect.0.as_ptr(),
                0x80,
            )
        };

        assert_eq!(DRAWS.load(Ordering::SeqCst), 1, "a just-loaded wrapper draws");
        assert_eq!(LAST_DRAW_ALPHA.load(Ordering::SeqCst), 0x80);
        restore_hooks(guard);
    }

    #[test]
    fn the_default_hooks_draw_nothing_for_a_fresh_wrapper() {
        let mut wrapper = Wrapper::new();
        let rect = Out::new();

        // Must simply return: no-op loader leaves the flag clear and
        // the no-op draw stub is never reached.
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
