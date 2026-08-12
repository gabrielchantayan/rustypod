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
    /// `FUN_082a1dbc` @ 0x082a1dbc (20 bytes; 19 `bl` call sites): the
    /// parsed bitmap object's bounds getter — copies the four words at
    /// +0x98..+0xa4 of the inner object `*(object + 0x1c)` into `out`.
    /// Default: no-op, which leaves the query block holding its
    /// argument-spill words (see [`bitmap_query_bounds`]); the real
    /// getter always overwrites all four.
    pub read_bounds: unsafe extern "C" fn(object: *mut u8, out: *mut u32),
}

unsafe extern "C" fn ensure_loaded_stub(_wrapper: *mut u8) {}

unsafe extern "C" fn read_bounds_stub(_object: *mut u8, _out: *mut u32) {}

/// Wired defaults: no-op stubs for both unported originals.
pub(crate) const DEFAULT_BITMAP_HOOKS: BitmapHooks = BitmapHooks {
    ensure_loaded: ensure_loaded_stub,
    read_bounds: read_bounds_stub,
};

/// The active hooks. Host tests swap in recording mocks and restore.
pub static mut BITMAP_HOOKS: BitmapHooks = DEFAULT_BITMAP_HOOKS;

/// Volatile read so LLVM cannot fold the default stubs in and delete
/// the dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn hooks() -> BitmapHooks {
    core::ptr::read_volatile(core::ptr::addr_of!(BITMAP_HOOKS))
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
/// 3. Otherwise dispatch the parsed object's bounds getter
///    (`FUN_082a1dbc`, through [`BITMAP_HOOKS`]) on the +0xc4 object,
///    filling a 16-byte stack block, then copy the four words into
///    `out` (`ldmia`/`stmia`).
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
///   with the real `FUN_082a1dbc` (which writes all four words) they
///   are unobservable. With the default no-op `read_bounds` stub the
///   loaded path copies the spill words `(out, wrapper, arg3, arg4)`
///   into `out` — the exact content the original's stack block would
///   hand a getter that stored nothing.
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
        (hooks().read_bounds)(object, bounds.as_mut_ptr());
        for slot in 0..4 {
            (out.add(slot)).write_volatile(bounds[slot]);
        }
    }
    ((bounds[1] as u64) << 32) | bounds[0] as u64
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

    /// A fake parsed bitmap object; only its identity (the pointer
    /// value reaching `read_bounds`) matters to these tests.
    static mut FAKE_OBJECT: [u8; 8] = [0; 8];

    /// Serializes the tests that swap [`BITMAP_HOOKS`].
    static HOOK_LOCK: StdMutex<()> = StdMutex::new(());
    static LOADS: AtomicU32 = AtomicU32::new(0);
    static QUERIES: AtomicU32 = AtomicU32::new(0);
    static LAST_QUERIED_OBJECT: AtomicUsize = AtomicUsize::new(usize::MAX);
    /// Set by a test to make the loader mock resolve the wrapper
    /// (store the fake object at +0xc4, raise the +0x08 flag).
    static LOAD_RESOLVES: AtomicU32 = AtomicU32::new(0);

    /// The four recognizable bounds words the query mock plants.
    const BOUNDS: [u32; 4] = [0x1111_0000, 0x2222_0000, 0x3333_0000, 0x4444_0000];

    unsafe extern "C" fn recording_ensure_loaded(wrapper: *mut u8) {
        LOADS.fetch_add(1, Ordering::SeqCst);
        if LOAD_RESOLVES.load(Ordering::SeqCst) != 0 {
            set_bitmap_object(wrapper, core::ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8);
            wrapper.add(LOADED).write_volatile(1);
        }
    }

    unsafe extern "C" fn recording_read_bounds(object: *mut u8, out: *mut u32) {
        QUERIES.fetch_add(1, Ordering::SeqCst);
        LAST_QUERIED_OBJECT.store(object as usize, Ordering::SeqCst);
        for (slot, word) in BOUNDS.into_iter().enumerate() {
            out.add(slot).write_volatile(word);
        }
    }

    /// Plants the +0xc4 object pointer the way the loader's store does.
    unsafe fn set_bitmap_object(wrapper: *mut u8, object: *mut u8) {
        (wrapper.add(BITMAP_OBJECT) as *mut *mut u8).write_volatile(object);
    }

    /// Installs the recording hooks and hands back the guard; the
    /// caller restores with [`restore_hooks`] (the seek_core.rs rule:
    /// never shadow a guard).
    fn with_recording_hooks() -> MutexGuard<'static, ()> {
        let guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        LOADS.store(0, Ordering::SeqCst);
        QUERIES.store(0, Ordering::SeqCst);
        LAST_QUERIED_OBJECT.store(usize::MAX, Ordering::SeqCst);
        LOAD_RESOLVES.store(0, Ordering::SeqCst);
        unsafe {
            BITMAP_HOOKS = BitmapHooks {
                ensure_loaded: recording_ensure_loaded,
                read_bounds: recording_read_bounds,
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
    fn an_unloaded_wrapper_zeroes_all_four_words_and_skips_the_query() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new(); // +0x08 clear: not loaded
        let mut out = Out::new();

        unsafe { bitmap_query_bounds(out.ptr(), wrapper.ptr(), 0, 0) };

        assert_eq!(out.0, [0; 4], "every bounds word is zeroed");
        assert_eq!(LOADS.load(Ordering::SeqCst), 1, "the loader still runs first");
        assert_eq!(QUERIES.load(Ordering::SeqCst), 0, "the getter is not dispatched");
        restore_hooks(guard);
    }

    #[test]
    fn a_loaded_wrapper_copies_the_query_words_verbatim() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new();
        wrapper.set_byte(LOADED, 1);
        let object = core::ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8;
        wrapper.set_ptr(BITMAP_OBJECT, object);
        let mut out = Out::new();

        unsafe { bitmap_query_bounds(out.ptr(), wrapper.ptr(), 0, 0) };

        assert_eq!(out.0, BOUNDS, "the four getter words land in order");
        assert_eq!(QUERIES.load(Ordering::SeqCst), 1);
        assert_eq!(
            LAST_QUERIED_OBJECT.load(Ordering::SeqCst),
            object as usize,
            "the getter receives the +0xc4 object"
        );
        restore_hooks(guard);
    }

    #[test]
    fn the_first_two_words_come_back_as_the_return_value() {
        let guard = with_recording_hooks();
        let mut wrapper = Wrapper::new();
        wrapper.set_byte(LOADED, 1);
        wrapper.set_ptr(BITMAP_OBJECT, core::ptr::addr_of_mut!(FAKE_OBJECT) as *mut u8);
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
}
