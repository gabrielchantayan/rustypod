//! The sixteen lazily-constructed framework singletons. Every one is the
//! same four-step idiom over its own cache word, its own allocation
//! size and its own constructor:
//!
//! ```text
//! if (*slot == 0) { *slot = ctor(operator_new(SIZE)); }
//! return *slot;
//! ```
//!
//! | address | name | size | cache | ctor | `bl` sites |
//! |---|---|---|---|---|---|
//! | 0x0817ee04 | [`app_controller_get`] | 0xe8 | 0x089cc648 | 0x081847fc | **1108** |
//! | 0x08173848 | [`app_screen_get`] | 0x850 | 0x089cc1bc | 0x08177a78 | 140 |
//! | 0x0817ceb4 | [`media_player_get`] | 0xa6c | 0x089ca7cc | 0x0817d970 | 101 |
//! | 0x081eb0c4 | [`singleton_class_8900`] | 0x380 | 0x089cc3ac | 0x081ee0c0 | 88 |
//! | 0x0810a7b8 | [`singleton_class_6200`] | 0xd0 | 0x089cb308 | 0x0810ab3c | 47 |
//! | 0x081b803c | [`singleton_class_7f80`] | 0x1d4 | 0x089cc61c | 0x081b80b4 | 38 |
//! | 0x0816df60 | [`lazy_singleton_0x3c`] | 0x3c | 0x089d0130 | 0x0816e2ac | 38 |
//! | 0x08160148 | [`lazy_singleton_0x8c`] | 0x8c | 0x089ca7f0 | 0x08160534 | 32 |
//! | 0x081a5500 | [`singleton_class_8c00`] | 0xdc | 0x089cc7c0 | 0x081a71fc | 82 |
//! | 0x081dfa20 | [`command_dispatcher_get`] | 0x20 | 0x089cc828 | 0x081dfc1c | 73 |
//! | 0x081f77a4 | [`volume_controller_get`] | 0x3bc | 0x089cc288 | 0x081fa070 | 52 |
//! | 0x0812c72c | [`lazy_singleton_0x58`] | 0x58 | 0x089cc16c | 0x0812ce88 | 46 |
//! | 0x0825b680 | [`lazy_singleton_0x40`] | 0x40 | 0x089cc94c | 0x0825bd20 | 43 |
//! | 0x0811b2c0 | [`singleton_class_6280`] | 0xa0 | 0x089cc30c | 0x0811c7fc | **43** |
//! | 0x081fa3b0 | [`stage_progress_tracker_get`] | 0x2c | 0x089ca5d4 | 0x081fa440 | 30 |
//! | 0x081303a8 | [`singleton_class_9300`] | 0x14c | 0x089cc2bc | 0x08130424 | 28 |
//!
//! (Call-site counts binary-scanned; the earlier scouting notes said 86
//! / 38 / 37 / 36 for the bottom four.)
//!
//! One of the eleven is also reached through a long-branch veneer, ported
//! alongside it:
//!
//! | address | name | target | `bl` sites |
//! |---|---|---|---|
//! | 0x0820b230 | [`command_dispatcher_get_veneer`] | 0x081dfa20 | **125** |
//!
//! Re-scanning every ARM `B`/`BL` word in `work/firmware/osos.dec`
//! (load base 0x08000000) resolves **73** unconditional `BL` to
//! 0x081dfa20 directly — the header row above previously said 69, an
//! `osos.asm` grep undercount — plus exactly one plain `B`, which is
//! the veneer itself, and **125** `BL` to the veneer. 198 call sites
//! in total, which makes 0x0820b230 the hotter of the two entry
//! points by a wide margin.
//!
//! `operator new` @ 0x082aadd4 is already ported
//! (`heap::veneers::operator_new`), so it is called directly. None of
//! the sixteen constructors is — they are large C++ constructors — so
//! they sit behind the [`SINGLETON_CTORS`] dispatch table, the house
//! pattern.
//!
//! ## What the objects are
//!
//! - The 0xE8 object is the **application controller** — views hand
//!   themselves to it (`FUN_08124af4(controller, view)`), callers poke a
//!   mode halfword at its +0x80, and its ctor resolves a registry target
//!   through `demo_mode_instance` @ 0x081883fc and vtable slot +0xe8.
//! - The 0x850 object is the **screen/layout** side: callers load layout
//!   resources into it (`FUN_08181110(screen, ...)` next to the
//!   "GotoExtraInfoLayout" / "GotoGenius" literals,
//!   `FUN_08174300(screen, 0x80, ...)`) and then hand it to the
//!   controller (`FUN_08183950(controller, screen)`). Neither class name
//!   survives in the image (the ctor's name argument comes from a
//!   runtime global @ 0x080cb828).
//! - The 0xA6C object is the **TPodMediaPlayer** — the one singleton
//!   whose class name survives in the image: its constructor @
//!   0x0817d970 hands the "TPodMediaPlayer" literal (@ 0x0817db74) to
//!   the class-name factory @ 0x0822053c. It is the media player
//!   controller: a deeply chained C++ ctor (vtable 0x089a75c8 at
//!   +0x14, sub-objects out past +0x9c4) that the getter's 101 call
//!   sites reach through the +4 slot of the global @ 0x089ca7c8. Its
//!   hottest consumer is [`media_player_interface_get`] (returns
//!   `instance + 0x14` or NULL, 264 `bl` call sites), ported below.
//! - Three of the remaining four are identified only by the **class id**
//!   their constructor publishes into the by-id registry
//!   (`app/registry.rs`), which is the firmware's own name for them:
//!   0x8900 (registered @ 0x081ee0f0), 0x6200 (@ 0x0810ac1c — the id is
//!   set 22 instructions earlier, which is why an 8-instruction scan
//!   missed it) and 0x7f80 (@ 0x081b8194). **None of the three classes
//!   could be named**: unlike TCDemoMode/TCSportTimer/TRadioCntlr and
//!   friends, these constructors never hand a name to the class-name
//!   factory @ 0x0820b230, and no name literal sits anywhere in their
//!   bodies. The symbols therefore carry the id and nothing more —
//!   inventing "TCSomethingCntlr" would be worse than saying so.
//! - The 0x3c object registers nothing at all and has no name literal
//!   either, so only its size identifies it. Its constructor
//!   `FUN_0816e2ac` builds a small object with a flag byte at +0x10, a
//!   zeroed +0x14..+0x38 and a sub-object at +0x20.
//! - The 0xDC object is registry class **0x8c00**, and it is the object
//!   the kernel's gateway path waits on: `gateway_wait_ready` @
//!   0x080c8304 (kernel/gateway_request_blocking.rs) polls its byte at
//!   +0x6a until it reads 1. Its constructor `FUN_081a71fc` is a
//!   multiple-inheritance ctor — it forms `sub = this + 0x48`, plants
//!   the primary vtable 0x0898b39c at +0x00 and the secondary vtables
//!   (+0x50, +0xcc, +0xdc off that literal) at +0x48/+0x60/+0x64, sets
//!   the ready pair +0x69/+0x6a to 1, caches
//!   [`singleton_class_8900`] at +0xd0, zeroes +0xc8 and +0xd8, and
//!   publishes **`sub`, not `this`**, under id 0x8c00 (`mov r1,
//!   #0x8c00; add r0, r4, #0x48; bl 0x081d23f8` @ 0x081a731c) — the
//!   interface sub-object is what the registry
//!   holds. The last field it writes is +0xd8, which is exactly what
//!   makes 0xDC the allocation size. Class NOT named: the ctor never
//!   reaches the name factory @ 0x0820b230.
//! - The 0x20 object is the **command dispatcher**: its ctor @
//!   0x081dfc1c plants vtable 0x0898ebac at +0x00 and initializes an
//!   embedded libstdc++ ordered map at +0x04 (header pointer at +0x14,
//!   flag +0x1c, comparator byte +0x1d — the container layout
//!   event_list.rs documents) keyed by command-NAME string. Of the 69
//!   call sites, 39 dispatch a command: build a temporary Silver list
//!   table (`FUN_081473d8`, the silver_list_table ctor) for resource
//!   `id - 1`, take the 'SCST'-resolved name handle at its +0x28, and
//!   call `FUN_081dfab0` → `FUN_081dfb10`, which inserts into the map
//!   under that name and invokes the handler at record+0x18; 9 sites
//!   register handlers by name string through `FUN_081df9ac`. The
//!   command ids sit in a private 0x0dad0000 namespace (observed
//!   0x0dad01d7..0x0dad0e01, pool-literal only — they name records in
//!   the rsrc volume, not addresses). Class NOT named: the ctor never
//!   reaches a name factory, so the symbol names the role the call
//!   sites prove.
//! - The 0x3BC object is the **volume controller** — registry class
//!   0x7f00 (`bl 0x081d23f8` with id 0x7f00 in the ctor @ 0x081fa070).
//!   The identification rests on its adjuster `FUN_081f9120`: a signed
//!   delta is clamped into a 0..100 range with a 100 cap (`if (uVar4 <
//!   100U - param_2) ... else param_2 = 100`) and committed through the
//!   player-side setter `FUN_081116e0`, with `FUN_081f77fc` the
//!   elapsed-paced sibling; the getter's 52 call sites feed it wheel
//!   deltas from the "EnterVolume" menu handler (@ 0x0810c9dc, one of
//!   the wheel_sample_capture consumers), and the ctor queries the
//!   media player interface (media_player_interface_get @ 0x08259594,
//!   twice, plus 0x0825a0c0) and stores its vtable+0x108 answer as a
//!   byte. Class NOT named in the image (no name-factory call), so the
//!   symbol names the proven role; the registry id says 0x7f00.
//!   Unlike its siblings the cache is the `+0x1c` slot of its globals
//!   word (DAT_081f77d0 = 0x089cc26c, so the cache is 0x089cc288),
//!   and the size is an immediate (`mov r0, #0x3bc`).
//!
//! - The 0x58 object is the newest arrival and sits in a **shared
//!   three-slot globals block** rather than a private cache word: the
//!   pool literal @ 0x0812c758 is 0x089cc168, and the block's `+0x00`
//!   (a 0x68 object, getter @ 0x0819bea8, ctor @ 0x0819c1d4) and
//!   `+0x08` (a 0x22c object, getter @ 0x081b5440, ctor @ 0x081b6628)
//!   are two more singletons of exactly this shape — only the `+0x04`
//!   slot is ported here. Its ctor @ 0x0812ce88 is unusually small (44
//!   bytes): base ctor @ 0x0819c550, vtable literal 0x08983b7c at
//!   +0x00, a sub-object initialized at +0x3c (`FUN_08270394(this +
//!   0x3c, 0, 0)`, the same three-argument initializer the base ctor
//!   runs at its own +0x18) and a flag byte zeroed at +0x54 — which is
//!   what makes 0x58 the allocation size. **Class NOT named**: neither
//!   the ctor nor the base ctor reaches a name factory or the by-id
//!   registry, and the vtable address falls in the region where the
//!   decrypted image holds the C++ mangled-name blob instead (the same
//!   page mismatch app/registry.rs records), so the vtable cannot be
//!   read for a name either. The 46 call sites use it purely as a
//!   `this` for virtual dispatch (slots +0x94, +0xac, +0x190) and as
//!   the first argument of the neighbouring free functions @
//!   0x0812ce60 / 0x0812ce74 / 0x0812c75c, clustered in the
//!   0x0822xxxx-0x0823xxxx UI/menu code. Size is the only identifying
//!   fact, so — like [`lazy_singleton_0x3c`] — the symbol says exactly
//!   that.
//! - The 0x40 object is the newest sibling and the only one whose cache
//!   word (0x089cc94c, pool literal @ 0x0825b6ac) sits right after the
//!   settings store's cache in the 0x089cc9xx globals page. Its
//!   constructor builds a mutex-guarded fixed-block pool of 20-byte
//!   records and the 43 call sites use the object as a registration /
//!   query hub — see [`lazy_singleton_0x40`] for what that proves.
//!   Class NOT named.
//! - The 0xA0 object is registry class **0x6280** — see
//!   [`singleton_class_6280`] below.
//! - The 0x2C object is the **stage progress tracker** — see
//!   [`stage_progress_tracker_get`] below. It breaks the family mould
//!   twice: it caches the RAW allocation rather than the constructor's
//!   return (its constructor @ 0x081fa440 returns `[this + 0xc]`, a
//!   budget word it just zeroed — NOT `this`), and a NULL allocation is
//!   fatal via `heap_panic` @ 0x08030f44 instead of being cached and
//!   retried.
//! - The 0x14C object is registry class **0x9300** — see
//!   [`singleton_class_9300`] below. Its constructor @ 0x08130424 wires
//!   an embedded timer at +0x44 armed to 2000 ms, which its method
//!   cluster (0x0812f754..0x08130134, the getter's own neighbours)
//!   drives. Class NOT named.
//!
//! **None of these symbols is hook-ready.** Until the constructors are
//! ported, the dispatch defaults hand out a zeroed block — no vtable,
//! no registry wiring — so branching stock code here would break it.
//! The getters are ported because the *getter* logic (test, allocate,
//! construct, cache, reload) is fully recovered; the ctor slot is the
//! documented boundary.
//!
//! Faithful details:
//! - The cached word is re-loaded after construction rather than reused
//!   from the ctor's return (the original's second `ldr r0, [r4, #N]`).
//!   Observable if the ctor itself writes the slot.
//! - A ctor returning NULL caches NULL, so the next call re-allocates.
//!   Reproduced.
//! - The cache slots are the crate statics below rather than words in
//!   0x089cxxxx / 0x089dxxxx pages (the block_mgr.rs deviation:
//!   those RW pages are runtime-initialized; the image holds stale UI
//!   strings there). All sixteen default to NULL, exactly the pre-init
//!   state.

use crate::heap::veneers::operator_new;

/// Allocation size of the application controller (`mov r0, #0xe8`).
pub const APP_CONTROLLER_SIZE: usize = 0xe8;

/// Allocation size of the screen object (`mov r0, #0x850`).
pub const APP_SCREEN_SIZE: usize = 0x850;

/// Allocation size of the TPodMediaPlayer object (original: the literal
/// @ 0x0817cee4, loaded by `ldr r0, [0x817cee4]` — too big for an ARM
/// immediate).
pub const MEDIA_PLAYER_SIZE: usize = 0xa6c;

/// Allocation size of the registry-class-0x8900 singleton
/// (`mov r0, #0x380`).
pub const CLASS_8900_SIZE: usize = 0x380;

/// Allocation size of the registry-class-0x6200 singleton
/// (`mov r0, #0xd0`).
pub const CLASS_6200_SIZE: usize = 0xd0;

/// Allocation size of the registry-class-0x7f80 singleton
/// (`mov r0, #0x1d4`).
pub const CLASS_7F80_SIZE: usize = 0x1d4;

/// Allocation size of the unidentified 0x3c singleton
/// (`mov r0, #0x3c`).
pub const SINGLETON_0X3C_SIZE: usize = 0x3c;

/// Allocation size of the unidentified 0x8c singleton (`mov r0, #0x8c`).
pub const SINGLETON_0X8C_SIZE: usize = 0x8c;

/// Allocation size of the registry-class-0x8c00 singleton
/// (`mov r0, #0xdc`).
pub const CLASS_8C00_SIZE: usize = 0xdc;

/// Allocation size of the command-dispatcher singleton
/// (`mov r0, #0x20`).
pub const COMMAND_DISPATCHER_SIZE: usize = 0x20;

/// Allocation size of the volume-controller singleton
/// (`mov r0, #0x3bc`).
pub const VOLUME_CONTROLLER_SIZE: usize = 0x3bc;

/// Allocation size of the unidentified 0x58 singleton
/// (`mov r0, #0x58`).
pub const SINGLETON_0X58_SIZE: usize = 0x58;

/// Allocation size of the unidentified 0x40 singleton
/// (`mov r0, #0x40`).
pub const SINGLETON_0X40_SIZE: usize = 0x40;

/// Allocation size of the registry-class-0x6280 singleton
/// (`mov r0, #0xa0`).
pub const CLASS_6280_SIZE: usize = 0xa0;

/// Allocation size of the stage-progress-tracker singleton
/// (`mov r0, #0x2c`).
pub const STAGE_PROGRESS_TRACKER_SIZE: usize = 0x2c;

/// Allocation size of the registry-class-0x9300 singleton
/// (`mov r0, #0x14c`).
pub const CLASS_9300_SIZE: usize = 0x14c;

/// An ADS C++ constructor: takes the raw block, returns `this`.
pub type Constructor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// Indirect dispatch table for the twelve unported constructors (see the
/// module header for the default-stub contract).
#[derive(Clone, Copy)]
pub struct SingletonCtors {
    /// Application-controller ctor @ 0x081847fc.
    pub app_controller: Constructor,
    /// Screen-object ctor @ 0x08177a78.
    pub app_screen: Constructor,
    /// TPodMediaPlayer ctor @ 0x0817d970.
    pub media_player: Constructor,
    /// Registry-class-0x8900 ctor @ 0x081ee0c0.
    pub class_8900: Constructor,
    /// Registry-class-0x6200 ctor @ 0x0810ab3c.
    pub class_6200: Constructor,
    /// Registry-class-0x7f80 ctor @ 0x081b80b4.
    pub class_7f80: Constructor,
    /// The 0x3c object's ctor @ 0x0816e2ac.
    pub singleton_0x3c: Constructor,
    /// The 0x8c object's ctor @ 0x08160534.
    pub singleton_0x8c: Constructor,
    /// Registry-class-0x8c00 ctor @ 0x081a71fc.
    pub class_8c00: Constructor,
    /// Command-dispatcher ctor @ 0x081dfc1c.
    pub command_dispatcher: Constructor,
    /// Volume-controller ctor @ 0x081fa070.
    pub volume_controller: Constructor,
    /// The 0x58 object's ctor @ 0x0812ce88.
    pub singleton_0x58: Constructor,
    /// The 0x40 object's ctor @ 0x0825bd20.
    pub singleton_0x40: Constructor,
    /// Registry-class-0x6280 ctor @ 0x0811c7fc.
    pub class_6280: Constructor,
    /// Stage-progress-tracker ctor @ 0x081fa440.
    pub stage_progress_tracker: Constructor,
    /// Registry-class-0x9300 ctor @ 0x08130424.
    pub class_9300: Constructor,
}

/// Defines one default constructor stub: zeroes the block and returns
/// it. A faithful *subset* — every original is dominated by zero stores
/// — but it installs no vtable and no registry wiring, which is why the
/// module header calls these symbols not hook-ready.
macro_rules! zeroing_ctor {
    ($name:ident, $size:expr) => {
        unsafe extern "C" fn $name(this: *mut u8) -> *mut u8 {
            zero_block(this, $size)
        }
    };
}

zeroing_ctor!(zeroing_controller_ctor, APP_CONTROLLER_SIZE);
zeroing_ctor!(zeroing_screen_ctor, APP_SCREEN_SIZE);
zeroing_ctor!(zeroing_media_player_ctor, MEDIA_PLAYER_SIZE);
zeroing_ctor!(zeroing_class_8900_ctor, CLASS_8900_SIZE);
zeroing_ctor!(zeroing_class_6200_ctor, CLASS_6200_SIZE);
zeroing_ctor!(zeroing_class_7f80_ctor, CLASS_7F80_SIZE);
zeroing_ctor!(zeroing_singleton_0x3c_ctor, SINGLETON_0X3C_SIZE);
zeroing_ctor!(zeroing_singleton_0x8c_ctor, SINGLETON_0X8C_SIZE);
zeroing_ctor!(zeroing_class_8c00_ctor, CLASS_8C00_SIZE);
zeroing_ctor!(zeroing_command_dispatcher_ctor, COMMAND_DISPATCHER_SIZE);
zeroing_ctor!(zeroing_volume_controller_ctor, VOLUME_CONTROLLER_SIZE);
zeroing_ctor!(zeroing_singleton_0x58_ctor, SINGLETON_0X58_SIZE);
zeroing_ctor!(zeroing_singleton_0x40_ctor, SINGLETON_0X40_SIZE);
zeroing_ctor!(zeroing_class_6280_ctor, CLASS_6280_SIZE);
zeroing_ctor!(zeroing_stage_progress_tracker_ctor, STAGE_PROGRESS_TRACKER_SIZE);
zeroing_ctor!(zeroing_class_9300_ctor, CLASS_9300_SIZE);

/// Zeroes `size` bytes and returns the block. Volatile stores: a plain
/// loop is rewritten by LLVM into a call to `__aeabi_memclr`, a symbol
/// that does not exist in this build (the strcat.rs / surface.rs trap).
unsafe fn zero_block(this: *mut u8, size: usize) -> *mut u8 {
    if !this.is_null() {
        for offset in 0..size {
            this.add(offset).write_volatile(0);
        }
    }
    this
}

/// Wired defaults (documented zeroing stubs until the ctors are ported).
pub(crate) const DEFAULT_SINGLETON_CTORS: SingletonCtors = SingletonCtors {
    app_controller: zeroing_controller_ctor,
    app_screen: zeroing_screen_ctor,
    media_player: zeroing_media_player_ctor,
    class_8900: zeroing_class_8900_ctor,
    class_6200: zeroing_class_6200_ctor,
    class_7f80: zeroing_class_7f80_ctor,
    singleton_0x3c: zeroing_singleton_0x3c_ctor,
    singleton_0x8c: zeroing_singleton_0x8c_ctor,
    class_8c00: zeroing_class_8c00_ctor,
    command_dispatcher: zeroing_command_dispatcher_ctor,
    volume_controller: zeroing_volume_controller_ctor,
    singleton_0x58: zeroing_singleton_0x58_ctor,
    singleton_0x40: zeroing_singleton_0x40_ctor,
    class_6280: zeroing_class_6280_ctor,
    stage_progress_tracker: zeroing_stage_progress_tracker_ctor,
    class_9300: zeroing_class_9300_ctor,
};

/// The active constructors. Host tests install recording mocks; the
/// real ports replace the defaults when they exist.
pub static mut SINGLETON_CTORS: SingletonCtors = DEFAULT_SINGLETON_CTORS;

/// Reads one ctor slot (volatile — same rationale as every dispatch
/// table: the slot is meant to be swapped at runtime).
macro_rules! ctor {
    ($field:ident) => {
        core::ptr::read_volatile(core::ptr::addr_of!(SINGLETON_CTORS.$field))
    };
}

/// The application-controller singleton (original: the word @
/// 0x089cc648 — see the module-header deviation).
pub static mut APP_CONTROLLER: *mut u8 = core::ptr::null_mut();

/// The screen singleton (original: the word @ 0x089cc1bc).
pub static mut APP_SCREEN: *mut u8 = core::ptr::null_mut();

/// The TPodMediaPlayer singleton (original: the word @ 0x089ca7cc, the
/// `+4` slot of the global @ 0x089ca7c8).
pub static mut MEDIA_PLAYER_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The registry-class-0x8900 singleton (original: the word @
/// 0x089cc3ac, the `+4` slot of the global @ 0x089cc3a8).
pub static mut CLASS_8900_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The registry-class-0x6200 singleton (original: the word @
/// 0x089cb308, the `+4` slot of the global @ 0x089cb304).
pub static mut CLASS_6200_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The registry-class-0x7f80 singleton (original: the word @
/// 0x089cc61c).
pub static mut CLASS_7F80_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The unidentified 0x3c singleton (original: the word @ 0x089d0130,
/// the `+0xc` slot of the global @ 0x089d0124).
pub static mut SINGLETON_0X3C: *mut u8 = core::ptr::null_mut();

/// The unidentified 0x8c singleton (original: the word @ 0x089ca7f0,
/// the pool literal @ 0x08160174).
pub static mut SINGLETON_0X8C: *mut u8 = core::ptr::null_mut();

/// The registry-class-0x8c00 singleton (original: the word @
/// 0x089cc7c0, the `+4` slot of the global @ 0x089cc7bc — the pool
/// literal at 0x081a552c).
pub static mut CLASS_8C00_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The command-dispatcher singleton (original: the word @ 0x089cc828,
/// the `+4` slot of the global @ 0x089cc824 — the pool literal
/// DAT_081dfa4c).
pub static mut COMMAND_DISPATCHER_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The volume-controller singleton (original: the word @ 0x089cc288,
/// the `+0x1c` slot of the global @ 0x089cc26c — the pool literal
/// DAT_081f77d0).
pub static mut VOLUME_CONTROLLER_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The unidentified 0x58 singleton (original: the word @ 0x089cc16c,
/// the `+4` slot of the shared globals block @ 0x089cc168 — the pool
/// literal @ 0x0812c758).
pub static mut SINGLETON_0X58: *mut u8 = core::ptr::null_mut();

/// The unidentified 0x40 singleton (original: the word @ 0x089cc94c,
/// the pool literal @ 0x0825b6ac — the next word after the settings
/// store's cache @ 0x089cc948).
pub static mut SINGLETON_0X40: *mut u8 = core::ptr::null_mut();

/// The registry-class-0x6280 singleton (original: the word @
/// 0x089cc30c, the pool literal @ 0x0811b2ec).
pub static mut CLASS_6280_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The stage-progress-tracker singleton (original: the word @
/// 0x089ca5d4, the `+0x48` slot of the global @ 0x089ca58c — the pool
/// literal @ 0x081fa3e8).
pub static mut STAGE_PROGRESS_TRACKER: *mut u8 = core::ptr::null_mut();

/// The registry-class-0x9300 singleton (original: the word @
/// 0x089cc2bc, the `+4` slot of the global @ 0x089cc2b8 — the pool
/// literal @ 0x081303d4).
pub static mut CLASS_9300_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The body all getters share: test the cache, allocate, construct,
/// store, and re-load the cache (the original's second `ldr r0, [r4, #N]`,
/// which is observable when another context changes the cache during the
/// constructor call).
///
/// The constructor arrives as a thunk so its dispatch-slot read stays
/// on the cold path, exactly where the original's `bl` is — passing the
/// pointer itself makes LLVM hoist the load above the cache test.
#[inline(always)]
unsafe fn lazy_singleton(
    cache: *mut *mut u8,
    size: usize,
    ctor: impl FnOnce() -> Constructor,
) -> *mut u8 {
    if core::ptr::read_volatile(cache).is_null() {
        let object = (ctor())(operator_new(size));
        core::ptr::write_volatile(cache, object);
    }
    core::ptr::read_volatile(cache)
}

/// app_controller_get — original: `FUN_0817ee04` @ 0x0817ee04
/// (44 bytes; 1108 `bl` call sites).
///
/// Returns the application-controller singleton, constructing it on
/// first use.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_controller_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(APP_CONTROLLER);
    lazy_singleton(cache, APP_CONTROLLER_SIZE, || unsafe { ctor!(app_controller) })
}

/// app_screen_get — original: `FUN_08173848` @ 0x08173848 (44 bytes;
/// 140 `bl` call sites).
///
/// Returns the screen singleton, constructing it on first use.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_screen_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(APP_SCREEN);
    lazy_singleton(cache, APP_SCREEN_SIZE, || unsafe { ctor!(app_screen) })
}

/// media_player_get — original: `FUN_0817ceb4` @ 0x0817ceb4 (44 bytes;
/// 101 `bl` call sites).
///
/// Returns the TPodMediaPlayer singleton — the media player controller —
/// constructing it on first use: `operator_new(0xa6c)` (the size is a
/// pool literal @ 0x0817cee4, too big for an ARM immediate) then the
/// constructor @ 0x0817d970, which names its class "TPodMediaPlayer"
/// through the name factory @ 0x0822053c. The instance is cached in the
/// `+4` slot of the global @ 0x089ca7c8. Same NOT-HOOK-READY caveat as
/// its siblings — see the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(MEDIA_PLAYER_INSTANCE);
    lazy_singleton(cache, MEDIA_PLAYER_SIZE, || unsafe { ctor!(media_player) })
}

/// media_player_interface_get — original: `FUN_08259594` @ 0x08259594
/// (20 bytes; 264 `bl` call sites — one of the hottest leaves in the
/// image).
///
/// Algorithm: `push {r4,lr}; bl media_player_get; cmp r0,#0;
/// addne r0,r0,#0x14; pop {r4,pc}` — fetch the TPodMediaPlayer
/// singleton and return a pointer to its interface sub-object at +0x14,
/// or NULL unchanged when the singleton is NULL (the NULL is *not*
/// offset). The +0x14 sub-object is the player's vtable-bearing
/// interface base: the constructor @ 0x0817d970 forms `r6 = this+0x14`
/// first and plants the vtable literal (pool @ 0x0817db6c) at `[r6]`,
/// and all 264 callers use the result purely as a `this` for virtual
/// dispatch (`ldr r1,[r0]; ldr r1,[r1,#N]; blx r1`, slots out past
/// +0x110). Same NOT-HOOK-READY caveat as the getters — see the module
/// header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_interface_get() -> *mut u8 {
    let player = media_player_get();
    if player.is_null() {
        player
    } else {
        player.add(0x14)
    }
}

/// singleton_class_8900 — original: `FUN_081eb0c4` @ 0x081eb0c4
/// (44 bytes; 88 `bl` call sites from 64 distinct callers).
///
/// The 0x380-byte singleton whose constructor publishes it in the by-id
/// class registry under id 0x8900 (`bl 0x081d23f8` @ 0x081ee0f0). The
/// class itself could not be named — see the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_class_8900() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(CLASS_8900_INSTANCE);
    lazy_singleton(cache, CLASS_8900_SIZE, || unsafe { ctor!(class_8900) })
}

/// singleton_class_6200 — original: `FUN_0810a7b8` @ 0x0810a7b8
/// (44 bytes; 47 `bl` call sites).
///
/// The 0xd0-byte singleton registered under class id 0x6200
/// (`mov r1, #0x6200` @ 0x0810abc4, `bl 0x081d23f8` @ 0x0810ac1c). Its
/// constructor also parks the layout-resource names
/// "Menu_AboutID_Template_iPod_Layout",
/// "ResetAllSettings_Language_Layout" and
/// "DialogNotice_InsufficientDiskSpace_Layout" in the object, so it is
/// somewhere in the settings/about area — not enough to name the class.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_class_6200() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(CLASS_6200_INSTANCE);
    lazy_singleton(cache, CLASS_6200_SIZE, || unsafe { ctor!(class_6200) })
}

/// singleton_class_7f80 — original: `FUN_081b803c` @ 0x081b803c
/// (44 bytes; 38 `bl` call sites).
///
/// The 0x1d4-byte singleton registered under class id 0x7f80
/// (`bl 0x081d23f8` @ 0x081b8194). Class not named — see the module
/// header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_class_7f80() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(CLASS_7F80_INSTANCE);
    lazy_singleton(cache, CLASS_7F80_SIZE, || unsafe { ctor!(class_7f80) })
}

/// lazy_singleton_0x3c — original: `FUN_0816df60` @ 0x0816df60
/// (44 bytes; 38 `bl` call sites).
///
/// The 0x3c-byte singleton. Unlike its three siblings this one's
/// constructor registers nothing and names nothing, so **its size is
/// the only identifying fact the firmware offers** and the symbol says
/// exactly that.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_singleton_0x3c() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(SINGLETON_0X3C);
    lazy_singleton(cache, SINGLETON_0X3C_SIZE, || unsafe { ctor!(singleton_0x3c) })
}

/// lazy_singleton_0x8c — original: `FUN_08160148` @ **0x08160148**
/// (44 bytes of code + one pool word @ 0x08160174 = **48 bytes** true
/// extent; **32 `bl` call sites, all unconditional — 0 predicated, 0 plain
/// `b`**, verified by decoding every B/BL word in `osos.dec`).
///
/// Algorithm: load the cache word @ 0x089ca7f0; on NULL, allocate exactly
/// 0x8c bytes with `operator_new`, call constructor `FUN_08160534`, store
/// its return, then reload and return the cache. Raw bytes show the next
/// function begins at 0x08160178, after this function's literal pool;
/// Ghidra's 44-byte extent drops that word.
///
/// The object has no recovered class name or registry id. Its constructor
/// plants the media-player interface vtable 0x089a75c8 at +0x00, then
/// connects to `TMediaNowPlayingCntlr`; that proves it is media-adjacent but
/// not a concrete identity, so the symbol names only the verified singleton
/// shape. Deviation: its unported constructor is the `singleton_0x8c`
/// dispatch slot, with the family zeroing default and crate cache rather
/// than the runtime-initialized 0x089cxxxx word. It is therefore not
/// hook-ready until `FUN_08160534` is ported.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_singleton_0x8c() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(SINGLETON_0X8C);
    lazy_singleton(cache, SINGLETON_0X8C_SIZE, || unsafe { ctor!(singleton_0x8c) })
}

/// lazy_singleton_0x58 — original: `FUN_0812c72c` @ **0x0812c72c**
/// (44 bytes of code + one pool word @ 0x0812c758 = **48 bytes** of
/// true extent; **46 `bl` call sites, 0 predicated and 0 plain `b`**,
/// binary-verified by decoding every B/BL word in
/// `work/firmware/osos.dec`).
///
/// ```text
/// 0812c72c  push {r4, lr}
/// 0812c730  ldr  r4, [pc, #32]      @ = 0x089cc168 (pool @ 0x0812c758)
/// 0812c734  ldr  r0, [r4, #4]
/// 0812c738  cmp  r0, #0
/// 0812c73c  bne  0x0812c750
/// 0812c740  mov  r0, #0x58
/// 0812c744  bl   0x082aadd4         @ operator new
/// 0812c748  bl   0x0812ce88         @ constructor
/// 0812c74c  str  r0, [r4, #4]
/// 0812c750  ldr  r0, [r4, #4]
/// 0812c754  pop  {r4, pc}
/// 0812c758  .word 0x089cc168
/// ```
///
/// The 0x58-byte singleton of the shared globals block @ 0x089cc168,
/// cached in that block's `+0x04` slot and constructed by
/// `FUN_0812ce88`. Ghidra reports 44 bytes because it drops the
/// trailing literal word; the true extent runs to 0x0812c75c, where
/// the next function opens `ldr r0, [r0, #0x30]`. Sitting next to
/// `timer_stop`/`timer_restart` it is **not** a member of the timer
/// family — the neighbour at 0x0812c6b0 shares only the address page.
///
/// The class could not be named — see the module header. Same
/// NOT-HOOK-READY caveat as its siblings.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_singleton_0x58() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(SINGLETON_0X58);
    lazy_singleton(cache, SINGLETON_0X58_SIZE, || unsafe { ctor!(singleton_0x58) })
}

/// singleton_class_8c00 — original: `FUN_081a5500` @ 0x081a5500
/// (44 bytes of code + one pool word @ 0x081a552c = 48 bytes total;
/// **82 `bl` call sites from 60 distinct callers**, binary-verified by
/// decoding every B/BL word in the image — no plain-`b` tail sites).
///
/// The 0xDC-byte singleton registered under class id 0x8c00, allocated
/// with `mov r0, #0xdc; bl 0x082aadd4` and constructed by
/// `FUN_081a71fc`. Ghidra reports the extent as 44 bytes because it
/// drops the trailing literal word — the function's own constant pool
/// holds 0x089cc7bc, and the cache is that global's `+4` slot
/// (`ldr r4, [pc, #32]; ldr r0, [r4, #4]`), so the true extent runs to
/// 0x081a5530 where the next function opens `push {r4, r5, r6, lr}`.
///
/// This is the object the kernel gateway path waits on: the ported
/// `gateway_wait_ready` @ 0x080c8304 polls `[this + 0x6a]` until it
/// reads 1, one of the 82 sites (`bl` @ 0x080c8314). It still reaches
/// the object through its own `GATEWAY_STATE` slot rather than calling
/// here, and deliberately so — see the module header: until
/// `FUN_081a71fc` is ported the zeroing default never sets +0x6a, so
/// wiring this getter in would swap one never-ready stub for another
/// that also allocates 0xDC bytes on every boot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_class_8c00() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(CLASS_8C00_INSTANCE);
    lazy_singleton(cache, CLASS_8C00_SIZE, || unsafe { ctor!(class_8c00) })
}

/// command_dispatcher_get — original: `FUN_081dfa20` @ 0x081dfa20
/// (44 bytes of code + one pool word @ 0x081dfa4c = 48 bytes total;
/// 73 direct `bl` call sites, 198 counting the veneer).
///
/// Returns the command-dispatcher singleton, constructing it on first
/// use: `operator_new(0x20)` (`mov r0, #0x20`) then the constructor @
/// 0x081dfc1c, cached in the `+4` slot of the global @ 0x089cc824
/// (the pool literal DAT_081dfa4c). The object is a vtable
/// (0x0898ebac) plus an embedded libstdc++ map at +0x04 keyed by
/// command-name string — the framework's command-handler registry that
/// 39 of the call sites dispatch through and 9 register into (see the
/// module header). Ghidra reports the extent as 44 bytes because it
/// drops the trailing literal word; the true extent runs to
/// 0x081dfa50, where the next function opens `push {r4, lr}`.
/// Same NOT-HOOK-READY caveat as its siblings — see the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn command_dispatcher_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(COMMAND_DISPATCHER_INSTANCE);
    lazy_singleton(cache, COMMAND_DISPATCHER_SIZE, || unsafe {
        ctor!(command_dispatcher)
    })
}

/// command_dispatcher_get_veneer — original: `thunk_FUN_0820b230` @
/// 0x0820b230 (4 bytes; **125** `bl` call sites, more than the 73 that
/// reach [`command_dispatcher_get`] directly).
///
/// One instruction — `b 0x081dfa20` (0xeaff51fa) — the long-branch
/// veneer the linker planted so the 0x0820xxxx-and-beyond callers
/// could reach the dispatcher getter. Genuinely 4 bytes, not the 8 of
/// the `ldr pc, [pc, #-4]` + target-word form: the word before it
/// (0x0820b22c) is a `bx lr` ending the previous function and the word
/// after it (0x0820b234) opens the next with `push {r3, r4, r5, lr}`.
///
/// Kept as its own `#[inline(never)]` symbol rather than a Rust alias
/// so a hook at 0x0820b230 lands on a real veneer that branches on to
/// the getter, exactly as the image has it (the `app/service_manager`
/// veneer precedent). Same NOT-HOOK-READY caveat as its target — see
/// the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn command_dispatcher_get_veneer() -> *mut u8 {
    command_dispatcher_get()
}

/// volume_controller_get — original: `FUN_081f77a4` @ 0x081f77a4
/// (44 bytes of code + one pool word @ 0x081f77d0 = 48 bytes total;
/// 52 `bl` call sites).
///
/// Returns the volume-controller singleton — registry class 0x7f00 —
/// constructing it on first use: `operator_new(0x3bc)` (`mov r0,
/// #0x3bc`) then the constructor @ 0x081fa070, cached in the `+0x1c`
/// slot of the global @ 0x089cc26c (the pool literal DAT_081f77d0),
/// one slot deeper than this family's usual `+4`. The 0..100-clamped,
/// wheel-driven adjuster `FUN_081f9120` and the "EnterVolume" menu
/// handler are what identify the object — see the module header.
/// Ghidra reports the extent as 44 bytes because it drops the trailing
/// literal word; the true extent runs to 0x081f77d4, where the next
/// function opens `push {r4, lr}`. Same NOT-HOOK-READY caveat as its
/// siblings — see the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn volume_controller_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(VOLUME_CONTROLLER_INSTANCE);
    lazy_singleton(cache, VOLUME_CONTROLLER_SIZE, || unsafe {
        ctor!(volume_controller)
    })
}

/// lazy_singleton_0x40 — original: `FUN_0825b680` @ **0x0825b680**
/// (44 bytes of code + one pool word @ 0x0825b6ac = **48 bytes** of
/// true extent; **43 `bl` call sites, all unconditional — 0 predicated,
/// 0 plain `b`** — binary-verified by decoding every B/BL word in
/// `work/firmware/osos.dec`).
///
/// ```text
/// 0825b680  push {r4, lr}
/// 0825b684  ldr  r4, [pc, #32]      @ = 0x089cc94c (pool @ 0x0825b6ac)
/// 0825b688  ldr  r0, [r4]
/// 0825b68c  cmp  r0, #0
/// 0825b690  bne  0x0825b6a4
/// 0825b694  mov  r0, #0x40
/// 0825b698  bl   0x082aadd4         @ operator new
/// 0825b69c  bl   0x0825bd20         @ constructor (Ghidra drops its `this`)
/// 0825b6a0  str  r0, [r4]
/// 0825b6a4  ldr  r0, [r4]           @ reload the slot before returning
/// 0825b6a8  pop  {r4, pc}
/// 0825b6ac  .word 0x089cc94c
/// ```
///
/// The twelfth member of this family: test the cache word @ 0x089cc94c,
/// and when it is NULL allocate exactly 0x40 bytes with the ported
/// `operator_new`, run the constructor @ 0x0825bd20 over the raw block,
/// store the ctor's return into the cache, RELOAD the slot and return
/// it (so a self-caching ctor wins, and a NULL-returning ctor leaves no
/// failure memory — the next call re-allocates). The true extent runs to
/// 0x0825b6b0, where the next function opens `push {r4, lr}`.
///
/// What the object is: its constructor plants a vtable literal
/// **0x089a7ffc** at +0 (that page is runtime-initialized — the image
/// holds a stale copy whose slot words land mid-flow of their target
/// functions, so the vtable cannot be read for a class name; see the
/// app/registry.rs page-mismatch note), builds an embedded fixed-block
/// pool at +4 through FUN_083c0ba8 (20-byte records, growth n+n/2+n/8,
/// free-list head chained through each node's +12) and parks that
/// pool's descriptor pointer at +0x14 with the descriptor's +8/+12
/// self-pointing (a circular sentinel), constructs a mutex at +32 via
/// the ported cxx_mutex_construct @ 0x08261e28, and zeroes byte +62
/// last — which is what makes 0x40 the allocation size. The 43 call
/// sites use it as a hub: they register sub-objects through vtable
/// slot +8 (`FUN_0816566c` hands it `this+0xd0`; the registry-class-
/// 0x8c00 ctor hands it `this+0x1c`) and poll booleans through slots
/// +0x18 / +0x48 / +0x4c (the stopwatch retry loop @ 0x08216568 gates
/// on the +0x4c answer). Some sites check the RESULT for NULL
/// (0x08216574 `cmp r0,#0; beq`) because a failed construction
/// propagates NULL — none of the calls themselves are predicated.
/// **Class NOT named**: neither the ctor nor any call site reaches a
/// name factory or carries a name literal, so — like
/// [`lazy_singleton_0x3c`] and [`lazy_singleton_0x58`] — the symbol
/// says only the size.
///
/// Deviations: the ctor rides the [`SINGLETON_CTORS`] dispatch table
/// (`singleton_0x40` slot, documented zeroing default — NOT HOOK-READY,
/// the family contract) and the cache is the crate static
/// [`SINGLETON_0X40`] rather than the word @ 0x089cc94c (the
/// block_mgr.rs RW-page deviation). Same NOT-HOOK-READY caveat as every
/// sibling — see the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_singleton_0x40() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(SINGLETON_0X40);
    lazy_singleton(cache, SINGLETON_0X40_SIZE, || unsafe { ctor!(singleton_0x40) })
}

/// singleton_class_6280 — original: `FUN_0811b2c0` @ **0x0811b2c0**
/// (44 bytes of code + one pool word @ 0x0811b2ec = **48 bytes** of
/// true extent; **43 `bl` call sites, all unconditional — 0 predicated,
/// 0 plain `b`** — binary-verified by decoding every B/BL word in
/// `work/firmware/osos.dec`).
///
/// ```text
/// 0811b2c0  push {r4, lr}
/// 0811b2c4  ldr  r4, [pc, #32]      @ = 0x089cc30c (pool @ 0x0811b2ec)
/// 0811b2c8  ldr  r0, [r4]
/// 0811b2cc  cmp  r0, #0
/// 0811b2d0  bne  0x0811b2e4
/// 0811b2d4  mov  r0, #0xa0
/// 0811b2d8  bl   0x082aadd4         @ operator new
/// 0811b2dc  bl   0x0811c7fc         @ constructor
/// 0811b2e0  str  r0, [r4]
/// 0811b2e4  ldr  r0, [r4]           @ reload the slot before returning
/// 0811b2e8  pop  {r4, pc}
/// 0811b2ec  .word 0x089cc30c
/// ```
///
/// The thirteenth member of this family: test the cache word @
/// 0x089cc30c, and when it is NULL allocate exactly 0xa0 bytes with the
/// ported `operator_new`, run the constructor @ 0x0811c7fc over the raw
/// block, store the ctor's return into the cache, RELOAD the slot and
/// return it (so a self-caching ctor wins, and a NULL-returning ctor
/// leaves no failure memory — the next call re-allocates). The true
/// extent runs to 0x0811b2f0, where the next function opens
/// `push {r4-r8, lr}`.
///
/// What the object is: its constructor plants vtable literal
/// **0x08981d2c** at +0 and a secondary vtable **0x08982934** on an
/// embedded sub-object, then registers the object in the by-id class
/// registry under id **0x6280** — the pool literal @ 0x0811c968 loaded
/// @ 0x0811c884 (`ldr r1, [pc, #220]`) immediately before
/// `bl 0x081d23f8` @ 0x0811c88c. The registered pointer is `this`
/// itself: the compiler forms `(FUN_0811d8ac(this + 0x6c) + 0x20) -
/// 0x8c` through two opaque calls whose arithmetic folds back to
/// `this` (the initializer FUN_0811d8ac returns its argument — see the
/// app/file_open_init note in names.yaml). It also allocates a
/// 0x34-byte sub-block through `operator_new` and builds it with
/// FUN_081bb450(·, 6, 1, 0x15e), plus an 8-byte pair initialized by
/// FUN_0810dddc. Unlike [`lazy_singleton_0x3c`] / [`lazy_singleton_0x58`]
/// / [`lazy_singleton_0x40`] this class IS identified — by its own
/// registry id, exactly like [`singleton_class_8900`] & co. The 43 call
/// sites use it as a hub: fetch the singleton, then hand it straight to
/// worker functions (0x0811c564 / 0x0811c010 / 0x0811c284 at the
/// 0x0822f97c cluster) or park it in a field (+0xbc of the object built
/// @ 0x0811aecc). None of the calls is predicated.
///
/// Deviations: the ctor rides the [`SINGLETON_CTORS`] dispatch table
/// (`class_6280` slot, documented zeroing default — NOT HOOK-READY, the
/// family contract) and the cache is the crate static
/// [`CLASS_6280_INSTANCE`] rather than the word @ 0x089cc30c (the
/// block_mgr.rs RW-page deviation; the image word there is stale UI
/// string data, `"ls_T"`). Same NOT-HOOK-READY caveat as every sibling
/// — see the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_class_6280() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(CLASS_6280_INSTANCE);
    lazy_singleton(cache, CLASS_6280_SIZE, || unsafe { ctor!(class_6280) })
}

/// stage_progress_tracker_get — original: `FUN_081fa3b0` @ **0x081fa3b0**
/// (56 bytes of code + one pool word @ 0x081fa3e8 = **60 bytes** of true
/// extent; **30 `bl` call sites, all unconditional — 0 predicated, 0 plain
/// `b`** — binary-verified by decoding every B/BL word in
/// `work/firmware/osos.dec`).
///
/// ```text
/// 081fa3b0  push {r4, r5, r6, lr}
/// 081fa3b4  ldr  r4, [pc, #44]      @ = 0x089ca58c (pool @ 0x081fa3e8)
/// 081fa3b8  ldr  r0, [r4, #72]      @ the +0x48 slot
/// 081fa3bc  cmp  r0, #0
/// 081fa3c0  bne  0x081fa3e0
/// 081fa3c4  mov  r0, #0x2c
/// 081fa3c8  bl   0x082aadd4         @ operator new
/// 081fa3cc  mov  r5, r0             @ keep the RAW allocation
/// 081fa3d0  bl   0x081fa440         @ constructor
/// 081fa3d4  cmp  r5, #0
/// 081fa3d8  str  r5, [r4, #72]      @ caches the raw allocation ...
/// 081fa3dc  bleq 0x08030f44         @ ... then heap_panic on OOM
/// 081fa3e0  ldr  r0, [r4, #72]      @ reload the slot before returning
/// 081fa3e4  pop  {r4, r5, r6, pc}
/// 081fa3e8  .word 0x089ca58c
/// ```
///
/// Ghidra's 56-byte extent is exact for the code but drops the trailing
/// literal word; the next function (the sibling `FUN_081fa3ec` stage
/// wait) opens `push {r4, r5, r6, lr}` at 0x081fa3ec.
///
/// What the object is: a 0x2c-byte **stage progress tracker** for the
/// long database-commit/copy paths — byte +0x00 the current stage index
/// (0..7), word +0x04 the progress counter, word +0x08 the accumulated
/// base, word +0x0c the total budget, and seven per-stage budget words
/// at +0x10..+0x2b. Its constructor @ 0x081fa440 zeroes the whole
/// object, then resets the global deadline keeper @ 0x089cc79c: the
/// running deadline at keeper+0x24 to 0 (through the veneer 0x081b9154
/// → 0x0815940c) and the total budget at keeper+0x2c to `[this + 0xc]`
/// (veneer 0x081b9150 → 0x081593f4). The siblings around the getter
/// drive it: `FUN_081fa2e8` waits for the in-flight stage
/// (`FUN_081fa3ec`, which polls in 10-tick yields through the
/// `wait_or_yield` veneer 0x080e9eb0) then advances the stage byte and
/// folds the finished stages' budgets into +0x08; `FUN_081fa36c` bumps
/// the progress counter and falls into `FUN_081fa378`, which pushes a
/// fresh running deadline (base + progress) to the keeper when the
/// progress is inside the stage budget; `FUN_081fa33c` commits the
/// seven-budget total to keeper+0x2c. The 30 call sites: 22 in the
/// database-commit path `FUN_08068504` (which sets the stage budgets
/// from the Photo-Database/ArtworkDB/iTunesDB file sizes in KiB through
/// `FUN_080ac06c` and advances stages around each commit step), five in
/// the copy loops `FUN_081b9878` / `FUN_081b979c` (feeding
/// byte-count-derived progress into stages 5 and 6), plus one each at
/// 0x0807fca0, 0x0808781c and 0x080ac0b4. Class NOT named: no name
/// factory or registry id is reachable from the constructor, so the
/// symbol names the proven role.
///
/// Two structural breaks from the family idiom, both verified against
/// the raw words:
/// - **The raw allocation is cached, not the constructor's return.**
///   The original keeps `operator_new`'s r0 in r5 across the `bl` and
///   stores r5 — and it must: the constructor returns `[this + 0xc]`
///   (the just-zeroed total-budget word it hands to the deadline
///   keeper), not `this`. The ctor's return value is discarded.
/// - **OOM is fatal.** `cmp r5, #0; str r5, [r4, #72]; bleq
///   heap_panic`: the NULL is stored into the cache first, then
///   `heap_panic` @ 0x08030f44 runs and never returns — unlike the
///   other fourteen getters, which cache a NULL ctor result and
///   re-allocate on the next call. Note the constructor is invoked on
///   the NULL block BEFORE the panic (the `bl 0x081fa440` is
///   unpredicated); reproduced, though the heap_panic port makes the
///   path unreachable in practice.
///
/// Deviations: the ctor rides the [`SINGLETON_CTORS`] dispatch table
/// (`stage_progress_tracker` slot, documented zeroing default — the
/// zeroing IS faithful to the ctor's object writes, but the default
/// skips the deadline-keeper reset, so NOT HOOK-READY, the family
/// contract) and the cache is the crate static [`STAGE_PROGRESS_TRACKER`]
/// rather than the word @ 0x089ca5d4 (the block_mgr.rs RW-page
/// deviation). `heap_panic` is the ported `heap::veneers::heap_panic`,
/// called directly like the original's `bleq`. The pushed r6 is never
/// used (an ADS frame artifact); the port keeps no frame. Same
/// NOT-HOOK-READY caveat as every sibling — see the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stage_progress_tracker_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(STAGE_PROGRESS_TRACKER);
    if core::ptr::read_volatile(cache).is_null() {
        let raw = operator_new(STAGE_PROGRESS_TRACKER_SIZE);
        // The ctor runs even on a NULL block (unpredicated `bl`); its
        // return is discarded — the original caches r5, the raw
        // allocation.
        ctor!(stage_progress_tracker)(raw);
        core::ptr::write_volatile(cache, raw);
        if raw.is_null() {
            crate::heap::veneers::heap_panic();
        }
    }
    core::ptr::read_volatile(cache)
}

/// singleton_class_9300 — original: `FUN_081303a8` @ **0x081303a8**
/// (44 bytes of code + one pool word @ 0x081303d4 = **48 bytes** of
/// true extent; **28 `bl` call sites, all unconditional — 0 predicated,
/// 0 plain `b`** — binary-verified by decoding every B/BL word in
/// `work/firmware/osos.dec`).
///
/// ```text
/// 081303a8  push {r4, lr}
/// 081303ac  ldr  r4, [pc, #32]      @ = 0x089cc2b8 (pool @ 0x081303d4)
/// 081303b0  ldr  r0, [r4, #4]       @ the cache word 0x089cc2bc
/// 081303b4  cmp  r0, #0
/// 081303b8  bne  0x081303cc
/// 081303bc  mov  r0, #0x14c
/// 081303c0  bl   0x082aadd4         @ operator new
/// 081303c4  bl   0x08130424         @ constructor
/// 081303c8  str  r0, [r4, #4]
/// 081303cc  ldr  r0, [r4, #4]       @ reload the slot before returning
/// 081303d0  pop  {r4, pc}
/// 081303d4  .word 0x089cc2b8
/// ```
///
/// The sixteenth member of this family: test the `+4` slot of the
/// global @ 0x089cc2b8, and when it is NULL allocate exactly 0x14c
/// bytes with the ported `operator_new`, run the constructor @
/// 0x08130424 over the raw block, store the ctor's return into the
/// cache, RELOAD the slot and return it (so a self-caching ctor wins,
/// and a NULL-returning ctor leaves no failure memory — the next call
/// re-allocates). Ghidra's 44 bytes is the code only; the true extent
/// runs to 0x081303d8, where the next function opens
/// `push {r4, r5, r6, lr}`. Ghidra's own listing is also broken here:
/// it emits no C file for this getter at all.
///
/// What the object is: its constructor @ 0x08130424 (192 bytes,
/// 0x08130424..0x081304e4, followed by the NULL-guarded deleting
/// destructor @ 0x081304f0) runs the two-argument base ctor
/// FUN_08272474(this, 0), plants primary vtable **0x089841e4** at +0,
/// builds the embedded cxx observable_array sub-object at +0x18
/// (0x08271cec, ported in cxx/observable_array), plants secondary
/// vtable **0x089a4b48** at +0x18, sets byte +0x28 = 1 and word
/// +0x2c = 0, zeroes byte +0x70 and word +0x74, runs FUN_0839ebc4 at
/// +0x78 and the ported scoped_context_construct @ 0x08270394 at +0x7c,
/// runs the ported pair_header_base_construct @ 0x0810ebbc at +0x94,
/// then registers `this` in the by-id class registry under id **0x9300**
/// (`mov r1, #0x9300; bl 0x081d23f8` @ 0x0813048c, the ported
/// registry_register). It finishes by wiring an embedded timer: the
/// ported timer_schedule_shim @ 0x0811108c(this, this+0x44, 0, 0) makes
/// the object its own timer config word, then the ported
/// timer_start_after @ 0x0812c63c(this+0x44, 2000) arms a **2000 ms**
/// timer at +0x44; FUN_0812f6ec(this) and a stack-temp copy into +0x78
/// (FUN_0839ebc4 / FUN_0839ec70 / FUN_0839cbc0) close it out. The 28
/// call sites feed the object's own method cluster sitting immediately
/// around the getter — FUN_0812f754 / FUN_0812fda0 / FUN_0812fb64 /
/// FUN_0812ff28 / FUN_08130134 — e.g. the menu handler @ 0x081ca278,
/// which polls FUN_0812f754, runs FUN_08130134 when it answers
/// non-zero, and gates a command-dispatch pair on FUN_0812fb64(obj, 1).
/// Class NOT named: neither the ctor nor the base ctors reach a name
/// factory, so — like [`singleton_class_8900`] & co. — the symbol
/// carries the registry id only.
///
/// Deviations: the ctor rides the [`SINGLETON_CTORS`] dispatch table
/// (`class_9300` slot, documented zeroing default — NOT HOOK-READY,
/// the family contract) and the cache is the crate static
/// [`CLASS_9300_INSTANCE`] rather than the word @ 0x089cc2bc (the
/// block_mgr.rs RW-page deviation). Same NOT-HOOK-READY caveat as every
/// sibling — see the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_class_9300() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(CLASS_9300_INSTANCE);
    lazy_singleton(cache, CLASS_9300_SIZE, || unsafe { ctor!(class_9300) })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::HEAP_OPS;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that swaps the globals below.
    static SINGLETON_LOCK: Mutex<()> = Mutex::new(());

    /// The block the stub allocator hands out (big enough for the
    /// largest singleton, the 0xa6c media player).
    static mut ARENA: [u8; MEDIA_PLAYER_SIZE] = [0xa5; MEDIA_PLAYER_SIZE];

    /// Sizes passed to `operator new`, in order.
    static mut ALLOC_SIZES: Vec<usize> = Vec::new();

    /// Blocks handed to a constructor, in order.
    static mut CTOR_BLOCKS: Vec<*mut u8> = Vec::new();

    /// What the recording constructors return (NULL means "fail").
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

    unsafe extern "C" fn recording_ctor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    /// A non-NULL dummy heap handle so `lazy_init_default_heap` is a
    /// no-op and `stub_create` is never reached.
    static mut FAKE_HEAP: usize = 0;

    /// Installs the stub allocator plus recording constructors and
    /// clears both caches.
    fn mock(ctor_result: *mut u8) -> MutexGuard<'static, ()> {
        let guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = stub_alloc;
            ops.create = stub_create;
            HEAP_OPS = ops;
            DEFAULT_HEAP = ptr::addr_of_mut!(FAKE_HEAP) as *mut HeapDescriptorDescriptor;
            SINGLETON_CTORS = SingletonCtors {
                app_controller: recording_ctor,
                app_screen: recording_ctor,
                media_player: recording_ctor,
                class_8900: recording_ctor,
                class_6200: recording_ctor,
                class_7f80: recording_ctor,
                singleton_0x3c: recording_ctor,
                singleton_0x8c: recording_ctor,
                class_8c00: recording_ctor,
                command_dispatcher: recording_ctor,
                volume_controller: recording_ctor,
                singleton_0x58: recording_ctor,
                singleton_0x40: recording_ctor,
                class_6280: recording_ctor,
                stage_progress_tracker: recording_ctor,
                class_9300: recording_ctor,
            };
            CTOR_RESULT = ctor_result;
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).clear();
            clear_caches();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
            DEFAULT_HEAP = ptr::null_mut();
            SINGLETON_CTORS = DEFAULT_SINGLETON_CTORS;
            clear_caches();
        }
        drop(guard);
    }

    /// Resets every cache slot to its pre-init NULL.
    unsafe fn clear_caches() {
        APP_CONTROLLER = ptr::null_mut();
        APP_SCREEN = ptr::null_mut();
        MEDIA_PLAYER_INSTANCE = ptr::null_mut();
        CLASS_8900_INSTANCE = ptr::null_mut();
        CLASS_6200_INSTANCE = ptr::null_mut();
        CLASS_7F80_INSTANCE = ptr::null_mut();
        SINGLETON_0X3C = ptr::null_mut();
        SINGLETON_0X8C = ptr::null_mut();
        CLASS_8C00_INSTANCE = ptr::null_mut();
        COMMAND_DISPATCHER_INSTANCE = ptr::null_mut();
        VOLUME_CONTROLLER_INSTANCE = ptr::null_mut();
        SINGLETON_0X58 = ptr::null_mut();
        SINGLETON_0X40 = ptr::null_mut();
        CLASS_6280_INSTANCE = ptr::null_mut();
        STAGE_PROGRESS_TRACKER = ptr::null_mut();
        CLASS_9300_INSTANCE = ptr::null_mut();
    }

    fn arena() -> *mut u8 {
        ptr::addr_of_mut!(ARENA) as *mut u8
    }

    /// A distinct address the recording ctors can return.
    fn constructed() -> *mut u8 {
        unsafe { arena().add(16) }
    }

    #[test]
    fn the_controller_is_allocated_at_its_exact_size_and_constructed_once() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(app_controller_get(), constructed());
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![0xe8]);
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()]);
            assert_eq!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)), constructed(), "the ctor result is cached");
        }
        restore(guard);
    }

    #[test]
    fn the_screen_is_allocated_at_its_exact_size() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(app_screen_get(), constructed());
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![0x850]);
        }
        restore(guard);
    }

    #[test]
    fn the_media_player_is_allocated_at_its_exact_size_and_constructed_once() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(media_player_get(), constructed());
            assert_eq!(media_player_get(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![0xa6c],
                "the 0x0817cee4 pool literal, allocated exactly once"
            );
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(MEDIA_PLAYER_INSTANCE)),
                constructed(),
                "the ctor result is cached"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_interface_getter_returns_the_player_plus_0x14() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(media_player_interface_get(), constructed().add(0x14));
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![MEDIA_PLAYER_SIZE],
                "the singleton is still constructed exactly once, at its own size"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_interface_getter_returns_null_unchanged_when_the_player_is_null() {
        // `addne`: the NULL is not offset by 0x14.
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(media_player_interface_get().is_null());
            assert!(media_player_interface_get().is_null());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 2, "no failure memory, same as the getter");
        }
        restore(guard);
    }

    #[test]
    fn the_interface_getter_offsets_the_cached_player_on_every_call() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(media_player_interface_get(), constructed().add(0x14));
            assert_eq!(media_player_interface_get(), constructed().add(0x14));
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "the second call hits the cache");
        }
        restore(guard);
    }

    #[test]
    fn the_media_player_cache_is_independent_of_the_others() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(media_player_get(), constructed());
            assert!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)).is_null(), "untouched");
            assert!(ptr::read_volatile(ptr::addr_of!(APP_SCREEN)).is_null(), "untouched");
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![MEDIA_PLAYER_SIZE]);
        }
        restore(guard);
    }

    #[test]
    fn the_media_player_zeroing_stub_clears_the_whole_block() {
        let guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let block = ptr::addr_of_mut!(ARENA) as *mut u8;
            for offset in 0..MEDIA_PLAYER_SIZE {
                block.add(offset).write(0xa5);
            }
            assert_eq!(zeroing_media_player_ctor(block), block);
            assert!((0..MEDIA_PLAYER_SIZE).all(|offset| block.add(offset).read() == 0));
        }
        restore(guard);
    }

    #[test]
    fn the_second_call_returns_the_cache_without_allocating() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(app_controller_get(), constructed());
            assert_eq!(app_controller_get(), constructed());
            assert_eq!(app_controller_get(), constructed());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated exactly once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
        }
        restore(guard);
    }

    #[test]
    fn a_pre_seeded_cache_short_circuits_everything() {
        let guard = mock(constructed());
        unsafe {
            APP_CONTROLLER = arena().add(64);
            assert_eq!(app_controller_get(), arena().add(64));
            assert!((*ptr::addr_of!(ALLOC_SIZES)).is_empty());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty());
        }
        restore(guard);
    }

    #[test]
    fn a_null_returning_ctor_caches_null_and_the_next_call_retries() {
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(app_controller_get().is_null());
            assert!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)).is_null());
            assert!(app_controller_get().is_null());
            assert_eq!(
                (*ptr::addr_of!(ALLOC_SIZES)).len(),
                2,
                "the original has no failure memory: it re-allocates every call"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_two_singletons_have_independent_caches() {
        let guard = mock(constructed());
        unsafe {
            app_controller_get();
            assert_eq!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)), constructed());
            assert!(ptr::read_volatile(ptr::addr_of!(APP_SCREEN)).is_null(), "the screen cache is untouched");
            app_screen_get();
            assert_eq!(ptr::read_volatile(ptr::addr_of!(APP_SCREEN)), constructed());
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![0xe8, 0x850]);
        }
        restore(guard);
    }

    #[test]
    fn the_getter_reloads_the_slot_after_construction() {
        // The original ends with a second `ldr r0, [r4, #8]`, so a ctor
        // that stores the slot itself wins over its own return value.
        unsafe extern "C" fn self_caching_ctor(this: *mut u8) -> *mut u8 {
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this);
            APP_CONTROLLER = this.add(32);
            this.add(8) // deliberately different from what it stored
        }
        let guard = mock(ptr::null_mut());
        unsafe {
            SINGLETON_CTORS.app_controller = self_caching_ctor;
            // The getter's own store lands last, so its value is what
            // the reload sees.
            assert_eq!(app_controller_get(), arena().add(8));
            assert_eq!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)), arena().add(8));
        }
        restore(guard);
    }

    #[test]
    fn every_getter_allocates_its_own_size_and_caches_independently() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(singleton_class_8900(), constructed());
            assert_eq!(singleton_class_6200(), constructed());
            assert_eq!(singleton_class_7f80(), constructed());
            assert_eq!(lazy_singleton_0x3c(), constructed());
            assert_eq!(singleton_class_8c00(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![
                    CLASS_8900_SIZE,
                    CLASS_6200_SIZE,
                    CLASS_7F80_SIZE,
                    SINGLETON_0X3C_SIZE,
                    CLASS_8C00_SIZE
                ]
            );
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_8C00_INSTANCE)), constructed());
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_8900_INSTANCE)), constructed());
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_6200_INSTANCE)), constructed());
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_7F80_INSTANCE)), constructed());
            assert_eq!(ptr::read_volatile(ptr::addr_of!(SINGLETON_0X3C)), constructed());
            assert!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)).is_null(), "the other caches are untouched");
            assert!(ptr::read_volatile(ptr::addr_of!(APP_SCREEN)).is_null());
        }
        restore(guard);
    }

    #[test]
    fn the_original_allocation_sizes_are_the_literal_immediates() {
        assert_eq!(APP_CONTROLLER_SIZE, 0xe8);
        assert_eq!(APP_SCREEN_SIZE, 0x850);
        assert_eq!(CLASS_8900_SIZE, 0x380);
        assert_eq!(CLASS_6200_SIZE, 0xd0);
        assert_eq!(CLASS_7F80_SIZE, 0x1d4);
        assert_eq!(SINGLETON_0X3C_SIZE, 0x3c);
        assert_eq!(CLASS_8C00_SIZE, 0xdc);
    }

    #[test]
    fn the_class_8c00_getter_allocates_0xdc_once_and_caches_it() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(singleton_class_8c00(), constructed());
            assert_eq!(singleton_class_8c00(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![0xdc],
                "the `mov r0, #0xdc` immediate, allocated exactly once"
            );
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()], "constructed on the raw block");
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_8C00_INSTANCE)), constructed());
        }
        restore(guard);
    }

    #[test]
    fn a_pre_seeded_class_8c00_cache_never_allocates() {
        // The `cmp r0, #0; bne` fast path: the 82 call sites after the
        // first boot-time construction never touch the allocator.
        let guard = mock(constructed());
        unsafe {
            CLASS_8C00_INSTANCE = arena().add(96);
            assert_eq!(singleton_class_8c00(), arena().add(96));
            assert!((*ptr::addr_of!(ALLOC_SIZES)).is_empty());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty());
        }
        restore(guard);
    }

    #[test]
    fn a_null_returning_class_8c00_ctor_caches_null_and_retries() {
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(singleton_class_8c00().is_null());
            assert!(ptr::read_volatile(ptr::addr_of!(CLASS_8C00_INSTANCE)).is_null());
            assert!(singleton_class_8c00().is_null());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![CLASS_8C00_SIZE, CLASS_8C00_SIZE],
                "no failure memory: it re-allocates every call"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_class_8c00_zeroing_stub_clears_exactly_0xdc_bytes() {
        let guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let block = ptr::addr_of_mut!(ARENA) as *mut u8;
            for offset in 0..CLASS_8C00_SIZE + 4 {
                block.add(offset).write(0xa5);
            }
            assert_eq!(zeroing_class_8c00_ctor(block), block);
            assert!((0..CLASS_8C00_SIZE).all(|offset| block.add(offset).read() == 0));
            assert_eq!(block.add(CLASS_8C00_SIZE).read(), 0xa5, "not one byte past the object");
        }
        restore(guard);
    }

    #[test]
    fn each_new_getter_constructs_exactly_once() {
        let guard = mock(constructed());
        unsafe {
            for _ in 0..3 {
                assert_eq!(singleton_class_8900(), constructed());
                assert_eq!(lazy_singleton_0x3c(), constructed());
            }
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 2);
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 2);
        }
        restore(guard);
    }

    #[test]
    fn a_null_returning_ctor_retries_on_every_new_getter() {
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(singleton_class_7f80().is_null());
            assert!(singleton_class_7f80().is_null());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![CLASS_7F80_SIZE, CLASS_7F80_SIZE],
                "no failure memory: it re-allocates every call"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_command_dispatcher_is_allocated_constructed_and_cached_on_first_call() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(command_dispatcher_get(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![COMMAND_DISPATCHER_SIZE],
                "the `mov r0, #0x20` immediate, allocated exactly once"
            );
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()], "constructed on the raw block");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(COMMAND_DISPATCHER_INSTANCE)),
                constructed(),
                "the ctor result is cached"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_command_dispatcher_second_call_returns_the_cache_without_reconstructing() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(command_dispatcher_get(), constructed());
            assert_eq!(command_dispatcher_get(), constructed());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated exactly once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(COMMAND_DISPATCHER_INSTANCE)),
                constructed(),
                "the cache still holds the first construction"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_command_dispatcher_veneer_constructs_and_caches_exactly_like_its_target() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(command_dispatcher_get_veneer(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![COMMAND_DISPATCHER_SIZE],
                "the veneer allocates through the same getter, once"
            );
            assert_eq!(
                command_dispatcher_get(),
                command_dispatcher_get_veneer(),
                "both entry points hand out the one cached instance"
            );
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
        }
        restore(guard);
    }

    #[test]
    fn the_command_dispatcher_veneer_is_a_distinct_symbol_from_its_target() {
        // The image has two separate entry points (0x0820b230 branches
        // to 0x081dfa20); a Rust alias would make a hook at the veneer
        // address meaningless.
        assert_ne!(
            command_dispatcher_get_veneer as *const () as usize,
            command_dispatcher_get as *const () as usize
        );
    }

    #[test]
    fn the_volume_controller_is_allocated_constructed_and_cached_on_first_call() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(volume_controller_get(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![VOLUME_CONTROLLER_SIZE],
                "the `mov r0, #0x3bc` immediate, allocated exactly once"
            );
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()], "constructed on the raw block");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(VOLUME_CONTROLLER_INSTANCE)),
                constructed(),
                "the ctor result is cached"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_volume_controller_second_call_returns_the_cache() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(volume_controller_get(), constructed());
            assert_eq!(volume_controller_get(), constructed());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated exactly once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(VOLUME_CONTROLLER_INSTANCE)),
                constructed(),
                "the cache still holds the first construction"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_0x58_singleton_is_allocated_constructed_and_cached_on_first_call() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(lazy_singleton_0x58(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![SINGLETON_0X58_SIZE],
                "the `mov r0, #0x58` immediate, allocated exactly once"
            );
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()], "constructed on the raw block");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(SINGLETON_0X58)),
                constructed(),
                "cached in the +4 slot of the 0x089cc168 block"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_0x58_singleton_second_call_returns_the_cache() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(lazy_singleton_0x58(), constructed());
            assert_eq!(lazy_singleton_0x58(), constructed());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated exactly once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
        }
        restore(guard);
    }

    #[test]
    fn a_null_returning_0x58_ctor_caches_null_and_reallocates() {
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(lazy_singleton_0x58().is_null(), "the ctor's NULL is returned verbatim");
            assert!(lazy_singleton_0x58().is_null());
            assert_eq!(
                (*ptr::addr_of!(ALLOC_SIZES)).len(),
                2,
                "a NULL cache re-runs the whole body, exactly as the original does"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_0x8c_singleton_allocates_constructs_and_reloads_its_cache() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(lazy_singleton_0x8c(), constructed());
            assert_eq!(lazy_singleton_0x8c(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![SINGLETON_0X8C_SIZE],
                "the raw `mov r0, #0x8c` allocation happens once"
            );
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()], "the raw allocation feeds the ctor");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(SINGLETON_0X8C)),
                constructed(),
                "the ctor return is stored then reloaded"
            );
        }
        restore(guard);
    }

    #[test]
    fn a_null_returning_0x8c_ctor_retries_on_every_call() {
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(lazy_singleton_0x8c().is_null());
            assert!(lazy_singleton_0x8c().is_null());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![SINGLETON_0X8C_SIZE, SINGLETON_0X8C_SIZE],
                "NULL is cached, so the next call repeats allocation and construction"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_0x40_singleton_is_allocated_at_exactly_0x40_and_constructed_once() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(lazy_singleton_0x40(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![0x40],
                "the `mov r0, #0x40` immediate"
            );
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()], "constructed on the raw block");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(SINGLETON_0X40)),
                constructed(),
                "the ctor result is cached in the word @ 0x089cc94c"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_0x40_singleton_second_call_returns_the_cache() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(lazy_singleton_0x40(), constructed());
            assert_eq!(lazy_singleton_0x40(), constructed());
            assert_eq!(lazy_singleton_0x40(), constructed());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated exactly once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
        }
        restore(guard);
    }

    #[test]
    fn a_pre_seeded_0x40_cache_never_allocates() {
        // The `cmp r0, #0; bne` fast path: the 43 call sites after the
        // first construction never touch the allocator.
        let guard = mock(constructed());
        unsafe {
            SINGLETON_0X40 = arena().add(48);
            assert_eq!(lazy_singleton_0x40(), arena().add(48));
            assert!((*ptr::addr_of!(ALLOC_SIZES)).is_empty());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty());
        }
        restore(guard);
    }

    #[test]
    fn a_null_returning_0x40_ctor_caches_null_and_retries_on_every_call() {
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(lazy_singleton_0x40().is_null());
            assert!(ptr::read_volatile(ptr::addr_of!(SINGLETON_0X40)).is_null());
            assert!(lazy_singleton_0x40().is_null());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![SINGLETON_0X40_SIZE, SINGLETON_0X40_SIZE],
                "no failure memory: it re-allocates every call, which is why
                 some call sites check the result for NULL (0x08216574)"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_0x40_zeroing_stub_clears_exactly_64_bytes() {
        let guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let block = ptr::addr_of_mut!(ARENA) as *mut u8;
            for offset in 0..SINGLETON_0X40_SIZE + 4 {
                block.add(offset).write(0xa5);
            }
            assert_eq!(zeroing_singleton_0x40_ctor(block), block);
            assert!((0..SINGLETON_0X40_SIZE).all(|offset| block.add(offset).read() == 0));
            assert_eq!(
                block.add(SINGLETON_0X40_SIZE).read(),
                0xa5,
                "not one byte past the object (the ctor's last write is byte +62)"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_0x40_cache_is_independent_of_the_settings_store_next_door() {
        // The cache word 0x089cc94c is the very next word after the
        // settings store's 0x089cc948; the crate statics keep them apart.
        let guard = mock(constructed());
        unsafe {
            lazy_singleton_0x40();
            assert!(ptr::read_volatile(ptr::addr_of!(SINGLETON_0X3C)).is_null(), "untouched");
            assert!(ptr::read_volatile(ptr::addr_of!(COMMAND_DISPATCHER_INSTANCE)).is_null(), "untouched");
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![0x40]);
        }
        restore(guard);
    }

    #[test]
    fn the_class_6280_singleton_is_allocated_at_exactly_0xa0_and_constructed_once() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(singleton_class_6280(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![0xa0],
                "the `mov r0, #0xa0` immediate"
            );
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()], "constructed on the raw block");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(CLASS_6280_INSTANCE)),
                constructed(),
                "the ctor result is cached in the word @ 0x089cc30c"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_class_6280_singleton_second_call_returns_the_cache() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(singleton_class_6280(), constructed());
            assert_eq!(singleton_class_6280(), constructed());
            assert_eq!(singleton_class_6280(), constructed());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated exactly once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
        }
        restore(guard);
    }

    #[test]
    fn a_pre_seeded_class_6280_cache_never_allocates() {
        // The `cmp r0, #0; bne` fast path: the 43 call sites after the
        // first construction never touch the allocator.
        let guard = mock(constructed());
        unsafe {
            CLASS_6280_INSTANCE = arena().add(72);
            assert_eq!(singleton_class_6280(), arena().add(72));
            assert!((*ptr::addr_of!(ALLOC_SIZES)).is_empty());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty());
        }
        restore(guard);
    }

    #[test]
    fn a_null_returning_class_6280_ctor_caches_null_and_retries_on_every_call() {
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(singleton_class_6280().is_null());
            assert!(ptr::read_volatile(ptr::addr_of!(CLASS_6280_INSTANCE)).is_null());
            assert!(singleton_class_6280().is_null());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![CLASS_6280_SIZE, CLASS_6280_SIZE],
                "no failure memory: it re-allocates every call"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_class_6280_zeroing_stub_clears_exactly_0xa0_bytes() {
        let guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let block = ptr::addr_of_mut!(ARENA) as *mut u8;
            for offset in 0..CLASS_6280_SIZE + 4 {
                block.add(offset).write(0xa5);
            }
            assert_eq!(zeroing_class_6280_ctor(block), block);
            assert!((0..CLASS_6280_SIZE).all(|offset| block.add(offset).read() == 0));
            assert_eq!(
                block.add(CLASS_6280_SIZE).read(),
                0xa5,
                "not one byte past the object"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_class_6280_cache_is_independent_of_its_globals_page_neighbours() {
        // The cache word 0x089cc30c sits between the class-0x8900 cache
        // (0x089cc3ac) and the screen cache (0x089cc1bc) in the same
        // globals page; the crate statics keep them apart.
        let guard = mock(constructed());
        unsafe {
            singleton_class_6280();
            assert!(ptr::read_volatile(ptr::addr_of!(CLASS_8900_INSTANCE)).is_null(), "untouched");
            assert!(ptr::read_volatile(ptr::addr_of!(APP_SCREEN)).is_null(), "untouched");
            assert!(ptr::read_volatile(ptr::addr_of!(SINGLETON_0X40)).is_null(), "untouched");
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![0xa0]);
        }
        restore(guard);
    }

    #[test]
    fn the_default_ctor_stubs_zero_the_block_and_return_it() {
        let guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let block = ptr::addr_of_mut!(ARENA) as *mut u8;
            for offset in 0..APP_SCREEN_SIZE {
                block.add(offset).write(0xa5);
            }
            assert_eq!(zeroing_controller_ctor(block), block);
            for offset in 0..APP_CONTROLLER_SIZE {
                assert_eq!(block.add(offset).read(), 0, "byte +{offset:#x}");
            }
            assert_eq!(block.add(APP_CONTROLLER_SIZE).read(), 0xa5, "no overrun");

            assert_eq!(zeroing_screen_ctor(block), block);
            assert!((0..APP_SCREEN_SIZE).all(|offset| block.add(offset).read() == 0));

            assert!(zeroing_controller_ctor(ptr::null_mut()).is_null(), "NULL-safe");
        }
        restore(guard);
    }

    #[test]
    fn the_stage_progress_tracker_caches_the_raw_allocation_not_the_ctor_return() {
        // The defining difference from every sibling: `str r5, [r4,
        // #72]` stores operator_new's r0, kept in r5 across the ctor
        // `bl` — the ctor's return (the original's `[this + 0xc]`
        // budget word) is discarded.
        let guard = mock(constructed());
        unsafe {
            assert_eq!(
                stage_progress_tracker_get(),
                arena(),
                "the raw block is returned although the ctor produced a different pointer"
            );
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![STAGE_PROGRESS_TRACKER_SIZE],
                "the `mov r0, #0x2c` immediate, allocated exactly once"
            );
            assert_eq!(
                *ptr::addr_of!(CTOR_BLOCKS),
                std::vec![arena()],
                "the ctor is constructed on the raw block"
            );
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(STAGE_PROGRESS_TRACKER)),
                arena(),
                "the +0x48 slot of the 0x089ca58c global holds the raw allocation"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_stage_progress_tracker_second_call_returns_the_cache() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(stage_progress_tracker_get(), arena());
            assert_eq!(stage_progress_tracker_get(), arena());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated exactly once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
        }
        restore(guard);
    }

    #[test]
    fn a_pre_seeded_stage_progress_tracker_cache_never_allocates() {
        // The `cmp r0, #0; bne` fast path.
        let guard = mock(constructed());
        unsafe {
            STAGE_PROGRESS_TRACKER = arena().add(56);
            assert_eq!(stage_progress_tracker_get(), arena().add(56));
            assert!((*ptr::addr_of!(ALLOC_SIZES)).is_empty());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty());
        }
        restore(guard);
    }

    #[test]
    fn the_stage_progress_tracker_store_lands_after_its_ctor_runs() {
        // Order is alloc -> ctor -> store: a ctor that pokes the cache
        // slot itself is overwritten by the raw-allocation store (the
        // original's `str r5` follows the `bl 0x081fa440`).
        unsafe extern "C" fn cache_poking_ctor(this: *mut u8) -> *mut u8 {
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this);
            STAGE_PROGRESS_TRACKER = this.add(24);
            this.add(40)
        }
        let guard = mock(ptr::null_mut());
        unsafe {
            SINGLETON_CTORS.stage_progress_tracker = cache_poking_ctor;
            assert_eq!(stage_progress_tracker_get(), arena(), "the raw-allocation store wins");
            assert_eq!(ptr::read_volatile(ptr::addr_of!(STAGE_PROGRESS_TRACKER)), arena());
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()], "the ctor still ran, once");
        }
        restore(guard);
    }

    #[test]
    fn the_stage_progress_tracker_zeroing_stub_clears_exactly_0x2c_bytes() {
        // The original ctor zeroes byte +0 and words +4/+8/+0xc
        // outright, then the 28 budget bytes at +0x10..+0x2b through
        // the IRAM memclr veneer 0x08037db8 — the whole object.
        let guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let block = ptr::addr_of_mut!(ARENA) as *mut u8;
            for offset in 0..STAGE_PROGRESS_TRACKER_SIZE + 4 {
                block.add(offset).write(0xa5);
            }
            assert_eq!(zeroing_stage_progress_tracker_ctor(block), block);
            assert!((0..STAGE_PROGRESS_TRACKER_SIZE).all(|offset| block.add(offset).read() == 0));
            assert_eq!(block.add(STAGE_PROGRESS_TRACKER_SIZE).read(), 0xa5, "not one byte past the object");
            assert!(zeroing_stage_progress_tracker_ctor(ptr::null_mut()).is_null(), "NULL-safe");
        }
        restore(guard);
    }

    #[test]
    fn the_stage_progress_tracker_cache_is_independent_of_its_siblings() {
        // The cache word 0x089ca5d4 is the +0x48 slot of a global whose
        // other words are unrelated state (the +0x4 slot mirrors the
        // +0xb1c RTC-context halfword); the crate statics keep them
        // apart.
        let guard = mock(constructed());
        unsafe {
            stage_progress_tracker_get();
            assert!(ptr::read_volatile(ptr::addr_of!(SINGLETON_0X40)).is_null(), "untouched");
            assert!(ptr::read_volatile(ptr::addr_of!(CLASS_6280_INSTANCE)).is_null(), "untouched");
            assert!(ptr::read_volatile(ptr::addr_of!(VOLUME_CONTROLLER_INSTANCE)).is_null(), "untouched");
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![STAGE_PROGRESS_TRACKER_SIZE]);
        }
        restore(guard);
    }

    #[test]
    fn the_class_9300_singleton_is_allocated_at_exactly_0x14c_and_constructed_once() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(singleton_class_9300(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![0x14c],
                "the `mov r0, #0x14c` immediate"
            );
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()], "constructed on the raw block");
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(CLASS_9300_INSTANCE)),
                constructed(),
                "the ctor result is cached in the +4 slot of the word @ 0x089cc2b8"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_class_9300_singleton_second_call_returns_the_cache() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(singleton_class_9300(), constructed());
            assert_eq!(singleton_class_9300(), constructed());
            assert_eq!(singleton_class_9300(), constructed());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated exactly once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
        }
        restore(guard);
    }

    #[test]
    fn a_pre_seeded_class_9300_cache_never_allocates() {
        // The `cmp r0, #0; bne` fast path: the 28 call sites after the
        // first construction never touch the allocator.
        let guard = mock(constructed());
        unsafe {
            CLASS_9300_INSTANCE = arena().add(96);
            assert_eq!(singleton_class_9300(), arena().add(96));
            assert!((*ptr::addr_of!(ALLOC_SIZES)).is_empty());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty());
        }
        restore(guard);
    }

    #[test]
    fn a_null_returning_class_9300_ctor_caches_null_and_retries_on_every_call() {
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(singleton_class_9300().is_null());
            assert!(ptr::read_volatile(ptr::addr_of!(CLASS_9300_INSTANCE)).is_null());
            assert!(singleton_class_9300().is_null());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![CLASS_9300_SIZE, CLASS_9300_SIZE],
                "no failure memory: it re-allocates every call"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_class_9300_store_lands_after_its_ctor_runs() {
        // Order is alloc -> ctor -> store: a ctor that pokes the cache
        // slot itself is overwritten by the store of the ctor's return
        // (the original's `str r0, [r4, #4]` follows the `bl
        // 0x08130424`), and the reload then returns that stored value.
        unsafe extern "C" fn cache_poking_ctor(this: *mut u8) -> *mut u8 {
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this);
            CLASS_9300_INSTANCE = this.add(32);
            this.add(48)
        }
        let guard = mock(ptr::null_mut());
        unsafe {
            SINGLETON_CTORS.class_9300 = cache_poking_ctor;
            assert_eq!(singleton_class_9300(), arena().add(48), "the ctor-return store wins");
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_9300_INSTANCE)), arena().add(48));
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()], "the ctor still ran, once");
        }
        restore(guard);
    }

    #[test]
    fn the_class_9300_zeroing_stub_clears_exactly_0x14c_bytes() {
        let guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let block = ptr::addr_of_mut!(ARENA) as *mut u8;
            for offset in 0..CLASS_9300_SIZE + 4 {
                block.add(offset).write(0xa5);
            }
            assert_eq!(zeroing_class_9300_ctor(block), block);
            assert!((0..CLASS_9300_SIZE).all(|offset| block.add(offset).read() == 0));
            assert_eq!(
                block.add(CLASS_9300_SIZE).read(),
                0xa5,
                "not one byte past the object"
            );
            assert!(zeroing_class_9300_ctor(ptr::null_mut()).is_null(), "NULL-safe");
        }
        restore(guard);
    }

    #[test]
    fn the_class_9300_cache_is_independent_of_its_globals_page_neighbours() {
        // The cache word 0x089cc2bc sits in the same 0x089cc2xx globals
        // cluster as the volume-controller global (0x089cc26c) and the
        // class-0x6280 cache (0x089cc30c); the crate statics keep them
        // apart.
        let guard = mock(constructed());
        unsafe {
            singleton_class_9300();
            assert!(ptr::read_volatile(ptr::addr_of!(VOLUME_CONTROLLER_INSTANCE)).is_null(), "untouched");
            assert!(ptr::read_volatile(ptr::addr_of!(CLASS_6280_INSTANCE)).is_null(), "untouched");
            assert!(ptr::read_volatile(ptr::addr_of!(STAGE_PROGRESS_TRACKER)).is_null(), "untouched");
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![0x14c]);
        }
        restore(guard);
    }
}
