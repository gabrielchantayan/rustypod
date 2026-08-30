//! Shared host-test fixtures.
//!
//! Several ported modules describe firmware objects whose pointer fields are
//! **u32 target pointers**: the port reads them with `word(..) as usize as
//! *mut u8` and dereferences the result. A host fixture backing such an
//! object must therefore live entirely below 4 GiB, or the address truncates
//! on store and the first dereference dies on SIGSEGV.
//!
//! This is a strictly stronger requirement than the one the heap slabs have
//! (`heap/pool.rs`, `heap/mod.rs`), where the only constraint is that bit 31
//! stay clear because `pool_alloc` uses it as the uncached mark. Conflating
//! the two is how `cxx/list_splice.rs`, `heap/block_mgr.rs` and
//! `heap/client_populate.rs` each shipped a bit-31 assertion that a
//! 0x1_xxxx_xxxx mapping passes happily before crashing.
//!
//! **Not every host can satisfy it.** Linux honours a low `mmap` hint. arm64
//! macOS reserves the whole low 4 GiB and refuses such a mapping even with
//! `MAP_FIXED`, so there the fixture cannot exist at all. Modules that need
//! one skip their tests on those hosts rather than crash — which is why this
//! returns an `Option` instead of asserting.

extern crate std;

/// Fixture base addresses, one per mapping site — not merely one per
/// module. [`try_map_u32_slab`] never unmaps, so two tests in the SAME
/// module that share a hint collide exactly like two modules would: the
/// second one to run finds the region occupied and skips.
///
/// These MUST be unique. A duplicate does not fail loudly — the second
/// module to map simply gets some other address, which on a 64-bit host is
/// usually above 4 GiB, so [`try_map_u32_slab`] returns `None` and that
/// module's tests quietly skip on EVERY host. That is exactly what happened
/// when `app/event_list` picked `0x0d00_0000`, already held by
/// `cxx/list_splice`: seven tests stopped running anywhere and the suite
/// still reported green.
///
/// Keep every fixture hint here rather than as a literal in the module, so
/// a collision is visible in one place instead of being invisible across
/// six files. Each region is at most 0x0100_0000 wide, so neighbours cannot
/// overlap.
pub mod hints {
    pub const HEAP_INTEGRATION: usize = 0x0900_0000;
    pub const ATA_CMD: usize = 0x0a00_0000;
    pub const CLIENT_POPULATE: usize = 0x0b00_0000;
    pub const BLOCK_MGR: usize = 0x0c00_0000;
    pub const LIST_SPLICE: usize = 0x0d00_0000;
    pub const EVENT_LIST: usize = 0x0e00_0000;
    pub const CONTEXT_SCOPE: usize = 0x0f00_0000;
    pub const BTREE_PARSE_CELL: usize = 0x1000_0000;
    pub const BTREE_DATA_SIZE: usize = 0x1100_0000;
    pub const ELEMENT_REFERENCE: usize = 0x1200_0000;
    pub const VTABLE_SET_ITERATOR: usize = 0x1300_0000;
    pub const OBSERVABLE_ARRAY: usize = 0x1400_0000;
    pub const OBSERVABLE_ARRAY_DRAIN: usize = 0x1500_0000;
    pub const EVENT_SOURCE_DESTRUCT: usize = 0x1600_0000;
    pub const SILVER_CONTROLLER: usize = 0x1700_0000;
    pub const QUEUED_MESSAGE_POST: usize = 0x1800_0000;
    pub const VTABLE_SET_ITERATOR_RELEASE: usize = 0x1900_0000;
    pub const VDBE_SERIAL_PUT: usize = 0x1a00_0000;
    pub const PENDING_EVENT_TAKE: usize = 0x1b00_0000;
    pub const ANIMATION_INIT: usize = 0x1c00_0000;
    pub const STRING_RECORD: usize = 0x1d00_0000;
    pub const IAP_PACKET_OWNER_MODE: usize = 0x1e00_0000;
    pub const TOKENIZER: usize = 0x1f00_0000;
    pub const VIEW_TIMER: usize = 0x2000_0000;
    pub const STRING_TABLE: usize = 0x2100_0000;
    // `heap/pool.rs` maps its own arena at 0x0800_0000 through a separate
    // path: it needs only bit 31 clear, not full u32 addressability.
}

/// Maps `len` bytes at `hint` and returns it only if the whole span
/// round-trips through `u32` unchanged. `None` means this host cannot place
/// the fixture below 4 GiB; callers skip rather than guess an address.
///
/// Pass a constant from [`hints`] — never a bare literal.
pub fn try_map_u32_slab(hint: usize, len: usize) -> Option<*mut u8> {
    extern "C" {
        fn mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> usize;
    }
    #[cfg(target_os = "macos")]
    const MAP_PRIVATE_ANON: i32 = 0x1002;
    #[cfg(target_os = "linux")]
    const MAP_PRIVATE_ANON: i32 = 0x22;
    const PROT_READ_WRITE: i32 = 3;

    let p = unsafe { mmap(hint, len, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0) };
    if p == usize::MAX || p == 0 || p.checked_add(len)? > 0x1_0000_0000 {
        return None;
    }
    Some(p as *mut u8)
}

/// Prints a one-line notice so a skipped fixture is never mistaken for a
/// passing test. Always returns `true`, to read as `if unavailable() {
/// return; }` at the top of a test.
pub fn note_missing_u32_fixture(module: &str) -> bool {
    extern crate std;
    std::eprintln!(
        "{module}: skipped — this host cannot map the fixture below 4 GiB \
         (u32 object pointers cannot round-trip); run these on Linux"
    );
    true
}

/// Serializes every host test that installs mocks into the crate-global
/// `drivers::ata_cmd::TRACED_ALLOC_HOOKS`. That table is one shared
/// mutable global, and `cargo test` runs test functions on parallel
/// threads, so the allocator tests in `drivers::ata_cmd` and every
/// ported caller that allocates (`sqlite::blob_to_hex`, ...) must take
/// this lock for the duration of a test rather than each keeping a
/// private one.
pub static TRACED_ALLOC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs a container vtable into
/// `app::registry::CLASS_REGISTRY`. That registry is one shared mutable
/// global whose default vtable is NULL, so any test that resolves a
/// class id through it — `app::registry`'s own container tests and every
/// ported caller of `demo_mode_instance`, such as `app::class_6800` —
/// must hold this lock rather than each keeping a private one.
pub static CLASS_REGISTRY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs a fixture root into
/// `app::context_scope::APP_ROOT_OBJECT`. That static is the crate's single
/// model of the firmware word @ 0x089ca674 and is read by both
/// `app::context_scope` and `app::scoped_context`, so a per-module lock would
/// let one module's teardown NULL the root while the other is walking it.
pub static APP_ROOT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs mocks into
/// `sqlite::cell_size::BTREE_CELL_OPS`. That dispatch static is shared by
/// `sqlite::cell_size`'s own wrapper tests and `sqlite::parse_cell`'s
/// varint-seam tests (both swap slots on it), so a per-module lock would
/// let one module's teardown restore defaults under the other's mock.
pub static BTREE_CELL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs a mock reset into
/// `cxx::pair_header::PAIR_HEADER_ELEMENT_ARRAY_OPS`. That seam is one
/// shared mutable global read by the ported `FUN_082ab398` wrapper, and
/// both `cxx::pair_header`'s own tests and `runtime::cpp_array_construct`'s
/// adapter tests swap it, so a per-module lock would let one module's
/// teardown restore defaults under the other's mock.
pub static CPP_ARRAY_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that installs a fixture block into
/// `kernel::diag_ring_record::DIAG_RING_BLOCK_GETTER`. That seam is one
/// shared mutable global pointing at the per-task diagnostic ring, and
/// the sibling ring functions still unported (reset 0x08049694, dump
/// 0x080496f0) will share it, so they must hold this lock rather than
/// each keeping a private one.
pub static DIAG_RING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps `app::view_event::VIEW_EVENT_OPS`.
/// The view-event epilogue and `app::view_timer` both invoke the unported
/// view-timer-stop wrapper through this one dispatch table.
pub static VIEW_EVENT_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps `drivers::timer::TIMER_OPS`.
/// The timer module and view-timer callers both drive the ported timer
/// helpers through this one dispatch table.
pub static TIMER_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
