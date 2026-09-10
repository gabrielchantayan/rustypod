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
    pub const VIEW_EVENT_TIMER_STOP: usize = 0x5b00_0000;
    // 0x6000_0000 is reserved for app::view_event's localized-flag
    // fixture; mappings never unmap, so no other test may reuse it.
    pub const VIEW_EVENT_LOCALIZED_FLAGS: usize = 0x6000_0000;
    // 0x2500_0000, not the sequential 0x2200_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const IAP_THREAD_SLOT_POLL: usize = 0x2500_0000;
    pub const SCHEMA_TO_INDEX: usize = 0x2600_0000;
    // 0x2700_0000, skipping the sequential 0x2200_0000..0x2400_0000:
    // sibling ports in flight take the sequential slots, and a
    // collision skips tests silently on every host.
    pub const STRING_VIEW: usize = 0x2700_0000;
    pub const CONDVAR_WAIT_FOREVER_SIGNALED: usize = 0x2800_0000;
    pub const CONDVAR_WAIT_FOREVER_EMPTY: usize = 0x2900_0000;
    // 0x2d00_0000, skipping 0x2a00_0000..0x2c00_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const VIEW_BASE: usize = 0x2d00_0000;
    pub const SERVICE_MANAGER_SECONDARY_HANDLER: usize = 0x3600_0000;
    // 0x7b00_0000: dedicated to app/service_manager's raw-u32 slot-handler
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const SERVICE_MANAGER_SLOT_HANDLER: usize = 0x7b00_0000;
    pub const CHARACTER_CLASS: usize = 0x3700_0000;
    pub const TIMER_RESET_4000: usize = 0x3800_0000;
    // 0x3900_0000, skipping 0x2e00_0000..0x3500_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const SET_STRING: usize = 0x3900_0000;
    // 0x3a00_0000: sibling ports in flight take the sequential slots,
    // and a collision skips tests silently on every host.
    pub const KINDED_CONTROLLER: usize = 0x3a00_0000;
    // 0x3b00_0000: sibling ports in flight take the sequential slots,
    // and a collision skips tests silently on every host.
    pub const ELEMENT_REFERENCE_COOKIE: usize = 0x3b00_0000;
    // 0x3c00_0000: sibling ports in flight take the sequential slots,
    // and a collision skips tests silently on every host.
    pub const BIT_SET_TEST: usize = 0x3c00_0000;
    // 0x4100_0000, skipping 0x3d00_0000..0x4000_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const PLST_SLOT_ITEM: usize = 0x4100_0000;
    // 0x4600_0000, skipping 0x4200_0000..0x4500_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const PENDING_EVENT_INSERT: usize = 0x4600_0000;
    // 0x4a00_0000, skipping the sequential 0x4700_0000..0x4900_0000:
    // sibling ports in flight take the sequential slots, and a
    // collision skips tests silently on every host.
    pub const TAGGED_WORD_BUFFER: usize = 0x4a00_0000;
    // 0x5a00_0000, skipping 0x4b00_0000..0x5900_0000: sibling ports in
    // flight take the sequential slots, and a collision skips tests
    // silently on every host.
    pub const ELEMENT_REFERENCE_PERSISTENT_ID: usize = 0x5a00_0000;
    pub const TIMED_TRANSITION: usize = 0x5c00_0000;
    // 0x6a00_0000, far clear of the sequential run: sibling ports in
    // flight take the next free slots, and a collision skips tests
    // silently on every host.
    pub const HFS_BTREE_GET_NODE: usize = 0x6a00_0000;
    // 0x6b00_0000: dedicated to fp_misc query-object destructor tests;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const QUERY_OBJECT_DESTROY: usize = 0x6b00_0000;
    // 0x7a00_0000: dedicated to cxx/list_item_count's raw-u32 embedded
    // collection-pointer fixtures; mappings never unmap.
    pub const LIST_ITEM_COUNT: usize = 0x7a00_0000;
    // 0x7f00_0000: dedicated to cxx/bit_set's write-transition fixture;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const BIT_SET_WRITE: usize = 0x7f00_0000;
    // 0x6c00_0000, far clear of the sequential run: sibling ports in
    // flight take the next free slots, and a collision skips tests
    // silently on every host.
    pub const IAP_THREAD_SLOT_WAIT: usize = 0x6c00_0000;
    // 0x6e00_0000: dedicated to heap/word_buffer's raw-u32 singleton-reset
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const WORD_BUFFER_RESET_OPTIONAL_SINGLETON: usize = 0x6e00_0000;
    // 0x7c00_0000: dedicated to heap/word_buffer's raw-u32 assignment
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const MARKED_WORD_BUFFER_ASSIGN: usize = 0x7c00_0000;

    // 0x7e00_0000: dedicated to class-0x7f80 artwork-slot fixtures;
    // fixture mappings never unmap, so no other user may share this hint.
    pub const ARTWORK_SLOT_AVAILABILITY: usize = 0x7e00_0000;
    // 0x7100_0000: dedicated to ui/coordinate_origin's raw-u32 display
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const COORDINATE_OWNER_DISPLAY_LAYER: usize = 0x7100_0000;
    // 0x7300_0000: dedicated to crypto/bio_ctrl's raw-u32 BIO/method
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const BIO_CTRL: usize = 0x7300_0000;
    // 0x7200_0000: dedicated to crypto/bio_copy_next_retry's raw-u32 BIO
    // chain fixture; mappings never unmap, so no other user may share this
    // hint.
    pub const BIO_COPY_NEXT_RETRY: usize = 0x7200_0000;
    // 0x7400_0000: dedicated to sqlite/nested_parse's raw-u32 Parse/db
    // fixture; mappings never unmap.
    pub const SQLITE_NESTED_PARSE: usize = 0x7400_0000;
    // 0x7500_0000: dedicated to sqlite/find_table's raw-u32 sqlite3/Db
    // fixture; fixture mappings never unmap, so no other user may share
    // this hint.
    pub const SQLITE_FIND_TABLE: usize = 0x7500_0000;
    // 0x7700_0000: dedicated to sqlite/find_collation_encoding's raw-u32
    // sqlite3/default-collation fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const SQLITE_FIND_COLLATION_ENCODING: usize = 0x7700_0000;
    // 0x7600_0000: dedicated to app/resource_chain's
    // resource_chain_find_on_current_task chain fixture (the context
    // block carries the chain head as a raw u32 word); mappings never
    // unmap, so no other user may share this hint.
    pub const RESOURCE_CHAIN_ON_CURRENT_TASK: usize = 0x7600_0000;
    // 0x7800_0000: dedicated to heap/releasable_buffer's raw-u32 data
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const RELEASABLE_BUFFER: usize = 0x7800_0000;
    // 0xb400_0000: dedicated to heap/three_buffer_owner's raw-u32 data
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const THREE_BUFFER_OWNER_RELEASE: usize = 0xb400_0000;
    // 0x6d00_0000: dedicated to ui/string_view_array's derived-view
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const STRING_VIEW_ARRAY: usize = 0x6d00_0000;
    // 0x7900_0000: dedicated to ui/element_reference_item_count's raw-u32
    // reference/target/collection fixtures; mappings never unmap, so no other
    // user may share this hint.
    pub const ELEMENT_REFERENCE_ITEM_COUNT: usize = 0x7900_0000;
    // 0xa800_0000: dedicated to ui/element_reference_target_field_210's
    // raw-u32 reference/target fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const ELEMENT_REFERENCE_TARGET_FIELD_210: usize = 0xa800_0000;
    // `heap/pool.rs` maps its own arena at 0x0800_0000 through a separate
    // path: it needs only bit 31 clear, not full u32 addressability.
    // 0x8100_0000: dedicated to cxx/draw_state_surface's surface-descriptor
    // fixture (the record's +0x1c stores the surface identity as a raw u32);
    // mappings never unmap, so no other user may share this hint.
    pub const SURFACE_ATTACH: usize = 0x8100_0000;
    // 0x8200_0000: dedicated to cxx/list_cursor_index's raw-u32
    // list/cursor fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const LIST_CURSOR_INDEX: usize = 0x8200_0000;
    // 0x9e00_0000: dedicated to util/attr_record's raw-u32
    // named-attribute table fixture; mappings never unmap, so no other user
    // may share this hint.
    pub const NAMED_ATTRIBUTE_LOOKUP: usize = 0x9e00_0000;
    // 0x9f00_0000: dedicated to ui/tdat_payload's raw-u32 element, pool,
    // and payload fixture; mappings never unmap, so no other user may share it.
    pub const TDAT_PAYLOAD: usize = 0x9f00_0000;
    // 0xa900_0000: dedicated to fs/resource_reader_read_exact's raw-u32
    // file-handle fixture; mappings never unmap, so no other user may share it.
    pub const RESOURCE_READER_READ_EXACT: usize = 0xa900_0000;
    // 0xaa00_0000: dedicated to fs/resource_reader_seek_absolute's raw-u32
    // file-handle fixture; mappings never unmap, so no other user may share it.
    pub const RESOURCE_READER_SEEK_ABSOLUTE: usize = 0xaa00_0000;
    // 0xb700_0000: dedicated to app/animation timing-wheel unlink fixtures;
    // mappings never unmap, so no other user may share this hint.
    pub const TIMING_WHEEL_REMOVE: usize = 0xb700_0000;
    // 0xba00_0000: dedicated to app/progress_layout_transition's raw-u32
    // controller, timer, and activity fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const PROGRESS_LAYOUT_TRANSITION: usize = 0xba00_0000;
    // 0xbc00_0000: dedicated to app/fixed_value's refcounted-base
    // destructor fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const REFCOUNTED_BASE_DESTROY: usize = 0xbc00_0000;
    // 0xca00_0000: dedicated to app/iap_incoming_client_base's raw-u32
    // client-object and thread-context fixtures; mappings never unmap, so
    // no other user may share this hint.
    pub const IAP_INCOMING_CLIENT_BASE: usize = 0xca00_0000;
    // 0x4300_0000: dedicated to ui/current_window's raw-u32 session and
    // window fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const CURRENT_WINDOW: usize = 0x4300_0000;
    // 0xc700_0000: dedicated to sqlite/integrity_check_append_msg's
    // target-width vararg string-list fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const SQLITE_INTEGRITY_CHECK_APPEND_MSG: usize = 0xc700_0000;
    // 0xc800_0000: dedicated to app/context_scope's subject/current-context
    // predicate fixture; it carries raw-u32 scope and context links, and
    // fixture mappings never unmap, so no other user may share this hint.
    pub const CONTEXT_SCOPE_SUBJECT_MATCHES_CONTEXT_FIELD_F40: usize = 0xc800_0000;
    // 0xc900_0000: dedicated to ui/element_reference_construct_string's
    // raw-u32 reference/vtable/target fixture; mappings never unmap, so no
    // other user may share this hint.
    pub const ELEMENT_REFERENCE_CONSTRUCT_STRING: usize = 0xc900_0000;
    // 0xe600_0000: dedicated to app/strided_buffer_entry's raw-u32 table
    // and layout fixture; fixture mappings never unmap, so no other user may
    // share this hint.
    pub const STRIDED_BUFFER_ENTRY: usize = 0xe600_0000;
    // 0xe700_0000: dedicated to app/path_probe's raw-u32 counted-mutex
    // guard-destructor fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const PATH_PROBE_GUARD_DESTROY: usize = 0xe700_0000;
    // 0xe800_0000: dedicated to app/path_probe's raw-u32 interface and
    // counted-mutex constructor fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const PATH_PROBE_GUARD_CONSTRUCT: usize = 0xe800_0000;
    // 0xe900_0000: dedicated to app/timer_step_value's raw-u32 node and
    // value fixture; mappings never unmap, so no other user may share
    // this hint.
    pub const TIMER_STEP_VALUE: usize = 0xe900_0000;
    // 0xa000_0000: dedicated to util/resource_list's raw-u32 vector and
    // element fixture; mappings never unmap, so no other user may share it.
    pub const RESOURCE_LIST_DESTROY: usize = 0xa000_0000;
    // 0xdb00_0000: dedicated to app/root_context_f9c_bound's raw-u32
    // root/context fixture; mappings never unmap, so no other user may share it.
    pub const ROOT_CONTEXT_F9C_BOUND: usize = 0xdb00_0000;
    // 0xd000_0000: dedicated to app/animation's destructor fixture;
    // mappings never unmap, so no other user may share this hint.
    pub const ANIMATION_DESTROY: usize = 0xd000_0000;
    // 0x2f00_0000: dedicated to ui/plst_next's raw-u32 element and
    // chain-node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const PLST_NEXT: usize = 0x2f00_0000;
    // 0xea00_0000: dedicated to fs/block_window's raw-u32 owner/interface
    // chain fixture; mappings never unmap, so no other user may share it.
    pub const MAPPED_BLOCK_WINDOW_FINISH: usize = 0xea00_0000;
    // 0xeb00_0000: dedicated to fs/block_window's allocation-bitmap mapper
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const ALLOCATION_BITMAP_BLOCK_MAP: usize = 0xeb00_0000;
    // 0xf000_0000: dedicated to cxx/observable_array's copy-constructor
    // source/destination storage fixture; mappings never unmap, so no other
    // user may share this hint.
    pub const OBSERVABLE_ARRAY_COPY_CONSTRUCT: usize = 0xf000_0000;
    // 0xf100_0000: dedicated to app/iap_packet_event_schedule's raw-u32
    // active-context, packet, owner and pending-node fixture; mappings never
    // unmap, so no other user may share this hint.
    pub const IAP_PACKET_EVENT_SCHEDULE: usize = 0xf100_0000;
    // 0xf200_0000: dedicated to app/context_scope_selector's raw-u32
    // subject/context fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const CONTEXT_SCOPE_SELECTOR: usize = 0xf200_0000;
    // 0xd300_0000, far clear of the sequential run: sibling ports in
    // flight take the next free slots, and a collision skips tests
    // silently on every host.
    pub const PLST_SLOT_POSITION: usize = 0xd300_0000;
    // 0xf300_0000: dedicated to fs/volume_table's raw-u32 descriptor-table
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const VOLUME_TABLE_LOOKUP: usize = 0xf300_0000;
    // 0xf400_0000: dedicated to fs/drive_slot's raw-u32 drive-slot table
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const DRIVE_SLOT_LOOKUP: usize = 0xf400_0000;
    // 0xd400_0000: dedicated to codegen/expression_dependency_mask's raw-u32
    // expression-node fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const CG_EXPRESSION_DEPENDENCY_MASK: usize = 0xd400_0000;
    // 0x8400_0000: dedicated to util/fixed_matrix_cursor's raw-u32 base
    // fixture; mappings never unmap, so no other user may share this hint.
    pub const FIXED_MATRIX_CURSOR: usize = 0x8400_0000;
    // 0x9600_0000: dedicated to app/command_dispatch_name_callback's
    // raw-u32 dispatcher and command-record fixture; mappings never unmap,
    // so no other user may share this hint.
    pub const COMMAND_DISPATCH_BY_NAME_SINGLE_ARG: usize = 0x9600_0000;
    // 0xf500_0000: dedicated to app/application_string_registry's raw-u32
    // provider/registry fixture; mappings never unmap, so no other user may
    // share this hint.
    pub const APPLICATION_STRING_REGISTRY: usize = 0xf500_0000;
    // 0xf600_0000: dedicated to app/string_table's raw-u32 COW value
    // fixture for the signed-decimal getter; mappings never unmap, so no
    // other user may share this hint.
    pub const STRING_TABLE_PARSE_I32: usize = 0xf600_0000;
    // 0xb300_0000: dedicated to cxx/nested_object_value's raw-u32
    // owner/nested-object fixtures; mappings never unmap, so no other user
    // may share this hint.
    pub const NESTED_OBJECT_VALUE: usize = 0xb300_0000;
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

/// Serializes every host test that replaces
/// `util::global_state::GLOBAL_STATE_SLOT_FIND`. The global-state wrapper and
/// attribute-record lookup both install test slot finders into this one seam.
pub static GLOBAL_STATE_SLOT_FIND_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
/// Serializes every host test that swaps
/// `kernel::diag_ring_strings::DIAG_RING_STRING_OPS`. The varargs string
/// joiner owns this seam today; future callers must reuse this lock so their
/// restoration cannot race its tests.
pub static DIAG_RING_STRING_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Serializes every host test that swaps `app::view_event::VIEW_EVENT_OPS`.
/// The view-event epilogue and `app::view_timer` both invoke the unported
/// view-timer-stop wrapper through this one dispatch table.
pub static VIEW_EVENT_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps `app::string_table::STRING_TABLE_OPS`.
/// Derived view-event handlers use the real membership port through this
/// seam, so they share this lock with string-table's own tests.
pub static STRING_TABLE_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps `drivers::timer::TIMER_OPS`.
/// The timer module and view-timer callers both drive the ported timer
/// helpers through this one dispatch table.
pub static TIMER_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps `ui::string_view::STRING_VIEW_OPS`.
/// Both the base view constructor tests and derived-view constructor tests
/// replace this shared mutable table.
pub static STRING_VIEW_OPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes host tests that replace
/// `app::screen_layout::SCREEN_LAYOUT_ASSIGN_OPS`. The notification callback
/// is a shared dispatch seam, so a module-private lock would race teardown.
pub static SCREEN_LAYOUT_ASSIGN_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps
/// `cxx::string_object::STRING_OBJECT_ASSIGN_CSTR_OPS`. That seam models the
/// StringObject vtable slots +0x8/+0xc process-wide: `cxx::string_object`'s
/// own assignment tests install recorders on it, and ported callers whose
/// flow passes through `string_object_assign_payload` (e.g.
/// `app::screen_layout`'s resource-setter tests) install heap-backed slots,
/// so a module-private lock would race teardown across modules.
pub static STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes every host test that replaces `util::stream_read_be32`'s
/// stream-read-core seam. The word reader and zeroing wrapper both install
/// recorders into that mutable global.
pub static STREAM_READ_CORE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that swaps
/// `util::context_field::CURRENT_TASK_CTX_BLOCK`. That slot is one shared
/// mutable global: the accessor's own tests and the `app::resource_chain`
/// task-local front-end tests both install recording mocks into it, and
/// `cargo test` runs test functions on parallel threads, so a
/// module-private lock would race teardown across modules.
pub static TASK_CTX_BLOCK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes every host test that replaces `kernel::task::TASK_HOOKS`.
/// The task module's own tests and callers that exercise a port through
/// `current_task_ctx_block` both need to install a synthetic running node.
pub static TASK_HOOKS_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Serializes every host test that swaps
/// `app::event_code_queue::EVENT_CODE_QUEUE_HOOKS`. The queue module's own
/// tests and the `app::class_8c00` timer-rearm tests both install
/// recording enqueues into that one mutable global, so a module-private
/// lock would race teardown across modules.
pub static EVENT_CODE_QUEUE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes tests that replace the active service-handler context slot at
/// 0x089ccb5c. The readiness gate and iAP packet event scheduler share it.
pub static ACTIVE_SERVICE_HANDLER_CONTEXT_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes tests that replace `app::pending_event_insert`'s shared ops
/// table. The queue port and packet-event caller both install host models.
pub static PENDING_EVENT_INSERT_OPS_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes every host test that replaces the shared unported
/// `FUN_081d7f14` completion-dispatch table. The packet-event scheduler and
/// packet-completion port install models into this one mutable global.
pub static IAP_PACKET_EVENT_SCHEDULE_OPS_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Serializes host tests that mutate the shared timing-wheel bucket array
/// behind `app::animation::scheduler_table`. The animation and refcounted
/// base-destruction ports both unlink nodes through this one host model.
pub static SCHEDULER_TABLE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
