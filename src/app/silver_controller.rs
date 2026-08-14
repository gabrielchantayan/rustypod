//! `silver_controller` — the constructor @ 0x08134db4 of the retailOS
//! controller object whose two accessors `app/template_binding` already
//! ports.
//!
//! The identification is not a guess: this constructor writes the very
//! two members that module documents. Its base call reaches
//! `string_object_construct_from_cstr` @ 0x08277304 on `this + 0x28`
//! (`template_binding::NAME_OFFSET`, the embedded name string), and its
//! second inline container construction targets `this + 0x94`
//! (`template_binding::BINDING_MAP_OFFSET`, the name-keyed binding map
//! whose header word the validation walk @ 0x08134938 loads as
//! `this + 0xa4`). Same class, same block of the image
//! (0x08134600..0x08134d00 is the framework's observable base).
//!
//! # Extent, from the raw bytes
//!
//! Decoded with `arm-none-eabi-objdump` over `work/firmware/osos.dec` at
//! load base 0x08000000, not taken from Ghidra:
//!
//! ```text
//! 08134db0  b   0x0810e2a0          @ tail of the previous function
//! 08134db4  push {r2, r3, r4, r5, r6, lr}   @ <- this function starts
//!   ...
//! 08134e78  pop {r2, r3, r4, r5, r6, pc}
//! 08134e7c  .word 0x08984570        @ its literal pool: the vtable
//! 08134e80  cmp r0, #0              @ the next function starts here
//! ```
//!
//! So the extent is 0x08134db4..0x08134e80 = **204 bytes**: 50
//! instructions plus the one pool word, which `ldr r1, [pc, #184]` @
//! 0x08134dbc reaches. Verified counts, from decoding every B/BL word in
//! the 10 597 864-byte image: **92 `bl` sites and 1 plain-`b` tail call**
//! (a derived constructor chaining into this one), no predicated
//! branches, and **0 occurrences of 0x08134db4 as a data word** — it is
//! never reached through a vtable, which is what a statically bound
//! constructor looks like.
//!
//! # The second argument Ghidra drops
//!
//! Nothing in the body writes `r1` before `bl 0x0810e2e4`, so the
//! caller's `r1` flows straight into the base constructor, which starts
//! `mov r6, r1` and hands `r6` to `string_object_construct_from_cstr` @
//! 0x08277304 (already ported) for the name string at `this + 0x28`.
//! The signature is therefore `(this, name)`, two arguments. `r2`/`r3`
//! are *not* arguments: `push {r2, r3, ...}` is the ADS idiom for
//! carving eight bytes of stack scratch, and both pushed words are
//! overwritten (`str r5, [sp, #4]`, `str r5, [sp]`) before anything
//! reads them.
//!
//! # Algorithm
//!
//! 1. `base = construct_base(this, name)` @ 0x0810e2e4 — the framework
//!    base that builds the name string at +0x28 plus two more embedded
//!    strings at +0x30/+0x38. Its return value is what every later store
//!    uses, so the port threads it through instead of reusing `this`.
//! 2. Overwrite the base's vtable word at +0x00 with
//!    [`VTABLE_ADDRESS`].
//! 3. Inline-construct the auxiliary container at +0x78
//!    ([`AUXILIARY_MAP_OFFSET`]) and then the binding map at +0x94
//!    ([`template_binding::BINDING_MAP_OFFSET`]). ADS inlined both
//!    constructors, which is why 26 of the 50 instructions are member
//!    stores; see [`construct_container`].
//! 4. `install_demo_mode(base, demo_mode_instance())` @ 0x0810de38 —
//!    four instructions that store the singleton into `this + 0x44` and
//!    tail-dispatch vtable slot +0x2c. `demo_mode_instance` @
//!    0x081883fc is ported, so it is called directly.
//! 5. Return `base`, the ADS constructor convention.
//!
//! # The embedded containers
//!
//! Each is 28 bytes ([`CONTAINER_SIZE`]) and is an ADS C++ node
//! container with an *inline node pool*, the same shape
//! `app/event_list` documents for the event tree: pool-chunk list at
//! +0x00, recycled-node list at +0x04, bump cursor at +0x08, bump limit
//! at +0x0c, header/sentinel node at +0x10, live-node count at +0x14 and
//! two trailing flag bytes at +0x18/+0x19. The proof that they are 28
//! bytes apart rather than merely adjacent is the sibling constructor @
//! 0x081cdab4, which builds the identical pair at +0x0c and +0x28
//! through the *same two* node allocators, 0x1c apart.
//!
//! The two allocators differ (0x083c4d30 for the auxiliary container,
//! 0x083c14c8 for the binding map), so the two element types differ;
//! only the binding map's is known. The walk @ 0x08134938 shows it is a
//! red-black tree whose every node carries an inner vector at node+0x14.
//!
//! # Deviations
//!
//! - The pool word 0x08984570 is a *vtable address in the loaded image*,
//!   not a file offset: the decrypted `osos.dec` holds unrelated table
//!   bytes there, exactly the caveat `app/registry` records for
//!   `demo_mode_instance`'s own vtable 0x08989718 ("that one page of the
//!   image does not match what the device runs"). The port keeps it as
//!   the constant [`VTABLE_ADDRESS`] and stores it verbatim; it does not
//!   claim to know its contents.
//! - The four unported callees go through the [`SILVER_CONTROLLER_OPS`]
//!   `read_volatile` seam (house pattern — see
//!   `cxx/string_object`'s `STRING_OBJECT_ASSIGN_CSTR_OPS`).
//!   `demo_mode_instance` is ported and is called directly.
//! - The original materializes the two zero flag bytes through the stack
//!   scratch (`str r5, [sp, #4]` / `ldrb r0, [sp, #4]` / `strb r0, [r4,
//!   #0x19]`); both are demonstrably zero, so the port stores zero
//!   directly and keeps no scratch frame.
//! - **NOT HOOK-READY.** The default `allocate_*_header` boundary
//!   returns NULL, and the original stores through the allocator's
//!   result without a guard — so does the port. Branching stock code
//!   here before 0x083c4d30 / 0x083c14c8 are ported would fault.
//! - Container pointers are 32-bit target pointers written with aligned
//!   `u32` stores, so host fixtures must sit below 4 GiB
//!   (`crate::testing::try_map_u32_slab`).

use crate::app::registry::demo_mode_instance;
use crate::app::template_binding::BINDING_MAP_OFFSET;

/// The vtable this constructor installs at +0x00 (the literal pool word
/// @ 0x08134e7c, binary-verified against `osos.dec`). See the module
/// header: this is a loaded-image address, and the decrypted file holds
/// something else at it.
pub const VTABLE_ADDRESS: u32 = 0x0898_4570;

/// Byte offset of the controller's auxiliary embedded container — the
/// original's `add r4, r0, #120` @ 0x08134ddc. Element type
/// unidentified; its node allocator (0x083c4d30) differs from the
/// binding map's, so it is a different instantiation.
pub const AUXILIARY_MAP_OFFSET: usize = 0x78;

/// Byte offset of the member `install_demo_mode` @ 0x0810de38 writes
/// (`str r1, [r0, #68]`). The base constructor zeroes it first.
pub const DEMO_MODE_OFFSET: usize = 0x44;

/// Size of one embedded container, from the 0x94 - 0x78 spacing here and
/// the 0x28 - 0x0c spacing of the sibling constructor @ 0x081cdab4.
pub const CONTAINER_SIZE: usize = 0x1c;

/// Head of the container's own node-pool chunk list.
pub const CONTAINER_POOL_CHUNKS_OFFSET: usize = 0x00;
/// Recycled-node free list.
pub const CONTAINER_FREE_LIST_OFFSET: usize = 0x04;
/// Bump-allocation cursor into the current pool chunk.
pub const CONTAINER_CURSOR_OFFSET: usize = 0x08;
/// Bump-allocation limit of the current pool chunk.
pub const CONTAINER_LIMIT_OFFSET: usize = 0x0c;
/// The container's header/sentinel node — its `end()` iterator.
pub const CONTAINER_HEADER_OFFSET: usize = 0x10;
/// Live-node count.
pub const CONTAINER_NODE_COUNT_OFFSET: usize = 0x14;
/// The two trailing flag bytes, at +0x18 and +0x19.
pub const CONTAINER_FLAGS_OFFSET: usize = 0x18;

/// Header-node links, the ordinary `_Rb_tree_node_base` layout that
/// `app/event_list` records: parent/root at +0x04, left at +0x08, right
/// at +0x0c. An empty container has parent NULL and both links pointing
/// at the header itself.
pub const NODE_PARENT_OFFSET: usize = 0x04;
pub const NODE_LEFT_OFFSET: usize = 0x08;
pub const NODE_RIGHT_OFFSET: usize = 0x0c;

/// Writes one word of the opaque target layout. Object pointers are
/// 32-bit on the device, so host fixtures backing them must sit below
/// 4 GiB (`crate::testing::try_map_u32_slab`).
#[inline(always)]
unsafe fn write_word(at: *mut u8, value: u32) {
    unsafe { at.cast::<u32>().write(value) }
}

/// Reads one word of the opaque target layout.
#[inline(always)]
unsafe fn read_word(at: *const u8) -> u32 {
    unsafe { at.cast::<u32>().read() }
}

/// The four callees of [`silver_controller_construct`] that have no port
/// yet.
#[derive(Clone, Copy)]
pub struct SilverControllerOps {
    /// Original 0x0810e2e4: the framework base constructor. Builds the
    /// name string at `this + 0x28` from `name` plus two ROM-string
    /// members at +0x30/+0x38, installs its own vtable, and returns
    /// `this`.
    pub construct_base: unsafe extern "C" fn(this: *mut u8, name: *const u8) -> *mut u8,
    /// Original 0x083c4d30: pop or bump-allocate the header node of the
    /// auxiliary container at [`AUXILIARY_MAP_OFFSET`].
    pub allocate_auxiliary_header: unsafe extern "C" fn(container: *mut u8) -> *mut u8,
    /// Original 0x083c14c8: the same for the binding map — the allocator
    /// `app/event_source` already names for the event tree at +0x38 of
    /// its own object.
    pub allocate_binding_header: unsafe extern "C" fn(container: *mut u8) -> *mut u8,
    /// Original 0x0810de38: `this->demo_mode = demo_mode; return
    /// this->vtable[0x2c](this, demo_mode);` — a four-instruction store
    /// plus tail dispatch, called from nowhere else in the image.
    pub install_demo_mode: unsafe extern "C" fn(this: *mut u8, demo_mode: *mut u8),
}

/// Default boundary before 0x0810e2e4 is ported: the original returns
/// `this`, and the name string it would build is not something a stub
/// can stand in for.
unsafe extern "C" fn missing_construct_base(this: *mut u8, _name: *const u8) -> *mut u8 {
    this
}

/// Default boundary before 0x083c4d30 is ported. NULL, not a shared
/// static node: two containers may not alias one header, and the
/// original's allocator never fails.
unsafe extern "C" fn missing_allocate_auxiliary_header(_container: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Default boundary before 0x083c14c8 is ported. See
/// [`missing_allocate_auxiliary_header`]; the two allocators are
/// distinct functions, so they get distinct stubs.
unsafe extern "C" fn missing_allocate_binding_header(_container: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Default boundary before 0x0810de38 is ported. Its store is
/// reproducible, but its vtable tail dispatch is not, so the whole call
/// stays behind the seam and the default does nothing.
unsafe extern "C" fn missing_install_demo_mode(_this: *mut u8, _demo_mode: *mut u8) {}

/// Wired defaults for [`SILVER_CONTROLLER_OPS`].
pub const DEFAULT_SILVER_CONTROLLER_OPS: SilverControllerOps = SilverControllerOps {
    construct_base: missing_construct_base,
    allocate_auxiliary_header: missing_allocate_auxiliary_header,
    allocate_binding_header: missing_allocate_binding_header,
    install_demo_mode: missing_install_demo_mode,
};

/// Active model of the constructor's unported callees. A later port of
/// any one of them replaces its default without changing this caller.
pub static mut SILVER_CONTROLLER_OPS: SilverControllerOps = DEFAULT_SILVER_CONTROLLER_OPS;

#[inline(always)]
unsafe fn ops() -> SilverControllerOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SILVER_CONTROLLER_OPS)) }
}

/// Default-constructs one 28-byte embedded container in place: clear the
/// inline node pool, the header slot, the count and the two flag bytes,
/// then allocate the header node and close it into an empty circle
/// (`parent = NULL`, `left = right = header`).
///
/// The source keeps the original's two reloads of the header slot
/// between the three node stores (`ldr r0, [r4, #16]` @ 0x08134e08 and
/// 0x08134e10 — the same address, with no intervening store). LLVM
/// common-subexpression-eliminates the second of them, which is why
/// match.py shows one `ldr` where the original has two.
///
/// # Safety
///
/// `container` must point at [`CONTAINER_SIZE`] writable bytes, and
/// `allocate_header` must return a node of at least 16 writable bytes
/// addressable as a `u32`.
#[inline(always)]
unsafe fn construct_container(
    container: *mut u8,
    allocate_header: unsafe extern "C" fn(*mut u8) -> *mut u8,
) {
    unsafe {
        write_word(container.add(CONTAINER_POOL_CHUNKS_OFFSET), 0);
        write_word(container.add(CONTAINER_HEADER_OFFSET), 0);
        write_word(container.add(CONTAINER_NODE_COUNT_OFFSET), 0);
        container.add(CONTAINER_FLAGS_OFFSET).write(0);
        container.add(CONTAINER_FLAGS_OFFSET + 1).write(0);
        write_word(container.add(CONTAINER_LIMIT_OFFSET), 0);
        write_word(container.add(CONTAINER_CURSOR_OFFSET), 0);
        write_word(container.add(CONTAINER_FREE_LIST_OFFSET), 0);

        let header = allocate_header(container);
        write_word(container.add(CONTAINER_HEADER_OFFSET), header as u32);
        write_word(header.add(NODE_PARENT_OFFSET), 0);
        let header = read_word(container.add(CONTAINER_HEADER_OFFSET)) as *mut u8;
        write_word(header.add(NODE_LEFT_OFFSET), header as u32);
        let header = read_word(container.add(CONTAINER_HEADER_OFFSET)) as *mut u8;
        write_word(header.add(NODE_RIGHT_OFFSET), header as u32);
    }
}

/// silver_controller_construct — original: `FUN_08134db4` @ 0x08134db4
/// (204 bytes: 50 instructions plus one literal-pool word; **92 `bl`
/// sites and 1 plain-`b` tail call**, binary-scanned over `osos.dec`).
///
/// Constructs the retailOS controller object named by `name`: run the
/// framework base constructor, install this class's vtable,
/// default-construct the auxiliary container at +0x78 and the
/// name-keyed binding map at +0x94, then hand the object the
/// `TCDemoMode` singleton. Returns the object, as ADS constructors do.
///
/// No NULL guard on either argument — the original has none.
///
/// # Safety
///
/// `this` must point at a writable allocation of at least
/// `AUXILIARY_MAP_OFFSET.max(BINDING_MAP_OFFSET) + CONTAINER_SIZE`
/// bytes laid out as this class, and `name` must satisfy whatever the
/// installed [`SilverControllerOps::construct_base`] requires (the
/// firmware's reads it as a NUL-terminated C string).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn silver_controller_construct(this: *mut u8, name: *const u8) -> *mut u8 {
    unsafe {
        let ops = ops();
        let this = (ops.construct_base)(this, name);
        write_word(this, VTABLE_ADDRESS);
        construct_container(this.add(AUXILIARY_MAP_OFFSET), ops.allocate_auxiliary_header);
        construct_container(this.add(BINDING_MAP_OFFSET), ops.allocate_binding_header);
        (ops.install_demo_mode)(this, demo_mode_instance());
        this
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec::Vec;

    /// Whole object plus the two header nodes the allocators hand out.
    const FIXTURE_LEN: usize = 0x1000;
    const OBJECT_OFFSET: usize = 0x000;
    const OBJECT_LEN: usize = 0x100;
    const AUXILIARY_NODE_OFFSET: usize = 0x200;
    const BINDING_NODE_OFFSET: usize = 0x300;
    const NODE_LEN: usize = 0x20;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(crate::testing::hints::SILVER_CONTROLLER, FIXTURE_LEN).map(|p| p as usize)
    });

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    static mut BASE_CALLS: Vec<(*mut u8, *const u8)> = Vec::new();
    static mut ALLOCATOR_CALLS: Vec<(u32, *mut u8)> = Vec::new();
    static mut INSTALL_CALLS: Vec<(*mut u8, *mut u8)> = Vec::new();
    static mut AUXILIARY_NODE: *mut u8 = core::ptr::null_mut();
    static mut BINDING_NODE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_base(this: *mut u8, name: *const u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(BASE_CALLS)).push((this, name));
        this
    }

    unsafe extern "C" fn recording_auxiliary_allocator(container: *mut u8) -> *mut u8 {
        // Ordering evidence: the base runs before any container does.
        assert_eq!((*core::ptr::addr_of!(BASE_CALLS)).len(), 1);
        (*core::ptr::addr_of_mut!(ALLOCATOR_CALLS)).push((0, container));
        core::ptr::addr_of!(AUXILIARY_NODE).read()
    }

    unsafe extern "C" fn recording_binding_allocator(container: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(ALLOCATOR_CALLS)).push((1, container));
        core::ptr::addr_of!(BINDING_NODE).read()
    }

    unsafe extern "C" fn recording_install(this: *mut u8, demo_mode: *mut u8) {
        // Ordering evidence: both containers exist before the install.
        assert_eq!((*core::ptr::addr_of!(ALLOCATOR_CALLS)).len(), 2);
        (*core::ptr::addr_of_mut!(INSTALL_CALLS)).push((this, demo_mode));
    }

    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(SILVER_CONTROLLER_OPS)
                    .write_volatile(DEFAULT_SILVER_CONTROLLER_OPS);
            }
        }
    }

    /// Installs the recording boundary over a freshly poisoned slab and
    /// returns `(object, auxiliary_node, binding_node)`.
    fn bench() -> (OpsGuard, *mut u8, *mut u8, *mut u8) {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let slab = SLAB.expect("caller checked the fixture") as *mut u8;
        let object = unsafe { slab.add(OBJECT_OFFSET) };
        let auxiliary_node = unsafe { slab.add(AUXILIARY_NODE_OFFSET) };
        let binding_node = unsafe { slab.add(BINDING_NODE_OFFSET) };
        unsafe {
            core::ptr::write_bytes(slab, 0xa5, FIXTURE_LEN);
            (*core::ptr::addr_of_mut!(BASE_CALLS)).clear();
            (*core::ptr::addr_of_mut!(ALLOCATOR_CALLS)).clear();
            (*core::ptr::addr_of_mut!(INSTALL_CALLS)).clear();
            core::ptr::addr_of_mut!(AUXILIARY_NODE).write(auxiliary_node);
            core::ptr::addr_of_mut!(BINDING_NODE).write(binding_node);
            core::ptr::addr_of_mut!(SILVER_CONTROLLER_OPS).write_volatile(SilverControllerOps {
                construct_base: recording_base,
                allocate_auxiliary_header: recording_auxiliary_allocator,
                allocate_binding_header: recording_binding_allocator,
                install_demo_mode: recording_install,
            });
        }
        (OpsGuard { _lock: lock }, object, auxiliary_node, binding_node)
    }

    unsafe fn word_at(object: *const u8, offset: usize) -> u32 {
        unsafe { read_word(object.add(offset)) }
    }

    fn assert_empty_container(container: *const u8, header: *mut u8) {
        unsafe {
            assert_eq!(word_at(container, CONTAINER_POOL_CHUNKS_OFFSET), 0);
            assert_eq!(word_at(container, CONTAINER_FREE_LIST_OFFSET), 0);
            assert_eq!(word_at(container, CONTAINER_CURSOR_OFFSET), 0);
            assert_eq!(word_at(container, CONTAINER_LIMIT_OFFSET), 0);
            assert_eq!(word_at(container, CONTAINER_HEADER_OFFSET), header as u32);
            assert_eq!(word_at(container, CONTAINER_NODE_COUNT_OFFSET), 0);
            assert_eq!(container.add(CONTAINER_FLAGS_OFFSET).read(), 0);
            assert_eq!(container.add(CONTAINER_FLAGS_OFFSET + 1).read(), 0);

            assert_eq!(word_at(header, NODE_PARENT_OFFSET), 0);
            assert_eq!(word_at(header, NODE_LEFT_OFFSET), header as u32);
            assert_eq!(word_at(header, NODE_RIGHT_OFFSET), header as u32);
        }
    }

    #[test]
    fn the_layout_constants_match_the_original_offsets() {
        assert_eq!(AUXILIARY_MAP_OFFSET, 0x78);
        assert_eq!(BINDING_MAP_OFFSET, 0x94);
        assert_eq!(BINDING_MAP_OFFSET - AUXILIARY_MAP_OFFSET, CONTAINER_SIZE);
        assert_eq!(DEMO_MODE_OFFSET, 0x44);
        assert_eq!(VTABLE_ADDRESS, 0x0898_4570);
    }

    #[test]
    fn both_containers_are_constructed_empty_and_the_vtable_is_installed() {
        if SLAB.is_none() && note_missing_u32_fixture("app::silver_controller") {
            return;
        }
        let (_guard, object, auxiliary_node, binding_node) = bench();

        let returned = unsafe { silver_controller_construct(object, b"TCClock\0".as_ptr()) };

        assert_eq!(returned, object);
        unsafe {
            assert_eq!(word_at(object, 0), VTABLE_ADDRESS);
            assert_eq!(
                (&(*core::ptr::addr_of!(ALLOCATOR_CALLS)))[..],
                [
                    (0, object.add(AUXILIARY_MAP_OFFSET)),
                    (1, object.add(BINDING_MAP_OFFSET)),
                ]
            );
        }
        assert_empty_container(unsafe { object.add(AUXILIARY_MAP_OFFSET) }, auxiliary_node);
        assert_empty_container(unsafe { object.add(BINDING_MAP_OFFSET) }, binding_node);
    }

    #[test]
    fn the_name_reaches_the_base_constructor_untouched() {
        if SLAB.is_none() && note_missing_u32_fixture("app::silver_controller") {
            return;
        }
        let (_guard, object, _, _) = bench();
        let name = b"TCVoiceMemos\0".as_ptr();

        unsafe { silver_controller_construct(object, name) };

        unsafe {
            assert_eq!((&(*core::ptr::addr_of!(BASE_CALLS)))[..], [(object, name)]);
        }
    }

    /// The original threads the base constructor's *return value* into
    /// every later store, so a base that relocates `this` must move the
    /// whole construction with it.
    #[test]
    fn the_base_constructors_return_value_is_what_gets_constructed() {
        if SLAB.is_none() && note_missing_u32_fixture("app::silver_controller") {
            return;
        }
        unsafe extern "C" fn relocating_base(this: *mut u8, _name: *const u8) -> *mut u8 {
            unsafe { this.add(OBJECT_LEN) }
        }
        let (_guard, object, _, _) = bench();
        unsafe {
            let mut ops = ops();
            ops.construct_base = relocating_base;
            core::ptr::addr_of_mut!(SILVER_CONTROLLER_OPS).write_volatile(ops);
        }

        let returned = unsafe { silver_controller_construct(object, core::ptr::null()) };

        unsafe {
            assert_eq!(returned, object.add(OBJECT_LEN));
            assert_eq!(word_at(returned, 0), VTABLE_ADDRESS);
            assert_eq!(word_at(object, 0), 0xa5a5_a5a5, "the original stays poison");
            assert_eq!(
                (&(*core::ptr::addr_of!(INSTALL_CALLS)))[0].0,
                returned,
                "the demo-mode install sees the relocated object too"
            );
        }
    }

    #[test]
    fn the_demo_mode_singleton_is_installed_last() {
        if SLAB.is_none() && note_missing_u32_fixture("app::silver_controller") {
            return;
        }
        let (_guard, object, _, _) = bench();

        unsafe { silver_controller_construct(object, core::ptr::null()) };

        unsafe {
            assert_eq!(
                (&(*core::ptr::addr_of!(INSTALL_CALLS)))[..],
                [(object, demo_mode_instance())]
            );
        }
    }

    #[test]
    fn no_byte_outside_the_two_containers_and_the_vtable_is_written() {
        if SLAB.is_none() && note_missing_u32_fixture("app::silver_controller") {
            return;
        }
        let (_guard, object, _, _) = bench();

        unsafe { silver_controller_construct(object, core::ptr::null()) };

        for offset in 4..OBJECT_LEN {
            let touched = (AUXILIARY_MAP_OFFSET..AUXILIARY_MAP_OFFSET + CONTAINER_SIZE)
                .contains(&offset)
                || (BINDING_MAP_OFFSET..BINDING_MAP_OFFSET + CONTAINER_SIZE).contains(&offset);
            if touched {
                continue;
            }
            assert_eq!(
                unsafe { object.add(offset).read() },
                0xa5,
                "the constructor wrote +{offset:#x}, which it must leave to the base"
            );
        }
        // In particular +0x44: the base zeroes it and only the seam's
        // install writes it, which the default and the mock both skip.
        assert_eq!(unsafe { object.add(DEMO_MODE_OFFSET).read() }, 0xa5);
    }

    /// Only the sixteen bytes the header-node initialization names are
    /// written; the allocator owns the rest of the node.
    #[test]
    fn the_header_node_is_closed_into_an_empty_circle_and_nothing_more() {
        if SLAB.is_none() && note_missing_u32_fixture("app::silver_controller") {
            return;
        }
        let (_guard, object, auxiliary_node, _) = bench();

        unsafe { silver_controller_construct(object, core::ptr::null()) };

        unsafe {
            assert_eq!(word_at(auxiliary_node, 0), 0xa5a5_a5a5, "+0 is untouched");
            for offset in (0x10..NODE_LEN).step_by(4) {
                assert_eq!(word_at(auxiliary_node, offset), 0xa5a5_a5a5, "+{offset:#x}");
            }
        }
    }

    #[test]
    fn the_default_boundary_hands_out_no_header_node() {
        let ops = DEFAULT_SILVER_CONTROLLER_OPS;
        let mut object = std::vec![0u8; OBJECT_LEN];
        let this = object.as_mut_ptr();

        unsafe {
            assert_eq!((ops.construct_base)(this, core::ptr::null()), this);
            assert!((ops.allocate_auxiliary_header)(this).is_null());
            assert!((ops.allocate_binding_header)(this).is_null());
            (ops.install_demo_mode)(this, core::ptr::null_mut());
        }
        assert!(object.iter().all(|&byte| byte == 0));
    }
}
