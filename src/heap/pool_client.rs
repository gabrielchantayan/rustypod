//! Port of the *block-manager client base class* — the parent subobject
//! of the pool base ([`PoolBase`], heap/block_deque.rs). It owns the
//! first 0x44 bytes of the object: the vtable, the two-level client
//! ref, the recursive mutex every operation brackets, a mailbox slot, a
//! shared/private mode byte, the registration node the block manager
//! links into its client list, and the memoized client handle.
//!
//! - `pool_parent_construct` — original: `FUN_081f0050` @ 0x081f0050
//!   (80 bytes: 76 code + the vtable literal; 2 bl call sites @
//!   0x082141c0 (`pool_base_construct`) and 0x082236cc (a sibling
//!   derived class), binary-verified). Installs the parent vtable
//!   (literal 0x0898ff7c), clears the client ref, constructs the
//!   recursive mutex at +0x8 (0x082621b0), creates the +0x24 mailbox
//!   slot (`mailbox_slot_create` @ 0x0808e294, kernel/kobj.rs), writes
//!   the two mode bytes (+0x28 = 0, +0x29 = the caller's flag),
//!   constructs the registration node at +0x2c (0x081eff0c) and clears
//!   the memo words at +0x3c/+0x40. Returns `this`.
//! - `pool_client_attach` — original: `FUN_081efc8c` @ 0x081efc8c
//!   (232 bytes incl. the singleton literal; 3 bl call sites @
//!   0x08214020 (`block_deque_fill`'s gate), 0x08223530 and 0x082236ec,
//!   binary-verified). Under the base mutex: if no client handle is
//!   memoized at +0x3c, obtains one — either the process-wide singleton
//!   (mode byte +0x29 nonzero, behind the ADS static-init guard pair
//!   0x082ab31c/0x082ab338 over the .bss pair at 0x08a09704/0x08a09708)
//!   or a private one — by `operator new`-ing a 0x170-byte block and
//!   running the client constructor (0x081e6b34) on it, named through
//!   the registration node's `name_of` virtual (node vtable slot +0xc).
//!   A NULL client leaves the memo NULL and returns 0. Otherwise it
//!   points the node at the client, stamps the node's owner back at
//!   `this`, and returns the block manager's registration verdict
//!   (0x081eff38 — the real port, heap/client_register.rs — which
//!   installs the two-level ref at +0x4 that `client_handle_get`
//!   reads).
//!
//! # Deviations
//!
//! - **Vtables**: the parent vtable (literal 0x0898ff7c) and the
//!   registration node's vtable (0x089a74cc, installed by the node
//!   ctor over the base-class 0x089919a8) live in ADS
//!   runtime-initialized RW data; the decrypted image holds stale bytes
//!   whose "slots" land mid-function (spot-checked: 0x0898ff7c[0] =
//!   0x081328f8 is inside a function, 0x089a74cc[0] = 0x08105c64 is
//!   inside a jump table), and no serialized copy exists. Both are
//!   modeled as statics: [`POOL_PARENT_VTABLE`] is pointer identity
//!   only (nothing dispatches through it — every known construction
//!   path overwrites it with a derived vtable immediately), and
//!   [`CLIENT_NODE_VTABLE`] models the one slot this cluster
//!   dispatches, `name_of` (+0xc), whose default returns the node's
//!   stored name — the only reading consistent with the node ctor
//!   (0x08207674 stores the ctor's name argument at node +0x4) and
//!   with the client ctor, which `strlen`s the result. The parent
//!   vtable reuses the derived class's [`PoolBaseVtable`] type because
//!   that is the type of the field it is stored in.
//! - **Ops table** ([`POOL_CLIENT_OPS`], house pattern): the mutex ctor
//!   (0x082621b0), the node ctor (0x081eff0c), the client ctor
//!   (0x081e6b34) and the static-init guard pair
//!   (0x082ab31c/0x082ab338) are unported and dispatch indirectly. The
//!   guard defaults reproduce their originals exactly (they are five
//!   instructions between them: acquire claims a zero word and reports
//!   1, release is a bare `mov pc, lr` — ADS's single-threaded guard),
//!   and the node ctor default reproduces everything but the
//!   unrecoverable vtable pointer. The client ctor defaults to the
//!   no-block-manager answer (NULL), which is what makes
//!   `block_deque_fill`'s gate refuse without a manager. The
//!   registration call (0x081eff38) is the real port
//!   (heap/client_register.rs) — kept a slot only so host tests can
//!   observe it, like `mailbox_slot_create` and `client_alloc`; its
//!   own manager-side slot defaults to 0, so the wired defaults still
//!   refuse without a manager. `mailbox_slot_create` and
//!   `client_alloc` default to the real ports (kernel/kobj.rs,
//!   `veneers::operator_new`); they are slots only so host tests can
//!   observe them and stay out of the target-only allocation engine
//!   (the `POOL_OPS.new_control` precedent in heap/pool.rs).
//! - **Mutex**: locked/unlocked through block_region.rs's
//!   `REGION_MUTEX_OPS` — the same original pair (0x082e8390 /
//!   0x082e83d8, reached via the thunks at 0x082621a8/0x082621ac) the
//!   rest of the heap cluster brackets with.
//! - The original threads `this` through its callees' return values
//!   (`r4 = mutex_init(this + 8) - 8`, `this = node_construct(this +
//!   0x2c) - 0x2c`). Both callees return their argument unchanged, so
//!   the port keeps `this` in hand instead — re-deriving an object
//!   pointer from a literal byte offset is exactly what breaks on
//!   64-bit test hosts (the block_region.rs lesson).
//! - The singleton storage at 0x08a09704/0x08a09708 is .bss (the image
//!   holds no initializer there — verified), so the zero-initialized
//!   [`SHARED_CLIENT`] static is faithful.

use crate::heap::block_deque::{PoolBase, PoolBaseVtable};
use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::kernel::kobj::Mailbox;

/// Size of the block-manager client object (original: `mov r0, #0x170`
/// before both `operator new` calls).
const CLIENT_SIZE: usize = 0x170;

/// The registration node embedded at +0x2c: what the block manager
/// links into its client list (`client_register` hands it, together
/// with the object's client-ref slot, to 0x0818a630).
#[repr(C)]
pub struct ClientNode {
    /// +0x00 — node vtable (0x089a74cc; see the vtable deviation).
    pub vtable: *const ClientNodeVtable,
    /// +0x04 — the name the object was constructed with.
    pub name: *const u8,
    /// +0x08 — the attached client handle (`this + 0x34`).
    pub client: *mut u8,
    /// +0x0c — back-pointer to the owning object (`this + 0x38`).
    pub owner: *mut PoolBase,
}

/// The node vtable, modeled down to the one slot this cluster
/// dispatches (see the vtable deviation).
#[repr(C)]
pub struct ClientNodeVtable {
    /// Slots +0x00..+0x0c: contents unrecoverable (stale RW init data).
    pub unresolved: [usize; 3],
    /// Slot +0x0c: the node's name accessor, virtual-called by
    /// `pool_client_attach` to name a freshly constructed client.
    pub name_of: unsafe extern "C" fn(node: *mut ClientNode) -> *const u8,
}

/// Default `name_of`: the node's stored name (see the vtable
/// deviation).
unsafe extern "C" fn node_name_of(node: *mut ClientNode) -> *const u8 {
    (*node).name
}

/// The node vtable instance the node ctor installs (original literal:
/// 0x089a74cc).
pub static CLIENT_NODE_VTABLE: ClientNodeVtable = ClientNodeVtable {
    unresolved: [0; 3],
    name_of: node_name_of,
};

/// Unrecoverable parent vtable slot (see the vtable deviation): the
/// parent vtable never survives long enough to be dispatched through.
unsafe extern "C" fn missing_parent_slot(_this: *mut PoolBase) {}

/// The parent vtable instance `pool_parent_construct` installs
/// (original literal: 0x0898ff7c). Pointer identity only.
pub static POOL_PARENT_VTABLE: PoolBaseVtable = PoolBaseVtable {
    unresolved: [0; 4],
    fill_failed: missing_parent_slot,
};

/// The function-local static behind the shared block-manager client
/// (original storage: guard word @ 0x08a09704, client @ 0x08a09708 —
/// adjacent .bss words the original addresses as `guard` and
/// `guard[1]`).
#[repr(C)]
pub struct SharedClientSlot {
    /// ADS static-init guard word: bit 0 set once construction ran.
    pub guard: usize,
    /// The constructed singleton (NULL if construction failed).
    pub client: *mut u8,
}

/// Zero-initialized like the original .bss pair.
pub static mut SHARED_CLIENT: SharedClientSlot = SharedClientSlot {
    guard: 0,
    client: core::ptr::null_mut(),
};

/// Indirect dispatch table for this class's unported callees (see the
/// module-header ops deviation for each default's contract).
#[derive(Clone, Copy)]
pub struct PoolClientOps {
    /// C++ recursive mutex constructor @ 0x082621b0. Returns its
    /// argument.
    pub mutex_init: unsafe extern "C" fn(mutex: *mut u8) -> *mut u8,
    /// Mailbox slot create @ 0x0808e294 (kernel/kobj.rs, real port).
    pub mailbox_slot_create: unsafe extern "C" fn(slot: *mut *mut Mailbox),
    /// Registration node ctor @ 0x081eff0c `(node, name)`. Returns
    /// `node`.
    pub node_construct:
        unsafe extern "C" fn(node: *mut ClientNode, name: *const u8) -> *mut ClientNode,
    /// The 0x170-byte client allocation @ 0x082aadd4
    /// (`veneers::operator_new`, real port).
    pub client_alloc: unsafe extern "C" fn(size: usize) -> *mut u8,
    /// Block-manager client ctor @ 0x081e6b34 `(storage, name)`.
    /// Returns the constructed client (NULL with no block manager).
    pub client_construct:
        unsafe extern "C" fn(storage: *mut u8, name: *const u8) -> *mut u8,
    /// Client registration @ 0x081eff38 `(this)`: installs the
    /// two-level client ref at +0x4. Nonzero on success — this is
    /// `pool_client_attach`'s return value. Real port
    /// (heap/client_register.rs); a slot only so host tests can
    /// observe it.
    pub client_register: unsafe extern "C" fn(this: *mut PoolBase) -> i32,
    /// ADS static-init guard acquire @ 0x082ab31c: claims a zero guard
    /// word (setting it to 1) and reports 1; reports 0 otherwise.
    pub guard_acquire: unsafe extern "C" fn(guard: *mut usize) -> i32,
    /// ADS static-init guard release @ 0x082ab338: `mov pc, lr`.
    pub guard_release: unsafe extern "C" fn(guard: *mut usize),
}

/// Default mutex ctor: the recursive mutex body is opaque to this
/// cluster (it only ever passes the address to the lock pair, whose
/// own defaults are documented no-ops). Returns its argument, like the
/// original's closing `mov r0, r4`.
unsafe extern "C" fn stub_mutex_init(mutex: *mut u8) -> *mut u8 {
    mutex
}

/// Default node ctor: the original's whole body bar the unrecoverable
/// vtable pointer — base ctor (0x08207674) stores the name, then the
/// derived ctor installs its vtable and clears the client/owner pair.
unsafe extern "C" fn default_node_construct(
    node: *mut ClientNode,
    name: *const u8,
) -> *mut ClientNode {
    (*node).name = name;
    (*node).vtable = &CLIENT_NODE_VTABLE;
    (*node).client = core::ptr::null_mut();
    (*node).owner = core::ptr::null_mut();
    node
}

/// Default client ctor: no block manager, so nothing can be
/// constructed — the state that makes `block_deque_fill` refuse.
unsafe extern "C" fn stub_client_construct(_storage: *mut u8, _name: *const u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Default guard acquire — the original @ 0x082ab31c verbatim.
unsafe extern "C" fn guard_acquire(guard: *mut usize) -> i32 {
    if guard.read() != 0 {
        return 0;
    }
    guard.write(1);
    1
}

/// Default guard release — the original @ 0x082ab338 verbatim (ADS's
/// single-threaded guard has nothing to release).
unsafe extern "C" fn guard_release(_guard: *mut usize) {}

/// Wired defaults (real ports where they exist, documented stubs for
/// the unported block-manager machinery).
pub(crate) const DEFAULT_POOL_CLIENT_OPS: PoolClientOps = PoolClientOps {
    mutex_init: stub_mutex_init,
    mailbox_slot_create: crate::kernel::kobj::mailbox_slot_create,
    node_construct: default_node_construct,
    client_alloc: crate::heap::veneers::operator_new,
    client_construct: stub_client_construct,
    client_register: crate::heap::client_register::client_register,
    guard_acquire,
    guard_release,
};

/// The active implementation table. Written once at init on target;
/// host tests swap in recorders and restore the defaults.
pub static mut POOL_CLIENT_OPS: PoolClientOps = DEFAULT_POOL_CLIENT_OPS;

/// Reads one op (volatile — same rationale as every dispatch table).
macro_rules! op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(POOL_CLIENT_OPS.$field)) }
    };
}

/// Reads one op of the shared C++ mutex boundary (block_region.rs).
macro_rules! mutex_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) }
    };
}

/// pool_parent_construct — original: `FUN_081f0050` @ 0x081f0050
/// (80 bytes).
///
/// Constructs the block-manager client base subobject: parent vtable,
/// empty client ref, recursive mutex, mailbox slot, mode bytes,
/// registration node, cleared client memo. Returns `this`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_parent_construct(
    this: *mut PoolBase,
    name: *const u8,
    flag: usize,
) -> *mut PoolBase {
    (*this).vtable = &POOL_PARENT_VTABLE;
    (*this).client_ref = core::ptr::null();
    (op!(mutex_init))(core::ptr::addr_of_mut!((*this).mutex) as *mut u8);
    (op!(mailbox_slot_create))(core::ptr::addr_of_mut!((*this).parent_mailbox));
    (*this).parent_state = 0;
    (*this).client_shared = flag as u8;
    (op!(node_construct))(core::ptr::addr_of_mut!((*this).node), name);
    (*this).client_cache = core::ptr::null_mut();
    (*this).parent_reserved = 0;
    this
}

/// Constructs a fresh block-manager client, named through the
/// registration node's `name_of` virtual (the original's
/// `operator new(0x170)` / vtable slot +0xc / 0x081e6b34 sequence).
unsafe fn client_construct(this: *mut PoolBase) -> *mut u8 {
    let storage = (op!(client_alloc))(CLIENT_SIZE);
    let node = core::ptr::addr_of_mut!((*this).node);
    let name = ((*(*node).vtable).name_of)(node);
    (op!(client_construct))(storage, name)
}

/// The process-wide client, constructed at most once behind the ADS
/// static-init guard (a failed construction is remembered as NULL, and
/// the guard is never retried — faithful to the original).
unsafe fn shared_client(this: *mut PoolBase) -> *mut u8 {
    let slot = core::ptr::addr_of_mut!(SHARED_CLIENT);
    let guard = core::ptr::addr_of_mut!((*slot).guard);
    if guard.read() & 1 == 0 && (op!(guard_acquire))(guard) != 0 {
        (*slot).client = client_construct(this);
        (op!(guard_release))(guard);
    }
    (*slot).client
}

/// pool_client_attach — original: `FUN_081efc8c` @ 0x081efc8c
/// (232 bytes).
///
/// Memoizes a block-manager client on the object and registers it,
/// under the base mutex. Returns the registration verdict (0 when no
/// client could be obtained) — `block_deque_fill`'s gate.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pool_client_attach(this: *mut PoolBase) -> i32 {
    let mutex = core::ptr::addr_of_mut!((*this).mutex) as *mut u8;
    (mutex_op!(lock))(mutex);
    let mut result: i32 = 0;
    'attach: {
        if (*this).client_cache.is_null() {
            let client = if (*this).client_shared != 0 {
                shared_client(this)
            } else {
                client_construct(this)
            };
            (*this).client_cache = client;
            if client.is_null() {
                break 'attach;
            }
        }
        (*this).node.client = (*this).client_cache;
        (*this).node.owner = this;
        result = (op!(client_register))(this);
    }
    (mutex_op!(unlock))(mutex);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::block_deque::BlockDeque;
    use crate::heap::block_region::{RegionMutexOps, DEFAULT_REGION_MUTEX_OPS};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the global ops tables.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// One ordered event log across every mocked boundary.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ev {
        Lock(usize),
        Unlock(usize),
        MutexInit(usize),
        MboxCreate(usize),
        NodeCtor { node: usize, name: usize },
        Alloc(usize),
        NameOf(usize),
        ClientCtor { storage: usize, name: usize },
        Register(usize),
        GuardAcquire(usize),
        GuardRelease(usize),
    }

    static mut EVENTS: Vec<Ev> = Vec::new();

    fn push(ev: Ev) {
        unsafe { (*core::ptr::addr_of_mut!(EVENTS)).push(ev) }
    }

    fn events() -> Vec<Ev> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    /// The client the mock ctor hands out (NULL = construction fails).
    static mut CLIENT_RET: *mut u8 = 0x0c11_e000usize as *mut u8;
    static mut REGISTER_RET: i32 = 5;
    /// Storage the mock allocator hands out.
    static mut CLIENT_STORAGE: [u8; 16] = [0; 16];

    unsafe extern "C" fn mock_lock(m: *mut u8) -> u32 {
        push(Ev::Lock(m as usize));
        0
    }

    unsafe extern "C" fn mock_unlock(m: *mut u8) -> u32 {
        push(Ev::Unlock(m as usize));
        0
    }

    unsafe extern "C" fn mock_mutex_init(m: *mut u8) -> *mut u8 {
        push(Ev::MutexInit(m as usize));
        m
    }

    unsafe extern "C" fn mock_mbox_create(slot: *mut *mut Mailbox) {
        push(Ev::MboxCreate(slot as usize));
        *slot = 0x0b0e_0000usize as *mut Mailbox;
    }

    unsafe extern "C" fn mock_node_ctor(
        node: *mut ClientNode,
        name: *const u8,
    ) -> *mut ClientNode {
        push(Ev::NodeCtor {
            node: node as usize,
            name: name as usize,
        });
        default_node_construct(node, name)
    }

    unsafe extern "C" fn mock_alloc(size: usize) -> *mut u8 {
        push(Ev::Alloc(size));
        core::ptr::addr_of_mut!(CLIENT_STORAGE) as *mut u8
    }

    unsafe extern "C" fn mock_name_of(node: *mut ClientNode) -> *const u8 {
        push(Ev::NameOf(node as usize));
        (*node).name
    }

    static MOCK_NODE_VTABLE: ClientNodeVtable = ClientNodeVtable {
        unresolved: [0; 3],
        name_of: mock_name_of,
    };

    unsafe extern "C" fn mock_client_ctor(storage: *mut u8, name: *const u8) -> *mut u8 {
        push(Ev::ClientCtor {
            storage: storage as usize,
            name: name as usize,
        });
        CLIENT_RET
    }

    unsafe extern "C" fn mock_register(this: *mut PoolBase) -> i32 {
        push(Ev::Register(this as usize));
        REGISTER_RET
    }

    unsafe extern "C" fn mock_guard_acquire(guard: *mut usize) -> i32 {
        push(Ev::GuardAcquire(guard as usize));
        guard_acquire(guard)
    }

    unsafe extern "C" fn mock_guard_release(guard: *mut usize) {
        push(Ev::GuardRelease(guard as usize));
    }

    const MOCK_OPS: PoolClientOps = PoolClientOps {
        mutex_init: mock_mutex_init,
        mailbox_slot_create: mock_mbox_create,
        node_construct: mock_node_ctor,
        client_alloc: mock_alloc,
        client_construct: mock_client_ctor,
        client_register: mock_register,
        guard_acquire: mock_guard_acquire,
        guard_release: mock_guard_release,
    };

    /// Zeroed base object; host layout is wider than 0x7c, which is
    /// exactly the point (no field aliases another).
    fn zeroed_base() -> std::boxed::Box<PoolBase> {
        std::boxed::Box::new(unsafe { core::mem::zeroed::<PoolBase>() })
    }

    /// Installs the mocks and resets every global this module owns.
    fn setup() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            CLIENT_RET = 0x0c11_e000usize as *mut u8;
            REGISTER_RET = 5;
            core::ptr::addr_of_mut!(SHARED_CLIENT).write(SharedClientSlot {
                guard: 0,
                client: core::ptr::null_mut(),
            });
            core::ptr::addr_of_mut!(POOL_CLIENT_OPS).write(MOCK_OPS);
            core::ptr::addr_of_mut!(REGION_MUTEX_OPS).write(RegionMutexOps {
                lock: mock_lock,
                unlock: mock_unlock,
            });
        }
        guard
    }

    fn teardown() {
        unsafe {
            core::ptr::addr_of_mut!(POOL_CLIENT_OPS).write(DEFAULT_POOL_CLIENT_OPS);
            core::ptr::addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS);
            core::ptr::addr_of_mut!(SHARED_CLIENT).write(SharedClientSlot {
                guard: 0,
                client: core::ptr::null_mut(),
            });
        }
    }

    static NAME: &[u8] = b"pool_client\0";

    // ---- pool_parent_construct -----------------------------------------

    #[test]
    fn parent_construct_fills_every_field_and_returns_this() {
        let _lock = setup();
        unsafe {
            let mut base = zeroed_base();
            let this = &mut *base as *mut PoolBase;
            // Poison the memo words the ctor must clear.
            (*this).client_cache = 0xdead_beefusize as *mut u8;
            (*this).parent_reserved = 0xdead_beef;

            let ret = pool_parent_construct(this, NAME.as_ptr(), 1);

            assert_eq!(ret, this, "the ctor returns its object");
            assert_eq!((*this).vtable, &POOL_PARENT_VTABLE as *const _);
            assert!((*this).client_ref.is_null());
            assert_eq!((*this).parent_state, 0);
            assert_eq!((*this).client_shared, 1);
            assert_eq!((*this).node.name, NAME.as_ptr());
            assert_eq!((*this).node.vtable, &CLIENT_NODE_VTABLE as *const _);
            assert!((*this).node.client.is_null());
            assert!((*this).node.owner.is_null());
            assert!((*this).client_cache.is_null(), "memo cleared");
            assert_eq!((*this).parent_reserved, 0);
            assert_eq!(
                events(),
                std::vec![
                    Ev::MutexInit(core::ptr::addr_of_mut!((*this).mutex) as usize),
                    Ev::MboxCreate(core::ptr::addr_of_mut!((*this).parent_mailbox) as usize),
                    Ev::NodeCtor {
                        node: core::ptr::addr_of_mut!((*this).node) as usize,
                        name: NAME.as_ptr() as usize,
                    },
                ],
                "mutex, then mailbox, then node — the original's order"
            );
            // The mailbox slot really received the created block.
            assert_eq!((*this).parent_mailbox as usize, 0x0b0e_0000);
        }
        teardown();
    }

    #[test]
    fn parent_construct_truncates_the_mode_flag_to_a_byte() {
        let _lock = setup();
        unsafe {
            let mut base = zeroed_base();
            let this = &mut *base as *mut PoolBase;
            // Original: `mov r6, r2` then `strb r6, [r4, #0x29]`.
            pool_parent_construct(this, NAME.as_ptr(), 0x1_ff00);
            assert_eq!((*this).client_shared, 0, "low byte only");
            pool_parent_construct(this, NAME.as_ptr(), 0x1_ff02);
            assert_eq!((*this).client_shared, 2);
        }
        teardown();
    }

    #[test]
    fn parent_construct_does_not_disturb_the_derived_half() {
        let _lock = setup();
        unsafe {
            let mut base = zeroed_base();
            let this = &mut *base as *mut PoolBase;
            (*this).fill_block_count = 0x11;
            (*this).fill_cap = 0x22;
            (*this).deque.count = 0x33;
            (*this).mailbox = 0x4444usize as *mut Mailbox;

            pool_parent_construct(this, NAME.as_ptr(), 0);

            assert_eq!((*this).fill_block_count, 0x11);
            assert_eq!((*this).fill_cap, 0x22);
            assert_eq!((*this).deque.count, 0x33);
            assert_eq!((*this).mailbox as usize, 0x4444);
        }
        teardown();
    }

    // ---- pool_client_attach --------------------------------------------

    /// A constructed base object in "private client" mode.
    unsafe fn private_base() -> std::boxed::Box<PoolBase> {
        let mut base = zeroed_base();
        let this = &mut *base as *mut PoolBase;
        pool_parent_construct(this, NAME.as_ptr(), 0);
        (*this).node.vtable = &MOCK_NODE_VTABLE;
        (*core::ptr::addr_of_mut!(EVENTS)).clear();
        base
    }

    /// A constructed base object in "shared client" mode.
    unsafe fn shared_base() -> std::boxed::Box<PoolBase> {
        let mut base = zeroed_base();
        let this = &mut *base as *mut PoolBase;
        pool_parent_construct(this, NAME.as_ptr(), 1);
        (*this).node.vtable = &MOCK_NODE_VTABLE;
        (*core::ptr::addr_of_mut!(EVENTS)).clear();
        base
    }

    #[test]
    fn private_attach_creates_registers_and_returns_the_verdict() {
        let _lock = setup();
        unsafe {
            let mut base = private_base();
            let this = &mut *base as *mut PoolBase;
            let mutex = core::ptr::addr_of_mut!((*this).mutex) as usize;
            let node = core::ptr::addr_of_mut!((*this).node) as usize;

            assert_eq!(pool_client_attach(this), 5);

            assert_eq!((*this).client_cache, CLIENT_RET, "memoized");
            assert_eq!((*this).node.client, CLIENT_RET);
            assert_eq!((*this).node.owner, this, "node points back at the owner");
            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(mutex),
                    Ev::Alloc(0x170),
                    Ev::NameOf(node),
                    Ev::ClientCtor {
                        storage: core::ptr::addr_of_mut!(CLIENT_STORAGE) as usize,
                        name: NAME.as_ptr() as usize,
                    },
                    Ev::Register(this as usize),
                    Ev::Unlock(mutex),
                ],
                "private mode never touches the static-init guard"
            );
            assert!(
                SHARED_CLIENT.client.is_null() && SHARED_CLIENT.guard == 0,
                "the singleton stays untouched"
            );
        }
        teardown();
    }

    #[test]
    fn a_memoized_client_skips_construction_but_still_re_registers() {
        let _lock = setup();
        unsafe {
            let mut base = private_base();
            let this = &mut *base as *mut PoolBase;
            let mutex = core::ptr::addr_of_mut!((*this).mutex) as usize;
            assert_eq!(pool_client_attach(this), 5);
            (*core::ptr::addr_of_mut!(EVENTS)).clear();

            assert_eq!(pool_client_attach(this), 5, "second attach");

            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(mutex),
                    Ev::Register(this as usize),
                    Ev::Unlock(mutex),
                ],
                "no second allocation or construction"
            );
        }
        teardown();
    }

    #[test]
    fn a_failed_construction_returns_zero_without_registering() {
        let _lock = setup();
        unsafe {
            CLIENT_RET = core::ptr::null_mut();
            let mut base = private_base();
            let this = &mut *base as *mut PoolBase;
            let mutex = core::ptr::addr_of_mut!((*this).mutex) as usize;

            assert_eq!(pool_client_attach(this), 0);

            assert!((*this).client_cache.is_null());
            assert!((*this).node.client.is_null(), "node untouched");
            assert!((*this).node.owner.is_null());
            assert_eq!(
                *events().last().unwrap(),
                Ev::Unlock(mutex),
                "the mutex is still released on the failure path"
            );
            assert!(
                !events().contains(&Ev::Register(this as usize)),
                "registration is gated on a live client"
            );
        }
        teardown();
    }

    #[test]
    fn shared_attach_constructs_the_singleton_once_across_objects() {
        let _lock = setup();
        unsafe {
            let mut first = shared_base();
            let mut second = shared_base();
            let a = &mut *first as *mut PoolBase;
            let b = &mut *second as *mut PoolBase;
            let guard_addr = core::ptr::addr_of_mut!(SHARED_CLIENT.guard) as usize;

            assert_eq!(pool_client_attach(a), 5);
            assert_eq!(SHARED_CLIENT.client, CLIENT_RET);
            assert_eq!(SHARED_CLIENT.guard & 1, 1, "guard claimed");
            let first_events = events();
            assert!(first_events.contains(&Ev::GuardAcquire(guard_addr)));
            assert!(first_events.contains(&Ev::GuardRelease(guard_addr)));
            assert_eq!(
                first_events.iter().filter(|e| matches!(e, Ev::Alloc(_))).count(),
                1
            );
            (*core::ptr::addr_of_mut!(EVENTS)).clear();

            assert_eq!(pool_client_attach(b), 5);

            assert_eq!((*b).client_cache, CLIENT_RET, "joined the singleton");
            let second_events = events();
            assert!(
                !second_events.iter().any(|e| matches!(e, Ev::Alloc(_))),
                "the second object joins, it does not construct"
            );
            assert!(
                !second_events.contains(&Ev::GuardAcquire(guard_addr)),
                "the claimed guard word short-circuits before the call"
            );
        }
        teardown();
    }

    #[test]
    fn a_failed_singleton_is_remembered_and_never_retried() {
        let _lock = setup();
        unsafe {
            CLIENT_RET = core::ptr::null_mut();
            let mut base = shared_base();
            let this = &mut *base as *mut PoolBase;

            assert_eq!(pool_client_attach(this), 0);
            assert_eq!(SHARED_CLIENT.guard & 1, 1, "the guard is spent anyway");
            (*core::ptr::addr_of_mut!(EVENTS)).clear();

            // Even with construction now possible, the original never
            // revisits a consumed guard.
            CLIENT_RET = 0x0c11_e000usize as *mut u8;
            assert_eq!(pool_client_attach(this), 0);
            assert!(
                !events().iter().any(|e| matches!(e, Ev::Alloc(_))),
                "no retry"
            );
        }
        teardown();
    }

    #[test]
    fn the_wired_defaults_refuse_without_a_block_manager() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(POOL_CLIENT_OPS).write(DEFAULT_POOL_CLIENT_OPS);
            core::ptr::addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS);
            core::ptr::addr_of_mut!(SHARED_CLIENT).write(SharedClientSlot {
                guard: 0,
                client: core::ptr::null_mut(),
            });
            // Private mode so the default path stays off the singleton
            // (and off the real allocator's guard bookkeeping).
            let mut base = zeroed_base();
            let this = &mut *base as *mut PoolBase;
            (*this).client_shared = 0;
            (*this).node.vtable = &CLIENT_NODE_VTABLE;
            (*this).node.name = NAME.as_ptr();
            // The real `client_alloc` would reach the target-only alloc
            // engine; the stub client ctor is what decides the verdict,
            // so keep the allocation on a host buffer.
            (*core::ptr::addr_of_mut!(POOL_CLIENT_OPS)).client_alloc = mock_alloc;

            assert_eq!(pool_client_attach(this), 0, "no manager, no client");
            assert!((*this).client_cache.is_null());
        }
        teardown();
    }

    #[test]
    fn the_default_node_vtable_names_the_node() {
        unsafe {
            let mut node = ClientNode {
                vtable: &CLIENT_NODE_VTABLE,
                name: NAME.as_ptr(),
                client: core::ptr::null_mut(),
                owner: core::ptr::null_mut(),
            };
            let n = core::ptr::addr_of_mut!(node);
            assert_eq!(((*(*n).vtable).name_of)(n), NAME.as_ptr());
        }
    }

    #[test]
    fn the_default_guard_pair_matches_the_ads_originals() {
        unsafe {
            let mut g: usize = 0;
            assert_eq!(guard_acquire(&mut g), 1, "a zero guard is claimable");
            assert_eq!(g, 1, "acquire stamps the word");
            guard_release(&mut g);
            assert_eq!(g, 1, "release is a no-op");
            assert_eq!(guard_acquire(&mut g), 0, "a claimed guard refuses");
        }
    }

    /// The deque half of the object must not overlap the parent half —
    /// the whole reason the layout is expressed as typed fields.
    #[test]
    fn the_parent_and_derived_halves_are_disjoint() {
        unsafe {
            let mut base = zeroed_base();
            let this = &mut *base as *mut PoolBase;
            (*this).client_cache = 0x1111usize as *mut u8;
            (*this).node.owner = 0x2222usize as *mut PoolBase;
            (*this).fill_block_count = 0x3333;
            let dq: *mut BlockDeque = core::ptr::addr_of_mut!((*this).deque);
            (*dq).count = 0x4444;
            assert_eq!((*this).client_cache as usize, 0x1111);
            assert_eq!((*this).node.owner as usize, 0x2222);
            assert_eq!((*this).fill_block_count, 0x3333);
            assert_eq!((*dq).count, 0x4444);
        }
    }
}
