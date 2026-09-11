//! `stream_write_owner_construct` — original: `FUN_081f542c` @ 0x081f542c.
//!
//! # Extent and reachability, binary-verified
//!
//! Ghidra reports 48 bytes, which is the twelve-word instruction body from
//! 0x081f542c through 0x081f5458. Raw `osos.dec` decoding shows its
//! literal-pool vtable word at 0x081f545c is also part of the function, so
//! its true size is **52 bytes**. The next separately linked function starts
//! at 0x081f5460 (`cmp r0, #0`). Decoding every ARM B/BL immediate in
//! `osos.dec` finds exactly nine inbound calls, all unconditional `bl`:
//! 0x0805e730, 0x080f672c, 0x08121558, 0x0816156c, 0x081c7f48, 0x081e3210,
//! 0x082828d4, 0x08282f50, and 0x08295844. There are no predicated forms,
//! tail-branch calls, or aligned data-word references to this entry.
//!
//! # Algorithm
//!
//! Construct a stream-write owner: install vtable 0x0899020c, copy the

//! NUL-terminated `name` into its inline 256-byte storage at +12, store
//! `buffer_capacity` at +0x10c, clear the stream word at +8 and state word
//! at +4, then return `owner`. The fourth ABI input is not read. The ARM body
//! has no null, bounds, or alignment guards. Deliberate deviations: none.
type StringCopy = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;

/// Immutable function address, read volatily to preserve the retailOS
/// constructor's separate `strcpy` call rather than inlining its body.
static STRING_COPY: StringCopy = crate::libc::strcpy::strcpy;

#[inline(always)]
fn string_copy() -> StringCopy {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STRING_COPY)) }
}

/// Static vtable installed by the constructor.
pub const STREAM_WRITE_OWNER_VTABLE_ADDRESS: u32 = 0x0899_020c;

/// Prefix whose fields this constructor initializes on the 32-bit target.
///
/// The complete allocated object is 0x114 bytes, but the final word is not
/// touched by this constructor and is therefore deliberately not modeled.
#[repr(C)]
pub struct StreamWriteOwnerPrefix {
    vtable: u32,
    state: u32,
    stream: u32,
    name: [u8; 0x100],
    buffer_capacity: u32,
}

const _: [u8; 0x000] = [0; core::mem::offset_of!(StreamWriteOwnerPrefix, vtable)];
const _: [u8; 0x004] = [0; core::mem::offset_of!(StreamWriteOwnerPrefix, state)];
const _: [u8; 0x008] = [0; core::mem::offset_of!(StreamWriteOwnerPrefix, stream)];
const _: [u8; 0x00c] = [0; core::mem::offset_of!(StreamWriteOwnerPrefix, name)];
const _: [u8; 0x10c] = [0; core::mem::offset_of!(StreamWriteOwnerPrefix, buffer_capacity)];
const _: [u8; 0x110] = [0; core::mem::size_of::<StreamWriteOwnerPrefix>()];

/// Constructs the initialized stream-write-owner prefix and returns `owner`.
///
/// # Safety
///
/// `owner` must point to at least 0x110 writable, four-byte-aligned bytes;
/// `name` must point to a readable NUL-terminated string whose copy fits the
/// 256-byte inline name storage. The original has no guards for either
/// requirement. `ignored_input` is accepted to preserve the original four-
/// register ABI but is deliberately not read.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_write_owner_construct")]
#[inline(never)]
pub unsafe extern "C" fn stream_write_owner_construct(
    owner: *mut StreamWriteOwnerPrefix,
    name: *const u8,
    buffer_capacity: u32,
    _ignored_input: u32,
) -> *mut StreamWriteOwnerPrefix {
    unsafe {
        core::ptr::addr_of_mut!((*owner).vtable).write_volatile(STREAM_WRITE_OWNER_VTABLE_ADDRESS);
        string_copy()(core::ptr::addr_of_mut!((*owner).name).cast(), name);
        core::ptr::addr_of_mut!((*owner).buffer_capacity).write_volatile(buffer_capacity);
        core::ptr::addr_of_mut!((*owner).stream).write_volatile(0);
        core::ptr::addr_of_mut!((*owner).state).write_volatile(0);
    }
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(C)]
    struct OwnerWithUntouchedTail {
        owner: StreamWriteOwnerPrefix,
        tail: u32,
    }

    fn owner_with_bytes(byte: u8) -> OwnerWithUntouchedTail {
        OwnerWithUntouchedTail {
            owner: StreamWriteOwnerPrefix {
                vtable: 0xdead_beef,
                state: 0x1111_2222,
                stream: 0x3333_4444,
                name: [byte; 0x100],
                buffer_capacity: 0x5555_6666,
            },
            tail: 0x7777_8888,
        }
    }

    #[test]
    fn installs_fields_copies_name_and_returns_owner() {
        let mut storage = owner_with_bytes(0xa5);
        let owner = &mut storage.owner as *mut StreamWriteOwnerPrefix;
        let name = b"iTunesDB writer\0";

        let returned = unsafe { stream_write_owner_construct(owner, name.as_ptr(), 0x1_0000, 2) };

        assert_eq!(returned, owner);
        assert_eq!(storage.owner.vtable, STREAM_WRITE_OWNER_VTABLE_ADDRESS);
        assert_eq!(storage.owner.state, 0);
        assert_eq!(storage.owner.stream, 0);
        assert_eq!(storage.owner.buffer_capacity, 0x1_0000);
        assert_eq!(&storage.owner.name[..name.len()], name);
        assert!(storage.owner.name[name.len()..].iter().all(|&byte| byte == 0xa5));
        assert_eq!(storage.tail, 0x7777_8888);
    }

    #[test]
    fn copies_empty_name_and_ignores_fourth_input() {
        let mut storage = owner_with_bytes(0x5c);
        let owner = &mut storage.owner as *mut StreamWriteOwnerPrefix;
        let empty_name = [0u8];

        unsafe {
            stream_write_owner_construct(owner, empty_name.as_ptr(), u32::MAX, 0xdead_beef);
        }

        assert_eq!(storage.owner.name[0], 0);
        assert!(storage.owner.name[1..].iter().all(|&byte| byte == 0x5c));
        assert_eq!(storage.owner.buffer_capacity, u32::MAX);
    }
}
