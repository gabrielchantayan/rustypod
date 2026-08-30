//! Filesystem-layer helpers (path handling, FAT-facing utilities).
pub mod path_limits;
/// Path-resolution node release @ 0x082e19cc.
pub mod path_node;
/// Cache-entry reference release @ 0x082e18bc.
pub mod cache_entry;
/// Platform C++ file-object read wrapper @ 0x082784b8.
pub mod file_read;
