//! C++ standard-library runtime: the container and string implementations
//! retailOS's application layer is built on. They live in the
//! 0x083c0000-0x083dffff block of osos (~1000 functions), separate from
//! the ARM ADS C runtime.
pub mod byte_key_map;
pub mod handle;
pub mod pair_header;
pub mod release;
pub mod string;
pub mod string_object;
pub mod templates;
