#![doc(html_root_url = "https://docs.rs/syscall-numbers/2.0.0")]
#![warn(
    //missing_docs,
    keyword_idents,
    macro_use_extern_crate,
    missing_debug_implementations,
    non_ascii_idents,
    trivial_casts,
    trivial_numeric_casts,
    unstable_features,
    unused_extern_crates,
    unused_import_braces,
    unused_labels,
    variant_size_differences,
    unused_qualifications
)]

/*!
## System calls numbers for various architectures

Only Linux is currently supported.

## Versioning

This project adheres to [Semantic Versioning].
The `CHANGELOG.md` file details notable changes over time.

[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
*/

/// AArch64 definitions.
pub mod aarch64;
/// ARM definitions.
pub mod arm;
/// Motorola 68000 series definitions.
pub mod m68k;
/// MicroBlaze definitions.
pub mod microblaze;
/// MIPS definitions.
pub mod mips;
/// MIPS64 definitions.
pub mod mips64;
/// MIPS N32 definitions.
pub mod mipsn32;
/// OpenRISC 1000 definitions.
pub mod or1k;
/// PowerPC definitions.
pub mod powerpc;
/// PowerPC64 definitions.
pub mod powerpc64;
/// RISC-V 64 definitions.
pub mod riscv64;
/// IBM System Z 64-bit definitions.
pub mod s390x;
/// SuperH definitions.
pub mod sh;
/// X86_32 definitions.
pub mod x32;
/// X86 definitions.
pub mod x86;
/// AMD64 definitions.
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64 as native;

#[cfg(target_arch = "arm")]
pub use arm as native;

#[cfg(target_arch = "m68k")]
pub use m68k as native;

#[cfg(target_arch = "microblaze")]
pub use microblaze as native;

#[cfg(target_arch = "mips")]
pub use mips as native;

#[cfg(target_arch = "mips64")]
pub use mips64 as native;

#[cfg(target_arch = "mipsn32")]
pub use mipsn32 as native;

#[cfg(target_arch = "or1k")]
pub use or1k as native;

#[cfg(target_arch = "powerpc")]
pub use powerpc as native;

#[cfg(target_arch = "powerpc64")]
pub use powerpc64 as native;

#[cfg(target_arch = "riscv64")]
pub use riscv64 as native;

#[cfg(target_arch = "s390x")]
pub use s390x as native;

#[cfg(target_arch = "sh")]
pub use sh as native;

#[cfg(target_arch = "x32")]
pub use x32 as native;

#[cfg(target_arch = "x86")]
pub use x86 as native;

#[cfg(target_arch = "x86_64")]
pub use x86_64 as native;

use std::os::raw::c_long;

/// Returns the name of a system call, given its number.
pub(crate) fn sys_call_name(
    names: &'static [&'static str],
    base_index: c_long,
    number: c_long,
) -> Option<&'static str> {
    if number >= base_index {
        if let Ok(index) = usize::try_from(number - base_index) {
            return names.get(index).filter(|name| !name.is_empty()).cloned();
        }
    }
    None
}

/// Returns `true` if `number` is a valid system call number.
pub(crate) fn is_valid_sys_call_number(
    names: &'static [&'static str],
    base_index: c_long,
    number: c_long,
) -> bool {
    if let Ok(names_len) = c_long::try_from(names.len()) {
        let last_number = base_index + names_len - 1;
        return number >= base_index && number <= last_number;
    }
    false
}
