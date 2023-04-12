# Change log

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - 2023-04-12

### Changed

- Added support for `no_std`.

  Thank you, [*BrainStackOverFlow*](https://github.com/BrainStackOverFlow).

## [3.0.0] - 2022-05-08

### Changed

- The `riscv64::SYS_fstatat` was renamed to `riscv64::SYS_newfstatat`, to correct the system call
  name on RISC-V 64-bits.
  > ⚠️ **This is a breaking change**.

### Added

- Use hexadecimal system call numbers.
- Added the following system calls: `process_madvise`, `epoll_pwait2`, `mount_setattr`,
  `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`.

## [2.0.0] - 2021-10-25

### Changed

- Migrated Rust edition to 2021.
  > ⚠️ **This is a breaking change**.

## [1.0.0] - 2021-08-12

### Added

- Initial release.
