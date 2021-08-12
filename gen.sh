#!/bin/bash

set -e           # exit if any command has a non-zero exit code
set -u           # exit if any referenced variable has not been previously defined
set -o pipefail  # exit code of a pipeline is the failed command, if any failed
unset CDPATH
IFS=$' \n\t'
: "${BASH_SOURCE?'BASH_SOURCE variable not defined, not running in bash'}"

# change into the directory this script resides in
cd "$(dirname "${BASH_SOURCE[0]}")"

SED_PAT='s/^#define __NR_\([^ \t]\+\)[ \t]\+\([ \t()+xA-Fa-f0-9]\+\)$/\2,\1/ p'

sed -n "$SED_PAT" "musl-1.2.2/arch/x32/bits/syscall.h.in" | \
while read -r LINE ; do
    N=$(cut -d , -f 1 <<< "$LINE")
    S=$(cut -d , -f 2 <<< "$LINE")

    N=$(python3 -c "print($N)")
    echo "$N,$S"
done | sort -g > 'syscalls-raw-linux-x32.csv'

SED_PAT='s/^#define __NR_\([^ \t]\+\)[ \t]\+\([0-9]\+\)$/\2,\1/ p'

sed -n "$SED_PAT" "musl-1.2.2/arch/arm/bits/syscall.h.in" | \
    grep -v ',arm_' | \
    sort -g > 'syscalls-raw-linux-arm.csv'

sed -n "$SED_PAT" "musl-1.2.2/arch/or1k/bits/syscall.h.in" | \
    grep -v ',_llseek' | \
    sort -g > 'syscalls-raw-linux-or1k.csv'

for ARCH in aarch64 i386 m68k microblaze mips mips64 mipsn32 powerpc powerpc64 riscv64 s390x sh x86_64; do
    sed -n "$SED_PAT" "musl-1.2.2/arch/$ARCH/bits/syscall.h.in" | \
        grep -v ',arm_' | \
        sort -g > "syscalls-raw-linux-${ARCH}.csv"
done

for ARCH in aarch64 arm i386 m68k microblaze mips mips64 mipsn32 or1k powerpc powerpc64 riscv64 s390x sh x32 x86_64; do
    SYS_CALL_BASE_INDEX=$(cut -d , -f 1 syscalls-raw-linux-${ARCH}.csv | head -1)

    awk 'BEGIN { FS=","; N='"$SYS_CALL_BASE_INDEX"'; S=0; } END { exit(S); } /^[0-9]+/ { if (N > $1) { printf("[ERROR/'"$ARCH"'] Duplicate syscall number %s. New name: %s\n", $1, $2); S=1; } ; N = 1 + $1; }' "syscalls-raw-linux-${ARCH}.csv"

    awk 'BEGIN { FS=","; N='"$SYS_CALL_BASE_INDEX"'; } /^[0-9]+/ { for (; N < $1; N++) { printf("%d,\n", N); } print $0; N = 1 + $1; }' "syscalls-raw-linux-${ARCH}.csv" > "syscalls-full-linux-${ARCH}.csv"

    awk 'BEGIN { FS=","; printf("#![allow(non_upper_case_globals)]\n\nuse std::os::raw::c_long;\n\n"); } END { printf("\n"); } /^[0-9]+,/ { if (length($2)>0) { printf("pub const SYS_%s: c_long = %s;\n", $2, $1); } }' "syscalls-full-linux-${ARCH}.csv" > "src/${ARCH}.rs"

    printf "pub const SYS_CALL_BASE_INDEX: c_long = %s;\n\n" "$SYS_CALL_BASE_INDEX" >> "src/${ARCH}.rs"

    awk 'BEGIN { FS=","; printf("pub static SYS_CALL_NAME: &[&str] = &[\n"); } END { printf("];\n"); } /^[0-9]+,/ { printf("    \"%s\",\n", $2); }' "syscalls-full-linux-${ARCH}.csv" >> "src/${ARCH}.rs"
done
