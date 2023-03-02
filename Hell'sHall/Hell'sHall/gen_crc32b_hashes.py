#!/usr/bin/env python3
import sys

POLYNOMIAL = 0xedb88320
INIT_MASK = 0xffffffff


def crc32_chksum(in_str: str) -> str:
    crc = INIT_MASK

    for each_byte in in_str.encode():
        crc ^= each_byte

        for _ in range(8):
            mask = INIT_MASK if (crc & 1) else 0x0
            crc = (crc >> 1) ^ (POLYNOMIAL & mask)

    crc ^= INIT_MASK

    return "".join(("0x", hex(crc)[2:].upper()))


def main():
    try:
        ntdll_funcs = sys.argv[1].split(',')
        ntdll_func_dict = {
            ntdll_func: crc32_chksum(ntdll_func)
            for ntdll_func in ntdll_funcs
        }

        out = ""
        for fn_name, fn_crc32_hash in ntdll_func_dict.items():
            out = "\n".join(
                (out, f"#define {fn_name}_CRC32b \t{fn_crc32_hash}"))

        print(out)
    except Exception:
        err_msg = f"""[-] Please provide the "ntdll" functions.
    Usage: {sys.argv[0]} "func1,func2,func3,..."
    
    e.g.
        {sys.argv[0]} "NtCreateThreadEx"
        {sys.argv[0]} "NtCreateThreadEx,NtCreateSection"
        {sys.argv[0]} "NtCreateThreadEx,NtAllocateVirtualMemory,NtProtectVirtualMemory"
        """

        print(err_msg)
        sys.exit(1)


if __name__ == "__main__":
    # unit test
    # assert (crc32_chksum("NtCreateThreadEx") == "0x2073465A")

    main()
