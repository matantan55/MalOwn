"""
Script to synthesize harmless sample files for testing MalOwn:
1. hello_windows.exe (PE executable)
2. hello_linux.elf (Linux ELF executable)
3. hello_script.py (Harmless Python script)
4. sample_archive.zip (ZIP archive containing a harmless file)
"""

import os
import struct
import zipfile
import shutil
import subprocess

FIXTURES_DIR = os.path.dirname(os.path.abspath(__file__))


def create_minimal_pe(target_path: str) -> None:
    """Generate a minimal valid 32-bit Windows PE executable."""
    # DOS Header
    # MZ, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)  # e_lfanew = 64
    pe_sig = b"PE\x00\x00"

    # COFF File Header (IMAGE_FILE_HEADER)
    # Machine=i386 (0x014c), NumberOfSections=1, TimeDateStamp=0x66000000, PointerToSymbolTable=0, NumberOfSymbols=0, SizeOfOptionalHeader=224, Characteristics=0x0102 (EXECUTABLE_IMAGE | 32BIT_MACHINE)
    file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0x66000000, 0, 0, 224, 0x0102)

    # Optional Header (IMAGE_OPTIONAL_HEADER32)
    # Magic=0x010b, MajorLinker=1, MinorLinker=0, SizeOfCode=512, SizeOfInitializedData=0, SizeOfUninitializedData=0,
    # AddressOfEntryPoint=0x1000, BaseOfCode=0x1000, BaseOfData=0x2000, ImageBase=0x400000,
    # SectionAlignment=0x1000, FileAlignment=0x200, MajorOS=4, MinorOS=0, MajorImage=0, MinorImage=0,
    # MajorSubsystem=4, MinorSubsystem=0, Win32Value=0, SizeOfImage=0x3000, SizeOfHeaders=0x200,
    # CheckSum=0, Subsystem=2 (WINDOWS_GUI), DllCharacteristics=0, SizeOfStackReserve=0x100000,
    # SizeOfStackCommit=0x1000, SizeOfHeapReserve=0x100000, SizeOfHeapCommit=0x1000, LoaderFlags=0, NumberOfRvaAndSizes=16
    opt_header = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B, 1, 0, 512, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200,
        4, 0, 0, 0, 4, 0, 0, 0x3000, 0x200, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16
    ) + b"\x00" * (16 * 8)

    # Section Header (.text)
    # Name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers, Characteristics (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ = 0x60000020)
    sec_name = b".text\x00\x00\x00"
    sec_header = struct.pack("<8sIIIIIIHHI", sec_name, 512, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)

    # Assembly: mov eax, 0; ret
    code = b"\xb8\x00\x00\x00\x00\xc3" + b"\x90" * 506

    headers = dos_header + pe_sig + file_header + opt_header + sec_header
    pe_bytes = headers + b"\x00" * (512 - len(headers)) + code

    with open(target_path, "wb") as f:
        f.write(pe_bytes)


def create_minimal_elf(target_path: str) -> None:
    """Generate a valid 64-bit Linux ELF executable with section headers."""
    # 64-bit ELF executable header
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8  # 64-bit, little-endian, SYSV
    e_type = 2          # ET_EXEC
    e_machine = 62      # EM_X86_64
    e_version = 1
    e_entry = 0x400080  # Entry point address
    e_phoff = 64        # Program header offset right after ELF header
    e_shoff = 256       # Section header offset
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 1
    e_shentsize = 64
    e_shnum = 3         # NULL section, .text section, .shstrtab section
    e_shstrndx = 2      # Section index of string table

    elf_header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
        e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    )

    # Program header (PT_LOAD, flags=PF_R | PF_X = 5)
    p_type = 1
    p_flags = 5
    p_offset = 0
    p_vaddr = 0x400000
    p_paddr = 0x400000
    p_filesz = 256
    p_memsz = 256
    p_align = 0x1000

    prog_header = struct.pack("<IIQQQQQQ", p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)

    # Code at offset 128 (entry 0x400080)
    # mov eax, 60 (sys_exit); xor edi, edi (status 0); syscall
    code = b"\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05"
    code_padding = b"\x90" * (128 - len(code))  # Pad up to offset 256

    # Section string table at offset 200: \x00.text\x00.shstrtab\x00
    shstrtab = b"\x00.text\x00.shstrtab\x00"

    # Section Headers at offset 256
    # 0: NULL section
    sh_null = b"\x00" * 64

    # 1: .text section (sh_name=1, sh_type=1 (SHT_PROGBITS), sh_flags=6 (SHF_ALLOC|SHF_EXECINSTR))
    sh_text = struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0x400080, 128, len(code), 0, 0, 16, 0)

    # 2: .shstrtab section (sh_name=7, sh_type=3 (SHT_STRTAB), sh_flags=0)
    sh_shstrtab = struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, 200, len(shstrtab), 0, 0, 1, 0)

    # Assemble bytes
    blob = bytearray(512)
    blob[0:64] = elf_header
    blob[64:120] = prog_header
    blob[128:128+len(code)] = code
    blob[200:200+len(shstrtab)] = shstrtab
    blob[256:320] = sh_null
    blob[320:384] = sh_text
    blob[384:448] = sh_shstrtab

    with open(target_path, "wb") as f:
        f.write(bytes(blob))


def create_sample_zip(target_path: str) -> None:
    """Generate a sample zip archive containing a harmless payload."""
    readme_content = b"MalOwn test fixture: benign archive member.\nContact: security@example.com\n"
    script_content = b"#!/bin/sh\necho 'Running test fixture payload'\nexit 0\n"

    with zipfile.ZipFile(target_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", readme_content)
        zf.writestr("scripts/setup.sh", script_content)


def create_infected_password_zip(target_path: str) -> None:
    """Generate a password-protected zip archive using standard password 'infected'."""
    data = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with zipfile.ZipFile(target_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Note: standard zipfile setpassword only supports decrypting or standard PKWARE
        zf.setpassword(b"infected")
        zf.writestr("eicar.com", data)


if __name__ == "__main__":
    create_minimal_pe(os.path.join(FIXTURES_DIR, "hello_windows.exe"))
    create_minimal_elf(os.path.join(FIXTURES_DIR, "hello_linux.elf"))
    create_sample_zip(os.path.join(FIXTURES_DIR, "sample_archive.zip"))
    print("Fixtures created successfully.")
