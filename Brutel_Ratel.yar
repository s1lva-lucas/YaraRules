import "pe"
import "math"

rule Backdoor_BRUTEL_S1 {
    meta:
        author = "Ian Kenefick"
        Description = "Brute Ratel Backdoor"
    condition:
       math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) >= 5.39 and
        math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) <= 6.62 and
        math.entropy(pe.sections[1].raw_data_offset, pe.sections[1].raw_data_size) >= 6.66 and
        math.entropy(pe.sections[1].raw_data_offset, pe.sections[1].raw_data_size) <= 8.79 and
        math.entropy(pe.sections[2].raw_data_offset, pe.sections[2].raw_data_size) >= 2.29 and
        math.entropy(pe.sections[2].raw_data_offset, pe.sections[2].raw_data_size) <= 3.33 and
        math.entropy(pe.sections[3].raw_data_offset, pe.sections[3].raw_data_size) >= 2.19 and
        math.entropy(pe.sections[3].raw_data_offset, pe.sections[3].raw_data_size) <= 2.8 and
        math.entropy(pe.sections[4].raw_data_offset, pe.sections[4].raw_data_size) >= 2.74 and
        math.entropy(pe.sections[4].raw_data_offset, pe.sections[4].raw_data_size) <= 3.58 and
        math.entropy(pe.sections[5].raw_data_offset, pe.sections[5].raw_data_size) == 0.0 and
        math.entropy(pe.sections[6].raw_data_offset, pe.sections[6].raw_data_size) >= 0.66 and
        math.entropy(pe.sections[6].raw_data_offset, pe.sections[6].raw_data_size) <= 0.83 and
        math.entropy(pe.sections[7].raw_data_offset, pe.sections[7].raw_data_size) >= 3.2 and
        math.entropy(pe.sections[7].raw_data_offset, pe.sections[7].raw_data_size) <= 3.93 and
        math.entropy(pe.sections[8].raw_data_offset, pe.sections[8].raw_data_size) >= 0.18 and
        math.entropy(pe.sections[8].raw_data_offset, pe.sections[8].raw_data_size) <= 0.28 and
        math.entropy(pe.sections[9].raw_data_offset, pe.sections[9].raw_data_size) == 0.0 and
        math.entropy(pe.sections[10].raw_data_offset, pe.sections[10].raw_data_size) >= 0.88 and
        math.entropy(pe.sections[10].raw_data_offset, pe.sections[10].raw_data_size) <= 1.09 and
        pe.imports("KERNEL32.dll", "DeleteCriticalSection") and
        pe.imports("KERNEL32.dll", "EnterCriticalSection") and
        pe.imports("KERNEL32.dll", "GetLastError") and
        pe.imports("KERNEL32.dll", "InitializeCriticalSection") and
        pe.imports("KERNEL32.dll", "LeaveCriticalSection") and
        pe.imports("KERNEL32.dll", "Sleep") and
        pe.imports("KERNEL32.dll", "TlsGetValue") and
        pe.imports("KERNEL32.dll", "VirtualProtect") and
        pe.imports("KERNEL32.dll", "VirtualQuery") and
        pe.imports("msvcrt.dll", "__iob_func") and
        pe.imports("msvcrt.dll", "_amsg_exit") and
        pe.imports("msvcrt.dll", "_initterm") and
        pe.imports("msvcrt.dll", "_lock") and
        pe.imports("msvcrt.dll", "_unlock") and
        pe.imports("msvcrt.dll", "abort") and
        pe.imports("msvcrt.dll", "calloc") and
        pe.imports("msvcrt.dll", "free") and
        pe.imports("msvcrt.dll", "fwrite") and
        pe.imports("msvcrt.dll", "realloc") and
        pe.imports("msvcrt.dll", "strlen") and
        pe.imports("msvcrt.dll", "strncmp") and
        pe.imports("msvcrt.dll", "vfprintf") and
        pe.exports("main") and
        pe.data_directories[0].virtual_address >= 243302 and
        pe.data_directories[0].virtual_address <= 414515 and
        pe.data_directories[0].size >= 61 and
        pe.data_directories[0].size <= 75 and
        pe.data_directories[1].virtual_address >= 246989 and
        pe.data_directories[1].virtual_address <= 419021 and
        pe.data_directories[1].size >= 781 and
        pe.data_directories[1].size <= 955 and
        pe.data_directories[2].virtual_address == 0 and
        pe.data_directories[2].size == 0 and
        pe.data_directories[3].virtual_address >= 232243 and
        pe.data_directories[3].virtual_address <= 400998 and
        pe.data_directories[3].size >= 486 and
        pe.data_directories[3].size <= 607 and
        pe.data_directories[4].virtual_address == 0 and
        pe.data_directories[4].size == 0 and
        pe.data_directories[5].virtual_address >= 258048 and
        pe.data_directories[5].virtual_address <= 432538 and
        pe.data_directories[5].size >= 83 and
        pe.data_directories[5].size <= 101 and
        pe.data_directories[6].virtual_address == 0 and
        pe.data_directories[6].size == 0 and
        pe.data_directories[7].virtual_address == 0 and
        pe.data_directories[7].size == 0 and
        pe.data_directories[8].virtual_address == 0 and
        pe.data_directories[8].size == 0 and
        pe.data_directories[9].virtual_address >= 228586 and
        pe.data_directories[9].virtual_address <= 396528 and
        pe.data_directories[9].size >= 36 and
        pe.data_directories[9].size <= 44 and
        pe.data_directories[10].virtual_address == 0 and
        pe.data_directories[10].size == 0 and
        pe.data_directories[11].virtual_address == 0 and
        pe.data_directories[11].size == 0 and
        pe.data_directories[12].virtual_address >= 247216 and
        pe.data_directories[12].virtual_address <= 419298 and
        pe.data_directories[12].size >= 173 and
        pe.data_directories[12].size <= 211 and
        pe.data_directories[13].virtual_address == 0 and
        pe.data_directories[13].size == 0 and
        pe.data_directories[14].virtual_address == 0 and
        pe.data_directories[14].size == 0 and
        pe.data_directories[15].virtual_address == 0 and
        pe.data_directories[15].size == 0 and
        pe.DLL and
        pe.is_64bit()
}