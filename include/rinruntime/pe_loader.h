// SPDX-License-Identifier: MIT
/*
 * RinOS PE (Windows Executable) Loader
 * 共通PE32/64ローダー ✿
 *
 * kernel_main.c と kernel_main64.c 用のPE実行ファイルローダー
 * Windows .exe/.dll ファイルをRinOS上で実行可能にする互換レイヤー
 *
 * デバッグ出力を使用するには、このヘッダーをincludeする前に
 * PE_DEBUG_PRINT(str) と PE_DEBUG_HEX(val) マクロを定義してください。
 */

#ifndef PE_LOADER_H
#define PE_LOADER_H

#include <stdint.h>
#include <stddef.h>

/* デバッグ出力フック（未定義の場合は何もしない） */
#ifndef PE_DEBUG_PRINT
#define PE_DEBUG_PRINT(s)  ((void)0)
#endif
#ifndef PE_DEBUG_HEX
#define PE_DEBUG_HEX(v)    ((void)0)
#endif

/* ═══════════════════════════════════════════════════════════════
 * PE マジック・定数
 * ═══════════════════════════════════════════════════════════════*/

#define PE_DOS_MAGIC        0x5A4D      /* "MZ" */
#define PE_SIGNATURE        0x00004550  /* "PE\0\0" */
#define PE_OPT_MAGIC_32     0x010B      /* PE32 */
#define PE_OPT_MAGIC_64     0x020B      /* PE32+ (64-bit) */

/* マシンタイプ */
#define PE_MACHINE_UNKNOWN  0x0000
#define PE_MACHINE_I386     0x014C      /* x86 */
#define PE_MACHINE_AMD64    0x8664      /* x64 */
#define PE_MACHINE_ARM      0x01C0      /* ARM */
#define PE_MACHINE_ARM64    0xAA64      /* ARM64 */

/* Characteristics */
#define PE_CHAR_RELOCS_STRIPPED     0x0001
#define PE_CHAR_EXECUTABLE_IMAGE    0x0002
#define PE_CHAR_32BIT_MACHINE       0x0100
#define PE_CHAR_DLL                 0x2000

/* Subsystem */
#define PE_SUBSYSTEM_UNKNOWN        0
#define PE_SUBSYSTEM_NATIVE         1
#define PE_SUBSYSTEM_WINDOWS_GUI    2
#define PE_SUBSYSTEM_WINDOWS_CUI    3   /* Console */
#define PE_SUBSYSTEM_POSIX_CUI      7

/* Data Directory indices */
#define PE_DIR_EXPORT           0
#define PE_DIR_IMPORT           1
#define PE_DIR_RESOURCE         2
#define PE_DIR_EXCEPTION        3
#define PE_DIR_SECURITY         4
#define PE_DIR_BASERELOC        5
#define PE_DIR_DEBUG            6
#define PE_DIR_TLS              9
#define PE_DIR_IAT              12
#define PE_DIR_DELAY_IMPORT     13
#define PE_NUM_DATA_DIRS        16

/* Section characteristics */
#define PE_SCN_CNT_CODE             0x00000020
#define PE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define PE_SCN_CNT_UNINITIALIZED    0x00000080
#define PE_SCN_MEM_DISCARDABLE      0x02000000
#define PE_SCN_MEM_EXECUTE          0x20000000
#define PE_SCN_MEM_READ             0x40000000
#define PE_SCN_MEM_WRITE            0x80000000

/* Relocation types */
#define PE_REL_BASED_ABSOLUTE       0   /* No relocation */
#define PE_REL_BASED_HIGH           1   /* High 16 bits */
#define PE_REL_BASED_LOW            2   /* Low 16 bits */
#define PE_REL_BASED_HIGHLOW        3   /* Full 32 bits */
#define PE_REL_BASED_DIR64          10  /* Full 64 bits */

/* エラーコード */
#define PE_OK               0
#define PE_ERR_NULL         -1
#define PE_ERR_NOT_PE       -2
#define PE_ERR_UNSUPPORTED  -3
#define PE_ERR_SIZE         -4
#define PE_ERR_LOAD         -5
#define PE_ERR_BOUNDS       -6
#define PE_ERR_OVERLAP      -7
#define PE_ERR_IMPORT       -8
#define PE_ERR_RELOCATION   -9
#define PE_ERR_POLICY       -10
#define PE_ERR_EXPORT       -11

#define PE_MAX_SECTIONS          96u
#define PE_MAX_IMAGE_SIZE        (1024u * 1024u * 1024u)
#define PE_MAX_IMPORT_SYMBOLS    65536u
#define PE_MAX_EXPORT_SYMBOLS    65536u

/* Mapping flags are kernel-internal policy switches. Delay imports remain a
 * RinNT user-space responsibility; the ordinary mapper rejects them unless
 * its caller explicitly keeps the image private for RinNT post-processing. */
#define PE_LOAD_DEFER_DELAY_IMPORTS 0x00000001u
#define PE_LOAD_VALID_FLAGS PE_LOAD_DEFER_DELAY_IMPORTS

/* ═══════════════════════════════════════════════════════════════
 * PE 構造体定義
 * ═══════════════════════════════════════════════════════════════*/

/* DOS Header */
typedef struct {
    uint16_t e_magic;       /* MZ = 0x5A4D */
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;      /* Offset to PE header */
} __attribute__((packed)) PeDosHeader;

/* COFF File Header */
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} __attribute__((packed)) PeFileHeader;

/* Data Directory Entry */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} __attribute__((packed)) PeDataDirectory;

/* Optional Header - PE32 (32-bit) */
typedef struct {
    uint16_t Magic;                     /* 0x010B */
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    PeDataDirectory DataDirectory[PE_NUM_DATA_DIRS];
} __attribute__((packed)) PeOptionalHeader32;

/* Optional Header - PE32+ (64-bit) */
typedef struct {
    uint16_t Magic;                     /* 0x020B */
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    PeDataDirectory DataDirectory[PE_NUM_DATA_DIRS];
} __attribute__((packed)) PeOptionalHeader64;

/* Section Header */
typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} __attribute__((packed)) PeSectionHeader;

/* Base Relocation Block */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
    /* Followed by WORD entries */
} __attribute__((packed)) PeBaseRelocation;

/* Import Descriptor */
typedef struct {
    uint32_t OriginalFirstThunk;    /* RVA to INT */
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;                  /* RVA to DLL name */
    uint32_t FirstThunk;            /* RVA to IAT */
} __attribute__((packed)) PeImportDescriptor;

/* Delay-load descriptor (IMAGE_DELAYLOAD_DESCRIPTOR). Fields remain DWORDs
 * in both PE32 and PE32+; Attributes bit 0 selects RVA-based encoding. */
typedef struct {
    uint32_t Attributes;
    uint32_t Name;
    uint32_t ModuleHandle;
    uint32_t DelayImportAddressTable;
    uint32_t DelayImportNameTable;
    uint32_t BoundDelayImportTable;
    uint32_t UnloadDelayImportTable;
    uint32_t TimeDateStamp;
} __attribute__((packed)) PeDelayImportDescriptor;

/* Import By Name */
typedef struct {
    uint16_t Hint;
    char     Name[1];               /* Variable length */
} __attribute__((packed)) PeImportByName;

/* TLS Directory - 32-bit */
typedef struct {
    uint32_t StartAddressOfRawData;
    uint32_t EndAddressOfRawData;
    uint32_t AddressOfIndex;
    uint32_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
} __attribute__((packed)) PeTlsDirectory32;

/* TLS Directory - 64-bit */
typedef struct {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
} __attribute__((packed)) PeTlsDirectory64;

/* TLS Callback function type */
typedef void (*PeTlsCallback)(void* DllHandle, uint32_t Reason, void* Reserved);

/* DLL notification reasons */
#define DLL_PROCESS_DETACH  0
#define DLL_PROCESS_ATTACH  1
#define DLL_THREAD_ATTACH   2
#define DLL_THREAD_DETACH   3

/* Import Ordinal Flag */
#define PE_ORDINAL_FLAG32   0x80000000
#define PE_ORDINAL_FLAG64   0x8000000000000000ULL

/* Export Directory */
typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} __attribute__((packed)) PeExportDirectory;

/* ═══════════════════════════════════════════════════════════════
 * PE ロード情報
 * ═══════════════════════════════════════════════════════════════*/

typedef struct {
    uint64_t entry_point;       /* Entry point address */
    uint64_t image_base;        /* Loaded image base */
    uint64_t preferred_base;    /* Preferred image base */
    uint32_t image_size;        /* Total image size */
    uint32_t header_size;       /* Header size */
    uint16_t machine;           /* Machine type */
    uint16_t subsystem;         /* Subsystem (GUI/CUI) */
    uint16_t characteristics;   /* PE characteristics */
    uint8_t  is_64bit;          /* 1 if PE32+, 0 if PE32 */
    uint8_t  is_dll;            /* 1 if DLL, 0 if EXE */
    uint8_t  has_tls;           /* TLS initialization is deferred to RinNT */
    uint8_t  has_delay_imports; /* delay-import binding is deferred to RinNT */
    uint32_t unresolved_imports;/* Number of unresolved IAT entries */
    uint32_t import_count;
    uint32_t tls_directory_rva;
    uint32_t tls_directory_size;
} PeLoadInfo;

/* Immutable result of PE/COFF admission validation.  Pointers reference the
 * caller-owned file bytes and remain valid only while that buffer is alive. */
typedef struct {
    const uint8_t* file;
    size_t file_size;
    const PeDosHeader* dos_header;
    const PeFileHeader* file_header;
    const void* optional_header;
    const PeSectionHeader* sections;
    const PeDataDirectory* directories;
    uint32_t directory_count;
    uint32_t image_size;
    uint32_t header_size;
    uint32_t entry_rva;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint64_t preferred_base;
    uint32_t import_descriptor_count;
    uint32_t import_symbol_count;
    uint16_t subsystem;
    uint8_t is_64bit;
    uint8_t is_dll;
    uint8_t has_tls;
    uint8_t has_delay_imports;
} PeImageView;

/* Import resolver callback */
typedef void* (*PeImportResolver)(void* user_ctx,
                                  const char* dll_name,
                                  const char* proc_name,
                                  uint16_t ordinal,
                                  int by_ordinal);

/* 32-bit compatible load info */
typedef struct {
    uint32_t entry_point;
    uint32_t image_base;
    uint32_t image_size;
    uint16_t subsystem;
    uint16_t flags;
} PeLoadInfo32;

/* Public API */
int pe_validate_image(const void* data, size_t size, PeImageView* out_view);
int pe_is_pe(const void* data, size_t size);
int pe_is_64bit(const void* data, size_t size);
int pe_is_dll(const void* data, size_t size);
uint32_t pe_get_image_size(const void* data, size_t size);
uint16_t pe_get_machine(const void* data, size_t size);
uint16_t pe_get_subsystem(const void* data, size_t size);
int pe_load64(const void* data, size_t size,
              void* load_addr, PeLoadInfo* info,
              PeImportResolver import_resolver,
              void* import_resolver_ctx);
int pe_load64_ex(const void* data, size_t size,
                 void* load_addr, PeLoadInfo* info,
                 PeImportResolver import_resolver,
                 void* import_resolver_ctx,
                 uint32_t load_flags);
/* Map into caller-owned staging bytes while relocating and binding for a
 * potentially different final process address. RinNT uses this to prepare
 * WOW32 images from a 64-bit loader without leaking host pointers into IATs. */
int pe_load64_ex_at(const void* data, size_t size,
                    void* load_addr, uint64_t virtual_base, PeLoadInfo* info,
                    PeImportResolver import_resolver,
                    void* import_resolver_ctx,
                    uint32_t load_flags);
int pe_load(const void* data, size_t size,
            void* load_addr, PeLoadInfo32* info);
int pe_is_gui(const void* data, size_t size);
int pe_is_console(const void* data, size_t size);
const char* pe_error_string(int error);
void* pe_get_export(void* image_base, uint32_t image_size, const char* name);
void* pe_get_export_by_ordinal(void* image_base, uint32_t image_size,
                               uint16_t ordinal);
int pe_dll_attach(void* image_base, uint32_t image_size);
int pe_dll_detach(void* image_base, uint32_t image_size);
void pe_unload(void* image_base, uint32_t image_size,
               void (*free_func)(void*, uint32_t));

#ifdef PE_LOADER_IMPLEMENTATION

/* ═══════════════════════════════════════════════════════════════
 * PE 内部ヘルパー
 * ═══════════════════════════════════════════════════════════════*/

static inline void pe_memset(void* dst, int val, size_t n) {
    uint8_t* p = (uint8_t*)dst;
    while (n--) *p++ = (uint8_t)val;
}

static inline void pe_memcpy(void* dst, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    while (n--) *d++ = *s++;
}

static inline int pe_size_range_ok(size_t offset, size_t length, size_t limit) {
    return offset <= limit && length <= limit - offset;
}

static inline int pe_u32_range_ok(uint32_t offset, uint32_t length, uint32_t limit) {
    return offset <= limit && length <= limit - offset;
}

static inline int pe_is_power_of_two_u32(uint32_t value) {
    return value != 0u && (value & (value - 1u)) == 0u;
}

static inline int pe_align_up_u32(uint32_t value, uint32_t alignment,
                                  uint32_t* out) {
    uint32_t mask;
    if (!out || !pe_is_power_of_two_u32(alignment)) return -1;
    mask = alignment - 1u;
    if (value > UINT32_MAX - mask) return -1;
    *out = (value + mask) & ~mask;
    return 0;
}

static uint64_t pe_read_u64_unaligned(const uint8_t* bytes) {
    uint64_t value = 0u;
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        value |= ((uint64_t)bytes[index]) << (index * 8u);
    }
    return value;
}

static uint32_t pe_read_u32_unaligned(const uint8_t* bytes) {
    uint32_t value = 0u;
    uint32_t index;
    for (index = 0u; index < 4u; ++index) {
        value |= ((uint32_t)bytes[index]) << (index * 8u);
    }
    return value;
}

/* Translate an RVA into authenticated file bytes.  BSS-only bytes deliberately
 * have no translation: loader metadata, imports and relocations must be
 * present in the file that was admitted. */
static const uint8_t* pe_view_rva_to_file(const PeImageView* view,
                                          uint32_t rva,
                                          uint32_t minimum_size,
                                          uint32_t* out_available) {
    uint32_t index;
    if (out_available) *out_available = 0u;
    if (!view || !view->file) return NULL;
    if (rva < view->header_size) {
        uint32_t available = view->header_size - rva;
        if (minimum_size > available ||
            !pe_size_range_ok((size_t)rva, minimum_size, view->file_size)) {
            return NULL;
        }
        if (out_available) *out_available = available;
        return view->file + rva;
    }
    for (index = 0u; index < view->file_header->NumberOfSections; ++index) {
        const PeSectionHeader* section = &view->sections[index];
        uint32_t delta;
        uint32_t available;
        if (rva < section->VirtualAddress) continue;
        delta = rva - section->VirtualAddress;
        if (delta >= section->SizeOfRawData) continue;
        available = section->SizeOfRawData - delta;
        if (minimum_size > available ||
            !pe_size_range_ok((size_t)section->PointerToRawData + delta,
                              minimum_size, view->file_size)) {
            return NULL;
        }
        if (out_available) *out_available = available;
        return view->file + section->PointerToRawData + delta;
    }
    return NULL;
}

static int pe_view_rva_has_flags(const PeImageView* view, uint32_t rva,
                                 uint32_t size, uint32_t required_flags) {
    uint32_t index;
    if (!view || size == 0u) return 0;
    for (index = 0u; index < view->file_header->NumberOfSections; ++index) {
        const PeSectionHeader* section = &view->sections[index];
        uint32_t span = section->VirtualSize > section->SizeOfRawData
            ? section->VirtualSize : section->SizeOfRawData;
        if (rva >= section->VirtualAddress &&
            pe_u32_range_ok(rva, size, section->VirtualAddress + span) &&
            (section->Characteristics & required_flags) == required_flags) {
            return 1;
        }
    }
    return 0;
}

static int pe_validate_file_string(const PeImageView* view, uint32_t rva,
                                   uint32_t prefix_size, int require_nonempty) {
    uint32_t available;
    uint32_t index;
    const uint8_t* text = pe_view_rva_to_file(view, rva, prefix_size + 1u,
                                              &available);
    if (!text || available <= prefix_size) return PE_ERR_IMPORT;
    if (require_nonempty && text[prefix_size] == 0u) return PE_ERR_IMPORT;
    if (available > 4096u) available = 4096u;
    for (index = prefix_size; index < available; ++index) {
        if (text[index] == 0u) return PE_OK;
    }
    return PE_ERR_IMPORT;
}

static int pe_validate_import_directory(PeImageView* view) {
    const PeDataDirectory* directory;
    const uint8_t* descriptor_bytes;
    uint32_t max_descriptors;
    uint32_t descriptor_index;
    uint32_t total_symbols = 0u;
    int terminated = 0;
    if (!view || view->directory_count <= PE_DIR_IMPORT) return PE_OK;
    directory = &view->directories[PE_DIR_IMPORT];
    if (directory->VirtualAddress == 0u) return PE_OK;
    descriptor_bytes = pe_view_rva_to_file(view, directory->VirtualAddress,
                                           directory->Size, NULL);
    if (!descriptor_bytes || directory->Size < sizeof(PeImportDescriptor)) {
        return PE_ERR_IMPORT;
    }
    max_descriptors = directory->Size / (uint32_t)sizeof(PeImportDescriptor);
    for (descriptor_index = 0u; descriptor_index < max_descriptors;
         ++descriptor_index) {
        const PeImportDescriptor* descriptor = (const PeImportDescriptor*)
            (descriptor_bytes + descriptor_index * sizeof(PeImportDescriptor));
        uint32_t thunk_rva;
        uint32_t thunk_available;
        uint32_t thunk_width = view->is_64bit ? 8u : 4u;
        uint32_t thunk_index;
        const uint8_t* thunk_bytes;
        if (descriptor->OriginalFirstThunk == 0u && descriptor->TimeDateStamp == 0u &&
            descriptor->ForwarderChain == 0u && descriptor->Name == 0u &&
            descriptor->FirstThunk == 0u) {
            terminated = 1;
            view->import_descriptor_count = descriptor_index;
            break;
        }
        if (descriptor->Name == 0u || descriptor->FirstThunk == 0u ||
            pe_validate_file_string(view, descriptor->Name, 0u, 1) != PE_OK) {
            return PE_ERR_IMPORT;
        }
        thunk_rva = descriptor->OriginalFirstThunk != 0u
            ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
        thunk_bytes = pe_view_rva_to_file(view, thunk_rva, thunk_width,
                                          &thunk_available);
        if (!thunk_bytes) return PE_ERR_IMPORT;
        for (thunk_index = 0u; thunk_index < thunk_available / thunk_width;
             ++thunk_index) {
            uint64_t thunk = view->is_64bit
                ? pe_read_u64_unaligned(thunk_bytes + thunk_index * thunk_width)
                : pe_read_u32_unaligned(thunk_bytes + thunk_index * thunk_width);
            uint32_t iat_rva;
            if (thunk == 0u) break;
            if (total_symbols >= PE_MAX_IMPORT_SYMBOLS ||
                descriptor->FirstThunk > UINT32_MAX - thunk_index * thunk_width) {
                return PE_ERR_IMPORT;
            }
            iat_rva = descriptor->FirstThunk + thunk_index * thunk_width;
            if (!pe_u32_range_ok(iat_rva, thunk_width, view->image_size) ||
                !pe_view_rva_has_flags(view, iat_rva, thunk_width,
                                       PE_SCN_MEM_WRITE)) {
                return PE_ERR_IMPORT;
            }
            if (view->is_64bit ? ((thunk & PE_ORDINAL_FLAG64) == 0u)
                               : ((thunk & PE_ORDINAL_FLAG32) == 0u)) {
                uint32_t name_rva;
                if (view->is_64bit && (thunk >> 32u) != 0u) return PE_ERR_IMPORT;
                name_rva = (uint32_t)thunk;
                if (pe_validate_file_string(view, name_rva, 2u, 1) != PE_OK) {
                    return PE_ERR_IMPORT;
                }
            }
            ++total_symbols;
        }
        if (thunk_index >= thunk_available / thunk_width) return PE_ERR_IMPORT;
    }
    if (!terminated) return PE_ERR_IMPORT;
    view->import_symbol_count = total_symbols;
    return PE_OK;
}

static int pe_validate_export_directory(const PeImageView* view) {
    const PeDataDirectory* directory;
    const PeExportDirectory* exports;
    const uint8_t* function_bytes;
    const uint8_t* name_bytes;
    const uint8_t* ordinal_bytes;
    uint32_t index;
    uint32_t directory_end;
    if (!view || view->directory_count <= PE_DIR_EXPORT) return PE_OK;
    directory = &view->directories[PE_DIR_EXPORT];
    if (directory->VirtualAddress == 0u) return PE_OK;
    if (directory->Size < sizeof(PeExportDirectory) ||
        directory->VirtualAddress > UINT32_MAX - directory->Size) {
        return PE_ERR_EXPORT;
    }
    directory_end = directory->VirtualAddress + directory->Size;
    exports = (const PeExportDirectory*)pe_view_rva_to_file(
        view, directory->VirtualAddress, (uint32_t)sizeof(PeExportDirectory),
        NULL);
    if (!exports || exports->NumberOfFunctions > PE_MAX_EXPORT_SYMBOLS ||
        exports->NumberOfNames > exports->NumberOfFunctions ||
        exports->Base > UINT32_MAX - exports->NumberOfFunctions) {
        return PE_ERR_EXPORT;
    }
    if (exports->Name != 0u &&
        pe_validate_file_string(view, exports->Name, 0u, 1) != PE_OK) {
        return PE_ERR_EXPORT;
    }
    if (exports->NumberOfFunctions == 0u) {
        return exports->NumberOfNames == 0u ? PE_OK : PE_ERR_EXPORT;
    }
    if (exports->AddressOfFunctions == 0u) return PE_ERR_EXPORT;
    function_bytes = pe_view_rva_to_file(
        view, exports->AddressOfFunctions,
        exports->NumberOfFunctions * (uint32_t)sizeof(uint32_t), NULL);
    if (!function_bytes) return PE_ERR_EXPORT;
    if (exports->NumberOfNames != 0u) {
        if (exports->AddressOfNames == 0u ||
            exports->AddressOfNameOrdinals == 0u) return PE_ERR_EXPORT;
        name_bytes = pe_view_rva_to_file(
            view, exports->AddressOfNames,
            exports->NumberOfNames * (uint32_t)sizeof(uint32_t), NULL);
        ordinal_bytes = pe_view_rva_to_file(
            view, exports->AddressOfNameOrdinals,
            exports->NumberOfNames * (uint32_t)sizeof(uint16_t), NULL);
        if (!name_bytes || !ordinal_bytes) return PE_ERR_EXPORT;
        for (index = 0u; index < exports->NumberOfNames; ++index) {
            uint32_t name_rva = pe_read_u32_unaligned(name_bytes + index * 4u);
            uint16_t function_index =
                (uint16_t)ordinal_bytes[index * 2u] |
                ((uint16_t)ordinal_bytes[index * 2u + 1u] << 8u);
            if (function_index >= exports->NumberOfFunctions ||
                pe_validate_file_string(view, name_rva, 0u, 1) != PE_OK) {
                return PE_ERR_EXPORT;
            }
        }
    }
    for (index = 0u; index < exports->NumberOfFunctions; ++index) {
        uint32_t function_rva =
            pe_read_u32_unaligned(function_bytes + index * 4u);
        if (function_rva == 0u) continue;
        if (function_rva >= directory->VirtualAddress &&
            function_rva < directory_end) {
            if (pe_validate_file_string(view, function_rva, 0u, 1) != PE_OK) {
                return PE_ERR_EXPORT;
            }
        } else if (!pe_u32_range_ok(function_rva, 1u, view->image_size) ||
                   !pe_view_rva_has_flags(view, function_rva, 1u,
                                          PE_SCN_MEM_READ)) {
            return PE_ERR_EXPORT;
        }
    }
    return PE_OK;
}

static int pe_validate_relocation_directory(const PeImageView* view) {
    const PeDataDirectory* directory;
    const uint8_t* bytes;
    uint32_t cursor = 0u;
    if (!view || view->directory_count <= PE_DIR_BASERELOC) return PE_OK;
    directory = &view->directories[PE_DIR_BASERELOC];
    if (directory->VirtualAddress == 0u) return PE_OK;
    if (view->file_header->Characteristics & PE_CHAR_RELOCS_STRIPPED) {
        return PE_ERR_RELOCATION;
    }
    bytes = pe_view_rva_to_file(view, directory->VirtualAddress,
                                directory->Size, NULL);
    if (!bytes) return PE_ERR_RELOCATION;
    while (cursor < directory->Size) {
        uint32_t page_rva;
        uint32_t block_size;
        uint32_t entry_count;
        uint32_t entry_index;
        if (directory->Size - cursor < sizeof(PeBaseRelocation)) {
            return PE_ERR_RELOCATION;
        }
        page_rva = pe_read_u32_unaligned(bytes + cursor);
        block_size = pe_read_u32_unaligned(bytes + cursor + 4u);
        if (block_size < sizeof(PeBaseRelocation) || (block_size & 1u) != 0u ||
            block_size > directory->Size - cursor) {
            return PE_ERR_RELOCATION;
        }
        entry_count = (block_size - (uint32_t)sizeof(PeBaseRelocation)) / 2u;
        for (entry_index = 0u; entry_index < entry_count; ++entry_index) {
            uint32_t entry_offset = cursor + (uint32_t)sizeof(PeBaseRelocation) +
                                    entry_index * 2u;
            uint16_t entry = (uint16_t)bytes[entry_offset] |
                             ((uint16_t)bytes[entry_offset + 1u] << 8u);
            uint32_t type = entry >> 12u;
            uint32_t target_rva;
            uint32_t width;
            if (type == PE_REL_BASED_ABSOLUTE) continue;
            if (view->is_64bit) {
                if (type != PE_REL_BASED_DIR64) return PE_ERR_RELOCATION;
                width = 8u;
            } else {
                if (type == PE_REL_BASED_HIGHLOW) width = 4u;
                else if (type == PE_REL_BASED_HIGH || type == PE_REL_BASED_LOW) width = 2u;
                else return PE_ERR_RELOCATION;
            }
            if (page_rva > UINT32_MAX - (entry & 0x0fffu)) return PE_ERR_RELOCATION;
            target_rva = page_rva + (entry & 0x0fffu);
            if (!pe_u32_range_ok(target_rva, width, view->image_size)) {
                return PE_ERR_RELOCATION;
            }
        }
        cursor += block_size;
    }
    return cursor == directory->Size ? PE_OK : PE_ERR_RELOCATION;
}

int pe_validate_image(const void* data, size_t size, PeImageView* out_view) {
    PeImageView view;
    const uint8_t* file = (const uint8_t*)data;
    size_t pe_offset;
    size_t file_header_offset;
    size_t optional_offset;
    size_t section_table_offset;
    size_t optional_base_size;
    uint16_t optional_magic;
    uint32_t section_index;
    uint32_t aligned_headers;
    if (!data || !out_view) return PE_ERR_NULL;
    pe_memset(&view, 0, sizeof(view));
    if (size < sizeof(PeDosHeader)) return PE_ERR_NOT_PE;
    view.file = file;
    view.file_size = size;
    view.dos_header = (const PeDosHeader*)file;
    if (view.dos_header->e_magic != PE_DOS_MAGIC) return PE_ERR_NOT_PE;
    pe_offset = view.dos_header->e_lfanew;
    if (!pe_size_range_ok(pe_offset, 4u + sizeof(PeFileHeader), size)) {
        return PE_ERR_BOUNDS;
    }
    if (pe_read_u32_unaligned(file + pe_offset) != PE_SIGNATURE) return PE_ERR_NOT_PE;
    file_header_offset = pe_offset + 4u;
    view.file_header = (const PeFileHeader*)(file + file_header_offset);
    if (view.file_header->NumberOfSections == 0u ||
        view.file_header->NumberOfSections > PE_MAX_SECTIONS ||
        (view.file_header->Characteristics & PE_CHAR_EXECUTABLE_IMAGE) == 0u) {
        return PE_ERR_POLICY;
    }
    optional_offset = file_header_offset + sizeof(PeFileHeader);
    if (view.file_header->SizeOfOptionalHeader < sizeof(uint16_t) ||
        !pe_size_range_ok(optional_offset,
                          view.file_header->SizeOfOptionalHeader, size)) {
        return PE_ERR_BOUNDS;
    }
    optional_magic = (uint16_t)file[optional_offset] |
                     ((uint16_t)file[optional_offset + 1u] << 8u);
    view.optional_header = file + optional_offset;
    if (optional_magic == PE_OPT_MAGIC_64) {
        const PeOptionalHeader64* optional =
            (const PeOptionalHeader64*)view.optional_header;
        optional_base_size = offsetof(PeOptionalHeader64, DataDirectory);
        if (view.file_header->Machine != PE_MACHINE_AMD64 ||
            view.file_header->SizeOfOptionalHeader < optional_base_size) {
            return PE_ERR_UNSUPPORTED;
        }
        view.is_64bit = 1u;
        view.entry_rva = optional->AddressOfEntryPoint;
        view.preferred_base = optional->ImageBase;
        view.image_size = optional->SizeOfImage;
        view.header_size = optional->SizeOfHeaders;
        view.section_alignment = optional->SectionAlignment;
        view.file_alignment = optional->FileAlignment;
        view.subsystem = optional->Subsystem;
        view.directory_count = optional->NumberOfRvaAndSizes;
        view.directories = optional->DataDirectory;
    } else if (optional_magic == PE_OPT_MAGIC_32) {
        const PeOptionalHeader32* optional =
            (const PeOptionalHeader32*)view.optional_header;
        optional_base_size = offsetof(PeOptionalHeader32, DataDirectory);
        if (view.file_header->Machine != PE_MACHINE_I386 ||
            view.file_header->SizeOfOptionalHeader < optional_base_size) {
            return PE_ERR_UNSUPPORTED;
        }
        view.entry_rva = optional->AddressOfEntryPoint;
        view.preferred_base = optional->ImageBase;
        view.image_size = optional->SizeOfImage;
        view.header_size = optional->SizeOfHeaders;
        view.section_alignment = optional->SectionAlignment;
        view.file_alignment = optional->FileAlignment;
        view.subsystem = optional->Subsystem;
        view.directory_count = optional->NumberOfRvaAndSizes;
        view.directories = optional->DataDirectory;
    } else {
        return PE_ERR_UNSUPPORTED;
    }
    if (view.directory_count > PE_NUM_DATA_DIRS ||
        view.file_header->SizeOfOptionalHeader < optional_base_size +
            (size_t)view.directory_count * sizeof(PeDataDirectory)) {
        return PE_ERR_BOUNDS;
    }
    if (!pe_is_power_of_two_u32(view.file_alignment) ||
        view.file_alignment < 512u || view.file_alignment > 65536u ||
        !pe_is_power_of_two_u32(view.section_alignment) ||
        view.section_alignment < view.file_alignment ||
        view.image_size == 0u || view.image_size > PE_MAX_IMAGE_SIZE ||
        view.header_size == 0u || view.header_size > view.image_size ||
        view.header_size > size ||
        (view.image_size & (view.section_alignment - 1u)) != 0u ||
        (view.header_size & (view.file_alignment - 1u)) != 0u) {
        return PE_ERR_POLICY;
    }
    section_table_offset = optional_offset + view.file_header->SizeOfOptionalHeader;
    if (!pe_size_range_ok(section_table_offset,
                          (size_t)view.file_header->NumberOfSections *
                              sizeof(PeSectionHeader), size) ||
        section_table_offset +
            (size_t)view.file_header->NumberOfSections * sizeof(PeSectionHeader) >
                view.header_size) {
        return PE_ERR_BOUNDS;
    }
    view.sections = (const PeSectionHeader*)(file + section_table_offset);
    if (pe_align_up_u32(view.header_size, view.section_alignment,
                        &aligned_headers) != 0) return PE_ERR_POLICY;
    for (section_index = 0u; section_index < view.file_header->NumberOfSections;
         ++section_index) {
        const PeSectionHeader* section = &view.sections[section_index];
        uint32_t span = section->VirtualSize > section->SizeOfRawData
            ? section->VirtualSize : section->SizeOfRawData;
        uint32_t aligned_span;
        uint32_t other_index;
        if (span == 0u || section->VirtualAddress < aligned_headers ||
            (section->VirtualAddress & (view.section_alignment - 1u)) != 0u ||
            pe_align_up_u32(span, view.section_alignment, &aligned_span) != 0 ||
            !pe_u32_range_ok(section->VirtualAddress, aligned_span,
                             view.image_size) ||
            ((section->Characteristics & (PE_SCN_MEM_WRITE | PE_SCN_MEM_EXECUTE)) ==
             (PE_SCN_MEM_WRITE | PE_SCN_MEM_EXECUTE))) {
            return PE_ERR_POLICY;
        }
        if (section->SizeOfRawData != 0u) {
            if (section->PointerToRawData < view.header_size ||
                (section->PointerToRawData & (view.file_alignment - 1u)) != 0u ||
                (section->SizeOfRawData & (view.file_alignment - 1u)) != 0u ||
                !pe_size_range_ok(section->PointerToRawData,
                                  section->SizeOfRawData, size)) {
                return PE_ERR_BOUNDS;
            }
        } else if (section->PointerToRawData != 0u) {
            return PE_ERR_POLICY;
        }
        for (other_index = 0u; other_index < section_index; ++other_index) {
            const PeSectionHeader* other = &view.sections[other_index];
            uint32_t other_span = other->VirtualSize > other->SizeOfRawData
                ? other->VirtualSize : other->SizeOfRawData;
            uint32_t other_aligned;
            if (pe_align_up_u32(other_span, view.section_alignment,
                                &other_aligned) != 0) return PE_ERR_OVERLAP;
            if (section->VirtualAddress < other->VirtualAddress + other_aligned &&
                other->VirtualAddress < section->VirtualAddress + aligned_span) {
                return PE_ERR_OVERLAP;
            }
            if (section->SizeOfRawData != 0u && other->SizeOfRawData != 0u &&
                section->PointerToRawData < other->PointerToRawData + other->SizeOfRawData &&
                other->PointerToRawData < section->PointerToRawData + section->SizeOfRawData) {
                return PE_ERR_OVERLAP;
            }
        }
    }
    view.is_dll = (view.file_header->Characteristics & PE_CHAR_DLL) ? 1u : 0u;
    if (view.entry_rva == 0u) {
        if (!view.is_dll) return PE_ERR_POLICY;
    } else if (!pe_u32_range_ok(view.entry_rva, 1u, view.image_size) ||
               !pe_view_rva_has_flags(&view, view.entry_rva, 1u,
                                      PE_SCN_MEM_EXECUTE)) {
        return PE_ERR_POLICY;
    }
    for (section_index = 0u; section_index < view.directory_count;
         ++section_index) {
        const PeDataDirectory* directory = &view.directories[section_index];
        if ((directory->VirtualAddress == 0u) != (directory->Size == 0u)) {
            return PE_ERR_BOUNDS;
        }
        if (directory->VirtualAddress == 0u) continue;
        if (section_index == PE_DIR_SECURITY) {
            if (!pe_size_range_ok(directory->VirtualAddress, directory->Size,
                                  size)) return PE_ERR_BOUNDS;
        } else if (!pe_u32_range_ok(directory->VirtualAddress, directory->Size,
                                    view.image_size) ||
                   !pe_view_rva_to_file(&view, directory->VirtualAddress,
                                        directory->Size, NULL)) {
            return PE_ERR_BOUNDS;
        }
    }
    view.has_tls = (view.directory_count > PE_DIR_TLS &&
                    view.directories[PE_DIR_TLS].VirtualAddress != 0u) ? 1u : 0u;
    view.has_delay_imports = (view.directory_count > PE_DIR_DELAY_IMPORT &&
                             view.directories[PE_DIR_DELAY_IMPORT].VirtualAddress != 0u)
        ? 1u : 0u;
    if (view.has_tls) {
        uint32_t required = view.is_64bit ? (uint32_t)sizeof(PeTlsDirectory64)
                                          : (uint32_t)sizeof(PeTlsDirectory32);
        if (view.directories[PE_DIR_TLS].Size < required) return PE_ERR_BOUNDS;
    }
    {
        int result = pe_validate_export_directory(&view);
        if (result != PE_OK) return result;
        result = pe_validate_import_directory(&view);
        if (result != PE_OK) return result;
        result = pe_validate_relocation_directory(&view);
        if (result != PE_OK) return result;
    }
    *out_view = view;
    return PE_OK;
}

/* ═══════════════════════════════════════════════════════════════
 * PE 検証関数
 * ═══════════════════════════════════════════════════════════════*/

/* Check if data is a valid PE file */
int pe_is_pe(const void* data, size_t size) {
    if (!data || size < sizeof(PeDosHeader)) return 0;

    const PeDosHeader* dos = (const PeDosHeader*)data;
    if (dos->e_magic != PE_DOS_MAGIC) return 0;

    /* Check PE signature location */
    if (!pe_size_range_ok(dos->e_lfanew, 4u, size)) return 0;
    return pe_read_u32_unaligned((const uint8_t*)data + dos->e_lfanew) ==
        PE_SIGNATURE;
}

/* Check if PE is 64-bit */
int pe_is_64bit(const void* data, size_t size) {
    PeImageView view;
    return pe_validate_image(data, size, &view) == PE_OK && view.is_64bit;
}

/* Check if PE is a DLL */
int pe_is_dll(const void* data, size_t size) {
    PeImageView view;
    return pe_validate_image(data, size, &view) == PE_OK && view.is_dll;
}

/* Get required memory size for PE */
uint32_t pe_get_image_size(const void* data, size_t size) {
    PeImageView view;
    return pe_validate_image(data, size, &view) == PE_OK ? view.image_size : 0u;
}

/* Get machine type */
uint16_t pe_get_machine(const void* data, size_t size) {
    PeImageView view;
    return pe_validate_image(data, size, &view) == PE_OK
        ? view.file_header->Machine : PE_MACHINE_UNKNOWN;
}

/* Get subsystem type */
uint16_t pe_get_subsystem(const void* data, size_t size) {
    PeImageView view;
    return pe_validate_image(data, size, &view) == PE_OK
        ? view.subsystem : PE_SUBSYSTEM_UNKNOWN;
}

/* ═══════════════════════════════════════════════════════════════
 * PE ロード関数
 * ═══════════════════════════════════════════════════════════════*/

/* Load PE file - 64-bit capable version */
int pe_load64_ex_at(const void* data, size_t size,
                    void* load_addr, uint64_t virtual_base, PeLoadInfo* info,
                    PeImportResolver import_resolver,
                    void* import_resolver_ctx,
                    uint32_t load_flags) {
    PeImageView view;
    PeDataDirectory empty_directory;
    int validation_result;
    const uint8_t* file = (const uint8_t*)data;
    uint8_t* mem = (uint8_t*)load_addr;
    const PeFileHeader* coff;
    const PeSectionHeader* sections;
    const PeDataDirectory* data_dirs;
    uint32_t entry_rva;
    uint64_t preferred_base;
    uint32_t image_size;
    uint32_t header_size;
    uint16_t subsystem;
    int is_64bit;

    if (info) pe_memset(info, 0, sizeof(*info));
    if (!data || !load_addr || virtual_base == 0u) return PE_ERR_NULL;
    if ((load_flags & ~PE_LOAD_VALID_FLAGS) != 0u) return PE_ERR_POLICY;
    validation_result = pe_validate_image(data, size, &view);
    if (validation_result != PE_OK) {
        PE_DEBUG_PRINT("[PE] Admission validation rejected image\n");
        return validation_result;
    }
    if (view.has_delay_imports &&
        (load_flags & PE_LOAD_DEFER_DELAY_IMPORTS) == 0u) {
        return PE_ERR_UNSUPPORTED;
    }
    if (view.import_symbol_count != 0u && !import_resolver) return PE_ERR_IMPORT;

    pe_memset(&empty_directory, 0, sizeof(empty_directory));
    coff = view.file_header;
    sections = view.sections;
    data_dirs = view.directories;
    entry_rva = view.entry_rva;
    preferred_base = view.preferred_base;
    image_size = view.image_size;
    header_size = view.header_size;
    subsystem = view.subsystem;
    is_64bit = view.is_64bit ? 1 : 0;
    if (virtual_base > UINT64_MAX - image_size ||
        (!is_64bit &&
         (virtual_base > UINT32_MAX ||
          virtual_base + image_size > UINT64_C(0x100000000)))) {
        return PE_ERR_BOUNDS;
    }

    PE_DEBUG_PRINT(is_64bit ? "[PE64] Loading admitted PE32+ image\n"
                            : "[PE32] Loading admitted PE32 image\n");

    /* Zero out destination memory */
    pe_memset(mem, 0, image_size);

    /* Copy headers */
    pe_memcpy(mem, file, header_size);
    PE_DEBUG_PRINT("[PE] Headers copied (");
    PE_DEBUG_HEX(header_size);
    PE_DEBUG_PRINT(" bytes)\n");

    /* Load sections */
    PE_DEBUG_PRINT("[PE] Loading ");
    PE_DEBUG_HEX(coff->NumberOfSections);
    PE_DEBUG_PRINT(" sections\n");

    for (int i = 0; i < coff->NumberOfSections; i++) {
        const PeSectionHeader* sec = &sections[i];

        if (sec->SizeOfRawData == 0 || sec->PointerToRawData == 0) {
            /* BSS or virtual section */
            continue;
        }

        uint32_t copy_size = sec->SizeOfRawData;

        /* Copy section data */
        pe_memcpy(mem + sec->VirtualAddress,
                  file + sec->PointerToRawData,
                  copy_size);

        PE_DEBUG_PRINT("  Section: ");
        /* Name would be nice but complex in inline */
        PE_DEBUG_PRINT("@ RVA 0x");
        PE_DEBUG_HEX(sec->VirtualAddress);
        PE_DEBUG_PRINT(" size 0x");
        PE_DEBUG_HEX(copy_size);
        PE_DEBUG_PRINT("\n");
    }

    /* Apply base relocations if loading at different address */
    uint64_t actual_base = virtual_base;
    uint64_t distance;
    int64_t delta;
    if (actual_base >= preferred_base) {
        distance = actual_base - preferred_base;
        if (distance > (uint64_t)INT64_MAX) return PE_ERR_RELOCATION;
        delta = (int64_t)distance;
    } else {
        distance = preferred_base - actual_base;
        if (distance > (uint64_t)INT64_MAX) return PE_ERR_RELOCATION;
        delta = -(int64_t)distance;
    }

    if (delta != 0) {
        const PeDataDirectory* reloc_dir = view.directory_count > PE_DIR_BASERELOC
            ? &data_dirs[PE_DIR_BASERELOC] : &empty_directory;

        if (reloc_dir->VirtualAddress != 0 && reloc_dir->Size > 0) {
            PE_DEBUG_PRINT("[PE] Applying relocations (delta=0x");
            PE_DEBUG_HEX((uint64_t)(delta >= 0 ? delta : -delta));
            PE_DEBUG_PRINT(")\n");

            uint8_t* reloc_ptr = mem + reloc_dir->VirtualAddress;
            uint8_t* reloc_end = reloc_ptr + reloc_dir->Size;

            while (reloc_ptr < reloc_end) {
                PeBaseRelocation* block = (PeBaseRelocation*)reloc_ptr;

                if (block->SizeOfBlock == 0) break;
                if (block->SizeOfBlock < sizeof(PeBaseRelocation)) break;

                uint32_t num_entries =
                    (block->SizeOfBlock - sizeof(PeBaseRelocation)) / 2;
                uint16_t* entries = (uint16_t*)(reloc_ptr + sizeof(PeBaseRelocation));

                for (uint32_t i = 0; i < num_entries; i++) {
                    uint16_t entry = entries[i];
                    uint32_t type = entry >> 12;
                    uint32_t offset = entry & 0x0FFF;

                    if (type == PE_REL_BASED_ABSOLUTE) {
                        /* Skip padding */
                        continue;
                    }

                    uint8_t* target = mem + block->VirtualAddress + offset;

                    if (is_64bit && type == PE_REL_BASED_DIR64) {
                        *(uint64_t*)target += delta;
                    } else if (type == PE_REL_BASED_HIGHLOW) {
                        *(uint32_t*)target += (uint32_t)delta;
                    } else if (type == PE_REL_BASED_HIGH) {
                        *(uint16_t*)target += (uint16_t)((delta >> 16) & 0xFFFF);
                    } else if (type == PE_REL_BASED_LOW) {
                        *(uint16_t*)target += (uint16_t)(delta & 0xFFFF);
                    }
                }

                reloc_ptr += block->SizeOfBlock;
            }

            PE_DEBUG_PRINT("[PE] Relocations applied\n");
        } else {
            PE_DEBUG_PRINT("[PE] Relocation required but directory is absent\n");
            return PE_ERR_RELOCATION;
        }
    }

    /* Resolve imports (IAT patching) */
    const PeDataDirectory* import_dir = view.directory_count > PE_DIR_IMPORT
        ? &data_dirs[PE_DIR_IMPORT] : &empty_directory;
    uint32_t unresolved_imports = 0;
    if (import_dir->VirtualAddress != 0 && import_dir->Size > 0) {
        uint32_t descriptor_index;
        PE_DEBUG_PRINT("[PE] Resolving imports\n");

        PeImportDescriptor* imp = (PeImportDescriptor*)(mem + import_dir->VirtualAddress);

        for (descriptor_index = 0u;
             descriptor_index < view.import_descriptor_count;
             ++descriptor_index, ++imp) {
            char* dll_name = (char*)(mem + imp->Name);
            PE_DEBUG_PRINT("[PE] Import DLL: ");
            /* Can't easily print string in header-only, just log presence */
            PE_DEBUG_HEX(imp->Name);
            PE_DEBUG_PRINT("\n");

            /* Get IAT and INT (Import Name Table) */
            uint32_t iat_rva = imp->FirstThunk;
            uint32_t int_rva = imp->OriginalFirstThunk;
            if (int_rva == 0) int_rva = iat_rva;

            if (is_64bit) {
                uint64_t* iat = (uint64_t*)(mem + iat_rva);
                uint64_t* int_entry = (uint64_t*)(mem + int_rva);

                while (*int_entry != 0) {
                    void* resolved = NULL;

                    if (*int_entry & PE_ORDINAL_FLAG64) {
                        /* Import by ordinal */
                        uint16_t ordinal = (uint16_t)(*int_entry & 0xFFFF);
                        if (import_resolver) {
                            resolved = import_resolver(import_resolver_ctx, dll_name,
                                                       NULL, ordinal, 1);
                        }
                        PE_DEBUG_PRINT("[PE] Ordinal import: ");
                        PE_DEBUG_HEX(ordinal);
                        PE_DEBUG_PRINT("\n");
                    } else {
                        /* Import by name */
                        PeImportByName* ibn = (PeImportByName*)(mem + (uint32_t)*int_entry);
                        if (import_resolver) {
                            resolved = import_resolver(import_resolver_ctx, dll_name,
                                                       ibn->Name, 0, 0);
                        }
                    }

                    /* Write resolved address to IAT */
                    if (resolved) {
                        *iat = (uint64_t)(uintptr_t)resolved;
                    } else {
                        unresolved_imports++;
                    }

                    iat++;
                    int_entry++;
                }
            } else {
                uint32_t* iat = (uint32_t*)(mem + iat_rva);
                uint32_t* int_entry = (uint32_t*)(mem + int_rva);

                while (*int_entry != 0) {
                    void* resolved = NULL;

                    if (*int_entry & PE_ORDINAL_FLAG32) {
                        uint16_t ordinal = (uint16_t)(*int_entry & 0xFFFF);
                        if (import_resolver) {
                            resolved = import_resolver(import_resolver_ctx, dll_name,
                                                       NULL, ordinal, 1);
                        }
                        PE_DEBUG_PRINT("[PE] Ordinal import: ");
                        PE_DEBUG_HEX(ordinal);
                        PE_DEBUG_PRINT("\n");
                    } else {
                        PeImportByName* ibn = (PeImportByName*)(mem + *int_entry);
                        if (import_resolver) {
                            resolved = import_resolver(import_resolver_ctx, dll_name,
                                                       ibn->Name, 0, 0);
                        }
                    }

                    if (resolved &&
                        (uintptr_t)resolved <= (uintptr_t)UINT32_MAX) {
                        *iat = (uint32_t)(uintptr_t)resolved;
                    } else {
                        unresolved_imports++;
                    }

                    iat++;
                    int_entry++;
                }
            }
        }

        PE_DEBUG_PRINT("[PE] Imports processed\n");
    }

    if (unresolved_imports > 0u) {
        if (info) info->unresolved_imports = unresolved_imports;
        return PE_ERR_IMPORT;
    }

    /* PE mapping is data-only.  TLS allocation and callbacks belong to the
     * RinNT user-space loader after dependencies, PEB and TEB are ready. */
    if (view.has_tls) PE_DEBUG_PRINT("[PE] TLS initialization deferred to RinNT\n");

    /* Fill in load info */
    if (info) {
        info->entry_point = entry_rva != 0u
                                ? actual_base + entry_rva
                                : 0u;
        info->image_base = actual_base;
        info->preferred_base = preferred_base;
        info->image_size = image_size;
        info->header_size = header_size;
        info->machine = coff->Machine;
        info->subsystem = subsystem;
        info->characteristics = coff->Characteristics;
        info->is_64bit = is_64bit ? 1 : 0;
        info->is_dll = (coff->Characteristics & PE_CHAR_DLL) ? 1 : 0;
        info->has_tls = view.has_tls;
        info->has_delay_imports = view.has_delay_imports;
        info->unresolved_imports = unresolved_imports;
        info->import_count = view.import_symbol_count;
        if (view.has_tls) {
            info->tls_directory_rva = data_dirs[PE_DIR_TLS].VirtualAddress;
            info->tls_directory_size = data_dirs[PE_DIR_TLS].Size;
        }
    }

    PE_DEBUG_PRINT("[PE] Load complete. Entry: 0x");
    PE_DEBUG_HEX(actual_base + entry_rva);
    PE_DEBUG_PRINT("\n");

    return PE_OK;
}

int pe_load64_ex(const void* data, size_t size,
                 void* load_addr, PeLoadInfo* info,
                 PeImportResolver import_resolver,
                 void* import_resolver_ctx,
                 uint32_t load_flags) {
    return pe_load64_ex_at(data, size, load_addr,
                           (uint64_t)(uintptr_t)load_addr, info,
                           import_resolver, import_resolver_ctx, load_flags);
}

int pe_load64(const void* data, size_t size,
              void* load_addr, PeLoadInfo* info,
              PeImportResolver import_resolver,
              void* import_resolver_ctx) {
    return pe_load64_ex(data, size, load_addr, info, import_resolver,
                        import_resolver_ctx, 0u);
}

/* Load PE file - 32-bit version */
int pe_load(const void* data, size_t size,
                          void* load_addr, PeLoadInfo32* info) {
    PeLoadInfo info64;
    int ret = pe_load64(data, size, load_addr, &info64, NULL, NULL);

    if (ret == PE_OK && info) {
        info->entry_point = (uint32_t)info64.entry_point;
        info->image_base = (uint32_t)info64.image_base;
        info->image_size = info64.image_size;
        info->subsystem = info64.subsystem;
        info->flags = (info64.is_dll ? 0x01 : 0) |
                      (info64.is_64bit ? 0x02 : 0);
    }

    return ret;
}

/* ═══════════════════════════════════════════════════════════════
 * PE ユーティリティ関数
 * ═══════════════════════════════════════════════════════════════*/

/* Check if GUI application */
int pe_is_gui(const void* data, size_t size) {
    return pe_get_subsystem(data, size) == PE_SUBSYSTEM_WINDOWS_GUI;
}

/* Check if Console application */
int pe_is_console(const void* data, size_t size) {
    return pe_get_subsystem(data, size) == PE_SUBSYSTEM_WINDOWS_CUI;
}

/* Get error string */
const char* pe_error_string(int error) {
    switch (error) {
        case PE_OK:             return "OK";
        case PE_ERR_NULL:       return "Null pointer";
        case PE_ERR_NOT_PE:     return "Not a valid PE file";
        case PE_ERR_UNSUPPORTED: return "Unsupported PE format";
        case PE_ERR_SIZE:       return "Invalid size";
        case PE_ERR_LOAD:       return "Load failed";
        case PE_ERR_BOUNDS:     return "PE range is outside the file or image";
        case PE_ERR_OVERLAP:    return "PE sections overlap";
        case PE_ERR_IMPORT:     return "PE imports are invalid or unresolved";
        case PE_ERR_RELOCATION: return "PE relocation table is invalid or unavailable";
        case PE_ERR_POLICY:     return "PE violates RinNT admission policy";
        case PE_ERR_EXPORT:     return "PE export table is invalid or unsupported";
        default:                return "Unknown error";
    }
}

/* ═══════════════════════════════════════════════════════════════
 * PE エクスポート検索
 * ═══════════════════════════════════════════════════════════════*/

/* 文字列比較 (strcmp) */
static inline int pe_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

/* ロード済みイメージからエクスポートディレクトリを取得 */
static inline PeExportDirectory* pe_get_export_directory(
    void* image_base, uint32_t image_size, PeDataDirectory** out_directory) {
    uint8_t* mem = (uint8_t*)image_base;
    const PeDosHeader* dos;
    const PeFileHeader* coff;
    const PeDataDirectory* export_dir;
    size_t optional_offset;
    uint16_t optional_magic;
    uint32_t declared_size;
    uint32_t directory_count;
    if (out_directory) *out_directory = NULL;
    if (!mem || image_size < sizeof(PeDosHeader) ||
        image_size > PE_MAX_IMAGE_SIZE) return NULL;
    dos = (const PeDosHeader*)mem;
    if (dos->e_magic != PE_DOS_MAGIC ||
        !pe_size_range_ok(dos->e_lfanew, 4u + sizeof(PeFileHeader), image_size) ||
        pe_read_u32_unaligned(mem + dos->e_lfanew) != PE_SIGNATURE) return NULL;
    coff = (const PeFileHeader*)(mem + dos->e_lfanew + 4u);
    optional_offset = (size_t)dos->e_lfanew + 4u + sizeof(PeFileHeader);
    if (!pe_size_range_ok(optional_offset, coff->SizeOfOptionalHeader, image_size) ||
        coff->SizeOfOptionalHeader < sizeof(uint16_t)) return NULL;
    optional_magic = (uint16_t)mem[optional_offset] |
                     ((uint16_t)mem[optional_offset + 1u] << 8u);
    if (optional_magic == PE_OPT_MAGIC_64) {
        const PeOptionalHeader64* optional =
            (const PeOptionalHeader64*)(mem + optional_offset);
        size_t required = offsetof(PeOptionalHeader64, DataDirectory) +
                          sizeof(PeDataDirectory);
        if (coff->Machine != PE_MACHINE_AMD64 ||
            coff->SizeOfOptionalHeader < required) return NULL;
        declared_size = optional->SizeOfImage;
        directory_count = optional->NumberOfRvaAndSizes;
        export_dir = &optional->DataDirectory[PE_DIR_EXPORT];
    } else if (optional_magic == PE_OPT_MAGIC_32) {
        const PeOptionalHeader32* optional =
            (const PeOptionalHeader32*)(mem + optional_offset);
        size_t required = offsetof(PeOptionalHeader32, DataDirectory) +
                          sizeof(PeDataDirectory);
        if (coff->Machine != PE_MACHINE_I386 ||
            coff->SizeOfOptionalHeader < required) return NULL;
        declared_size = optional->SizeOfImage;
        directory_count = optional->NumberOfRvaAndSizes;
        export_dir = &optional->DataDirectory[PE_DIR_EXPORT];
    } else {
        return NULL;
    }
    if (declared_size == 0u || declared_size > image_size ||
        directory_count <= PE_DIR_EXPORT || directory_count > PE_NUM_DATA_DIRS ||
        export_dir->VirtualAddress == 0u ||
        export_dir->Size < sizeof(PeExportDirectory) ||
        !pe_u32_range_ok(export_dir->VirtualAddress, export_dir->Size,
                         declared_size)) return NULL;
    if (out_directory) *out_directory = (PeDataDirectory*)export_dir;
    return (PeExportDirectory*)(mem + export_dir->VirtualAddress);
}

static int pe_loaded_string_valid(const uint8_t* mem, uint32_t image_size,
                                  uint32_t rva) {
    uint32_t available;
    uint32_t index;
    if (!mem || rva >= image_size) return 0;
    available = image_size - rva;
    if (available > 4096u) available = 4096u;
    for (index = 0u; index < available; ++index) {
        if (mem[rva + index] == 0u) return index != 0u;
    }
    return 0;
}

/* 名前でエクスポートを検索 */
void* pe_get_export(void* image_base, uint32_t image_size, const char* name) {
    uint8_t* mem = (uint8_t*)image_base;
    PeDataDirectory* directory;
    PeExportDirectory* exports;
    uint32_t index;
    if (!name) return NULL;
    exports = pe_get_export_directory(image_base, image_size, &directory);
    if (!exports || exports->NumberOfFunctions > PE_MAX_EXPORT_SYMBOLS ||
        exports->NumberOfNames > exports->NumberOfFunctions ||
        exports->AddressOfFunctions == 0u ||
        !pe_u32_range_ok(exports->AddressOfFunctions,
                         exports->NumberOfFunctions * 4u, image_size)) {
        return NULL;
    }
    if (exports->NumberOfNames != 0u &&
        (exports->AddressOfNames == 0u ||
         exports->AddressOfNameOrdinals == 0u ||
         !pe_u32_range_ok(exports->AddressOfNames,
                          exports->NumberOfNames * 4u, image_size) ||
         !pe_u32_range_ok(exports->AddressOfNameOrdinals,
                          exports->NumberOfNames * 2u, image_size))) {
        return NULL;
    }
    for (index = 0u; index < exports->NumberOfNames; ++index) {
        uint32_t name_rva = pe_read_u32_unaligned(
            mem + exports->AddressOfNames + index * 4u);
        const uint8_t* ordinal_bytes =
            mem + exports->AddressOfNameOrdinals + index * 2u;
        uint16_t function_index = (uint16_t)ordinal_bytes[0] |
            ((uint16_t)ordinal_bytes[1] << 8u);
        if (function_index >= exports->NumberOfFunctions ||
            !pe_loaded_string_valid(mem, image_size, name_rva)) return NULL;
        if (pe_strcmp((const char*)(mem + name_rva), name) == 0) {
            uint32_t function_rva = pe_read_u32_unaligned(
                mem + exports->AddressOfFunctions + function_index * 4u);
            uint32_t directory_end = directory->VirtualAddress + directory->Size;
            if (function_rva == 0u || function_rva >= image_size ||
                (function_rva >= directory->VirtualAddress &&
                 function_rva < directory_end)) return NULL;
            return (void*)(mem + function_rva);
        }
    }
    return NULL;
}

/* オーディナルでエクスポートを検索 */
void* pe_get_export_by_ordinal(void* image_base, uint32_t image_size,
                               uint16_t ordinal) {
    uint8_t* mem = (uint8_t*)image_base;
    PeDataDirectory* directory;
    PeExportDirectory* exports =
        pe_get_export_directory(image_base, image_size, &directory);
    uint32_t index;
    uint32_t function_rva;
    uint32_t directory_end;
    if (!exports || exports->NumberOfFunctions > PE_MAX_EXPORT_SYMBOLS ||
        exports->Base > (uint32_t)ordinal || exports->AddressOfFunctions == 0u ||
        !pe_u32_range_ok(exports->AddressOfFunctions,
                         exports->NumberOfFunctions * 4u, image_size)) return NULL;
    index = (uint32_t)ordinal - exports->Base;
    if (index >= exports->NumberOfFunctions) return NULL;
    function_rva = pe_read_u32_unaligned(
        mem + exports->AddressOfFunctions + index * 4u);
    directory_end = directory->VirtualAddress + directory->Size;
    if (function_rva == 0u || function_rva >= image_size ||
        (function_rva >= directory->VirtualAddress &&
         function_rva < directory_end)) return NULL;
    return (void*)(mem + function_rva);
}

/* ═══════════════════════════════════════════════════════════════
 * PE DLL ライフサイクル
 * ═══════════════════════════════════════════════════════════════*/

/* DllMain signature */
typedef int (*PeDllMain)(void* hinstDLL, uint32_t fdwReason, void* lpvReserved);

static PeDllMain pe_get_dll_main(void* image_base, uint32_t image_size,
                                 int* out_status) {
    uint8_t* mem = (uint8_t*)image_base;
    const PeDosHeader* dos;
    const PeFileHeader* coff;
    const PeSectionHeader* sections;
    size_t optional_offset;
    size_t section_table_offset;
    uint16_t optional_magic;
    uint32_t declared_size;
    uint32_t header_size;
    uint32_t entry_rva;
    uint32_t index;
    if (out_status) *out_status = 0;
    if (!mem || !out_status || image_size < sizeof(PeDosHeader) ||
        image_size > PE_MAX_IMAGE_SIZE) return NULL;
    dos = (const PeDosHeader*)mem;
    if (dos->e_magic != PE_DOS_MAGIC ||
        !pe_size_range_ok(dos->e_lfanew, 4u + sizeof(PeFileHeader), image_size) ||
        pe_read_u32_unaligned(mem + dos->e_lfanew) != PE_SIGNATURE) return NULL;
    coff = (const PeFileHeader*)(mem + dos->e_lfanew + 4u);
    if (coff->NumberOfSections == 0u ||
        coff->NumberOfSections > PE_MAX_SECTIONS) return NULL;
    optional_offset = (size_t)dos->e_lfanew + 4u + sizeof(PeFileHeader);
    if (!pe_size_range_ok(optional_offset, coff->SizeOfOptionalHeader,
                          image_size) ||
        coff->SizeOfOptionalHeader < sizeof(uint16_t)) return NULL;
    optional_magic = (uint16_t)mem[optional_offset] |
                     ((uint16_t)mem[optional_offset + 1u] << 8u);
    if (optional_magic == PE_OPT_MAGIC_64) {
        const PeOptionalHeader64* optional =
            (const PeOptionalHeader64*)(mem + optional_offset);
        if (coff->Machine != PE_MACHINE_AMD64 ||
            coff->SizeOfOptionalHeader < offsetof(PeOptionalHeader64,
                                                  DataDirectory)) return NULL;
        declared_size = optional->SizeOfImage;
        header_size = optional->SizeOfHeaders;
        entry_rva = optional->AddressOfEntryPoint;
    } else if (optional_magic == PE_OPT_MAGIC_32) {
        const PeOptionalHeader32* optional =
            (const PeOptionalHeader32*)(mem + optional_offset);
        if (coff->Machine != PE_MACHINE_I386 ||
            coff->SizeOfOptionalHeader < offsetof(PeOptionalHeader32,
                                                  DataDirectory)) return NULL;
        declared_size = optional->SizeOfImage;
        header_size = optional->SizeOfHeaders;
        entry_rva = optional->AddressOfEntryPoint;
    } else {
        return NULL;
    }
    section_table_offset = optional_offset + coff->SizeOfOptionalHeader;
    if (declared_size == 0u || declared_size > image_size ||
        header_size == 0u || header_size > declared_size ||
        !pe_size_range_ok(section_table_offset,
                          (size_t)coff->NumberOfSections *
                              sizeof(PeSectionHeader), header_size)) return NULL;
    sections = (const PeSectionHeader*)(mem + section_table_offset);
    if (!(coff->Characteristics & PE_CHAR_DLL) || entry_rva == 0u) {
        *out_status = 1;
        return NULL;
    }
    for (index = 0u; index < coff->NumberOfSections; ++index) {
        const PeSectionHeader* section = &sections[index];
        uint32_t span = section->VirtualSize > section->SizeOfRawData
            ? section->VirtualSize : section->SizeOfRawData;
        if (!pe_u32_range_ok(section->VirtualAddress, span, declared_size)) {
            return NULL;
        }
        if (entry_rva >= section->VirtualAddress &&
            entry_rva - section->VirtualAddress < span &&
            (section->Characteristics & PE_SCN_MEM_EXECUTE)) {
            *out_status = 2;
            return (PeDllMain)(mem + entry_rva);
        }
    }
    return NULL;
}

/* DLL_PROCESS_ATTACH を呼び出す */
int pe_dll_attach(void* image_base, uint32_t image_size) {
    int status;
    PeDllMain dll_main = pe_get_dll_main(image_base, image_size, &status);
    if (status == 0) return 0;
    if (status == 1) return 1;
    PE_DEBUG_PRINT("[PE] Calling DllMain(ATTACH) at 0x");
    PE_DEBUG_HEX((uintptr_t)dll_main);
    PE_DEBUG_PRINT("\n");
    return dll_main(image_base, DLL_PROCESS_ATTACH, NULL);
}

/* DLL_PROCESS_DETACH を呼び出す */
int pe_dll_detach(void* image_base, uint32_t image_size) {
    int status;
    PeDllMain dll_main = pe_get_dll_main(image_base, image_size, &status);
    if (status == 0) return 0;
    if (status == 1) return 1;
    PE_DEBUG_PRINT("[PE] Calling DllMain(DETACH) at 0x");
    PE_DEBUG_HEX((uintptr_t)dll_main);
    PE_DEBUG_PRINT("\n");
    return dll_main(image_base, DLL_PROCESS_DETACH, NULL);
}

/* PE イメージのアンロード (メモリ解放) */
/* 注: メモリ解放関数は呼び出し側で実装する必要がある */
void pe_unload(void* image_base, uint32_t image_size,
                             void (*free_func)(void*, uint32_t)) {
    if (!image_base || !free_func) return;
    free_func(image_base, image_size);
}

#endif /* PE_LOADER_IMPLEMENTATION */

#endif /* PE_LOADER_H */
