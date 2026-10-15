// SPDX-License-Identifier: MIT
/*
 * RinFS - RinOS Native Filesystem ✿
 * FAT32代替の本格的なファイルシステム
 * 
 * 特徴:
 * - 64ビットファイルサイズ対応 (最大16EB)
 * - Unix風パーミッション
 * - シンボリックリンク/ハードリンク
 * - ディレクトリ階層
 * - ジャーナリング対応（オプション）
 * - 大きなファイルの効率的な管理（エクステント）
 */

#ifndef RINFS_H
#define RINFS_H

#include <stddef.h>
#include <stdint.h>

/* ═══════════════════════════════════════════════════════════════
 * RinFS Disk Layout
 * ═══════════════════════════════════════════════════════════════
 * 
 * Sector 0-1:    Superblock (1024 bytes)
 * Sector 2-N:    Block Bitmap (1 bit per block)
 * Sector N+1-M:  Inode Bitmap (1 bit per inode)
 * Sector M+1-P:  Inode Table (304 bytes per inode in deployed v1)
 * Sector P+1-...: Data Blocks
 * 
 * ═══════════════════════════════════════════════════════════════*/

/* Magic number: "RinFS✿" in little-endian */
#define RINFS_MAGIC         0x73466E52  /* "RnFs" */
#define RINFS_MAGIC2        0x00BF9CE2  /* "✿\0" UTF-8 flower */

/* Filesystem version */
#define RINFS_VERSION_MAJOR 1
#define RINFS_VERSION_MINOR 6

/* Compatible on-disk features. Older readers may ignore these safely. */
#define RINFS_FEATURE_COMPAT_RENAME_JOURNAL 0x00000001u
#define RINFS_FEATURE_COMPAT_DUAL_JOURNAL   0x00000002u

/* Incompatible on-disk features.  A reader that does not know one of these
 * must not reinterpret the same inode bytes with the old semantics. */
#define RINFS_FEATURE_INCOMPAT_NANO_TIMESTAMPS 0x00000001u
#define RINFS_FEATURE_INCOMPAT_CONTENT_VERSION64 0x00000002u
/* Enables reachable device/FIFO inodes. Character/block st_rdev is stored as
 * a little-endian uint32_t at i_reserved[24..27] (inode byte offsets 0xE0
 * through 0xE3).
 * Older kernels reject the volume instead of treating these bytes as zero. */
#define RINFS_FEATURE_INCOMPAT_SPECIAL_INODES 0x00000004u
/* The high d_file_type bit is a durable DELETE_ON_CLOSE dentry marker. */
#define RINFS_FEATURE_INCOMPAT_DELETE_ON_CLOSE 0x00000008u
#define RINFS_INODE_SPECIAL_DEVICE_OFFSET 24u
#define RINFS_FEATURE_INCOMPAT_SUPPORTED \
    (RINFS_FEATURE_INCOMPAT_NANO_TIMESTAMPS | \
     RINFS_FEATURE_INCOMPAT_CONTENT_VERSION64 | \
     RINFS_FEATURE_INCOMPAT_SPECIAL_INODES | \
     RINFS_FEATURE_INCOMPAT_DELETE_ON_CLOSE)

enum {
    RINFS_READ_ADVICE_NORMAL = 0,
    RINFS_READ_ADVICE_RANDOM = 1,
    RINFS_READ_ADVICE_SEQUENTIAL = 2
};

/* Internal descriptor flag enabling page-cache-bypassing aligned I/O. */
#define RINFS_O_DIRECT 0x0800

/* A content version is cache identity, not general inode metadata versioning.
 * Zero is deliberately untracked. A successful mutation clears only its own
 * transient precommit poison; poison inherited from an ambiguous failure is
 * lifetime-persistent and clears only when reclaim creates a new lifetime. */
#define RINFS_CONTENT_STATE_UNCERTAIN 0x00000001u
#define RINFS_CONTENT_STATE_MASK RINFS_CONTENT_STATE_UNCERTAIN
#define RINFS_CONTENT_TRACKING_RUNTIME_DISABLED 0x80000000u

/* Block and sector sizes */
#define RINFS_SECTOR_SIZE   512
#define RINFS_MIN_BLOCK_SIZE 1024
#define RINFS_MAX_BLOCK_SIZE 65536
#define RINFS_DEFAULT_BLOCK_SIZE 4096

/* Limits */
#define RINFS_NAME_MAX      255
#define RINFS_PATH_MAX      4096
#define RINFS_SYMLINK_MAX   4096
#define RINFS_DIRECT_BLOCKS 12
#define RINFS_INDIRECT_L1   1      /* Single indirect */
#define RINFS_INDIRECT_L2   1      /* Double indirect */
#define RINFS_INDIRECT_L3   1      /* Triple indirect */

/* Reserved inode numbers */
#define RINFS_INODE_NULL    0
#define RINFS_INODE_ROOT    1
#define RINFS_INODE_BADBLK  2
#define RINFS_INODE_JOURNAL 3
#define RINFS_INODE_FIRST   4      /* First usable inode */

/* File types (in i_mode upper 4 bits) */
#define RINFS_FT_UNKNOWN    0x0
#define RINFS_FT_REG        0x8    /* Regular file */
#define RINFS_FT_DIR        0x4    /* Directory */
#define RINFS_FT_CHR        0x2    /* Character device */
#define RINFS_FT_BLK        0x6    /* Block device */
#define RINFS_FT_FIFO       0x1    /* FIFO/pipe */
#define RINFS_FT_SOCK       0xC    /* Socket */
#define RINFS_FT_LNK        0xA    /* Symbolic link */

/* Permission bits */
#define RINFS_S_IXOTH   0x0001
#define RINFS_S_IWOTH   0x0002
#define RINFS_S_IROTH   0x0004
#define RINFS_S_IXGRP   0x0008
#define RINFS_S_IWGRP   0x0010
#define RINFS_S_IRGRP   0x0020
#define RINFS_S_IXUSR   0x0040
#define RINFS_S_IWUSR   0x0080
#define RINFS_S_IRUSR   0x0100
#define RINFS_S_ISVTX   0x0200  /* Sticky bit */
#define RINFS_S_ISGID   0x0400  /* Set-group-ID */
#define RINFS_S_ISUID   0x0800  /* Set-user-ID */

/* Filesystem state */
#define RINFS_STATE_CLEAN   0x0001
#define RINFS_STATE_ERROR   0x0002
#define RINFS_STATE_ORPHAN  0x0004

/* Mount flags */
#define RINFS_MNT_RDONLY    0x0001
#define RINFS_MNT_NOATIME   0x0002
#define RINFS_MNT_SYNC      0x0004
#define RINFS_MNT_JOURNAL   0x0008
#define RINFS_MNT_REPAIR    0x0010  /* Explicit allocation/structural recovery */
#define RINFS_MNT_RESCUE    0x0020  /* Explicit read-only best-effort salvage */
#define RINFS_MNT_RESIZE    0x0040  /* Offline resize/recovery maintenance */

/* Allocation-metadata checker flags and issue bits.  Counter repair is
 * deliberately narrower than a full inode/block reference fsck. */
#define RINFS_CHECK_REPAIR_COUNTERS       0x0001u
#define RINFS_CHECK_ISSUE_RESERVED_BLOCK  0x0001u
#define RINFS_CHECK_ISSUE_RESERVED_INODE  0x0002u
#define RINFS_CHECK_ISSUE_BLOCK_COUNT     0x0004u
#define RINFS_CHECK_ISSUE_INODE_COUNT     0x0008u

/* Inode flags */
#define RINFS_IFLG_SYNC     0x0001  /* Synchronous updates */
#define RINFS_IFLG_IMMUT    0x0002  /* Immutable file */
#define RINFS_IFLG_APPEND   0x0004  /* Append-only */
#define RINFS_IFLG_NODUMP   0x0008  /* Don't dump */
#define RINFS_IFLG_EXTENT   0x0010  /* Uses extents (not block pointers) */
#define RINFS_IFLG_INLINE   0x0020  /* Data stored inline in inode */
#define RINFS_IFLG_QUARANTINED_SPECIAL 0x0040 /* Neutralized special inode */
#define RINFS_IFLG_CONTENT_UNCERTAIN 0x0080 /* Persistent content poison */
#define RINFS_IFLG_QUARANTINED_TYPE_SHIFT 8u
#define RINFS_IFLG_QUARANTINED_TYPE_MASK  0x0F00u
#define RINFS_IFLG_ORPHAN_INTENT 0x1000u /* v1.6 interrupted unlink/reclaim */

/* Read coalescing is deliberately bounded by the ATA/AHCI transport contract.
 * A caller may still observe smaller I/O when a file is sparse or fragmented;
 * this is a target, never an excuse to read a non-contiguous extent. */
#define RINFS_READ_COALESCE_MAX_BYTES (128u * 1024u)
#define RINFS_DENTRY_CACHE_CAPACITY 256u
#define RINFS_DEVICE_FLAG_REMOVABLE 0x00000001u
#define RINFS_DEVICE_FLAG_SLOW      0x00000002u
#define RINFS_DEVICE_FLAG_OFFLINE  0x00000004u

typedef enum {
    RINFS_PAGE_CACHE_PRESSURE_NORMAL = 0,
    RINFS_PAGE_CACHE_PRESSURE_WARNING = 1,
    RINFS_PAGE_CACHE_PRESSURE_CRITICAL = 2,
    RINFS_PAGE_CACHE_PRESSURE_OOM = 3
} RinFS_PageCachePressure;

/* RinFS file data is cached only when the on-disk content identity is
 * available.  The cache is deliberately bounded and uses the filesystem
 * block as its 4 KiB page; non-4 KiB volumes retain the checked direct-I/O
 * path until a page/block translation is available. */
#define RINFS_PAGE_CACHE_PAGE_SIZE 4096u
#define RINFS_PAGE_CACHE_CAPACITY 32u

/* Per-inode extended attributes live in one separately allocated block.  The
 * format intentionally stays bounded by the volume block size: it is enough
 * for POSIX-style ACL records and application/security labels without
 * introducing an unbounded metadata tree into the v1 inode ABI. */
#define RINFS_XATTR_MAGIC       0x31584152u /* "RAX1" little endian */
#define RINFS_XATTR_VERSION     1u
#define RINFS_XATTR_NAME_MAX    255u
#define RINFS_XATTR_ENTRY_MAX   64u

/* ═══════════════════════════════════════════════════════════════
 * On-Disk Structures
 * ═══════════════════════════════════════════════════════════════*/

/* Superblock (1024 bytes, at sector 0-1) */
typedef struct __attribute__((packed)) {
    /* Magic and version (0x00-0x0F) */
    uint32_t s_magic;           /* 0x00: Magic number (RINFS_MAGIC) */
    uint32_t s_magic2;          /* 0x04: Second magic (RINFS_MAGIC2) */
    uint16_t s_version_major;   /* 0x08: Major version */
    uint16_t s_version_minor;   /* 0x0A: Minor version */
    uint32_t s_flags;           /* 0x0C: Filesystem flags */
    
    /* Geometry (0x10-0x2F) */
    uint64_t s_block_count;     /* 0x10: Total blocks in filesystem */
    uint64_t s_free_blocks;     /* 0x18: Free block count */
    uint64_t s_inode_count;     /* 0x20: Total inodes */
    uint64_t s_free_inodes;     /* 0x28: Free inode count */
    
    /* Block info (0x30-0x3F) */
    uint32_t s_block_size;      /* 0x30: Block size in bytes */
    uint32_t s_blocks_per_group;/* 0x34: Blocks per block group */
    uint32_t s_inodes_per_group;/* 0x38: Inodes per block group */
    uint32_t s_inode_size;      /* 0x3C: Inode structure size */
    
    /* Layout (0x40-0x5F) */
    uint64_t s_block_bitmap;    /* 0x40: Block bitmap start (block #) */
    uint64_t s_inode_bitmap;    /* 0x48: Inode bitmap start (block #) */
    uint64_t s_inode_table;     /* 0x50: Inode table start (block #) */
    uint64_t s_data_start;      /* 0x58: First data block */
    
    /* State and timestamps (0x60-0x7F) */
    uint16_t s_state;           /* 0x60: Filesystem state */
    uint16_t s_errors;          /* 0x62: Error handling behavior */
    uint32_t s_checksum;        /* 0x64: Superblock checksum */
    uint64_t s_mount_time;      /* 0x68: Last mount time (Unix timestamp) */
    uint64_t s_write_time;      /* 0x70: Last write time */
    uint16_t s_mount_count;     /* 0x78: Mount count since last fsck */
    uint16_t s_max_mount_count; /* 0x7A: Max mounts before fsck */
    uint32_t s_creator_os;      /* 0x7C: Creator OS (0=RinOS) */
    
    /* UUID and labels (0x80-0xEF) */
    uint8_t  s_uuid[16];        /* 0x80: Filesystem UUID */
    char     s_volume_name[32]; /* 0x90: Volume name (UTF-8) */
    char     s_last_mounted[64];/* 0xB0: Last mount path */
    
    /* Journal (0xF0-0x10F) */
    uint64_t s_journal_inode;   /* 0xF0: Journal inode number */
    uint64_t s_journal_size;    /* 0xF8: Journal size in blocks */
    uint32_t s_journal_seq;     /* 0x100: Current journal sequence */
    uint32_t s_reserved1;       /* 0x104: Reserved */
    uint64_t s_reserved2;       /* 0x108: Reserved */
    
    /* Feature flags (0x110-0x11F) */
    uint32_t s_compat_features; /* 0x110: Compatible features */
    uint32_t s_incompat_features;/* 0x114: Incompatible features */
    uint32_t s_ro_compat_features;/* 0x118: Read-only compatible features */
    uint32_t s_reserved3;       /* 0x11C: Reserved */
    
    /* Padding to 1024 bytes */
    uint8_t  s_padding[736];    /* 0x120-0x3FF */
} RinFS_Superblock;

_Static_assert(sizeof(RinFS_Superblock) == 1024,
               "RinFS superblock must occupy exactly two sectors");

/* Inode (304-byte deployed v1 ABI). Historical comments described a
 * 256-byte/6-direct-pointer draft, but mkfs has always serialized the actual
 * 12-direct-pointer C layout through s_inode_size. */
typedef struct __attribute__((packed)) {
    /* Type and permissions (0x00-0x03) */
    uint16_t i_mode;            /* 0x00: File type and permissions */
    uint16_t i_flags;           /* 0x02: Inode flags */
    
    /* Ownership (0x04-0x0B) */
    uint32_t i_uid;             /* 0x04: Owner user ID */
    uint32_t i_gid;             /* 0x08: Owner group ID */
    
    /* Size and links (0x0C-0x17) */
    uint64_t i_size;            /* 0x0C: File size in bytes */
    uint32_t i_links;           /* 0x14: Hard link count */
    
    /* Timestamps (0x18-0x37) */
    uint64_t i_atime;           /* 0x18: Access time */
    uint64_t i_mtime;           /* 0x20: Modification time */
    uint64_t i_ctime;           /* 0x28: Change time (inode) */
    uint64_t i_btime;           /* 0x30: Birth/creation time */
    
    /* Block count (0x38-0x3F) */
    uint64_t i_blocks;          /* 0x38: Blocks allocated (512-byte units) */
    
    /* Direct block pointers (0x40-0x6F) - 12 x 8 bytes = 96 bytes */
    uint64_t i_block[RINFS_DIRECT_BLOCKS];
    
    /* Indirect block pointers (0xA0-0xB7) */
    uint64_t i_indirect1;       /* 0xA0: Single indirect */
    uint64_t i_indirect2;       /* 0xA8: Double indirect */
    uint64_t i_indirect3;       /* 0xB0: Triple indirect */
    
    /* Extended attributes (0xB8-0xBF) */
    uint64_t i_xattr_block;     /* 0xB8: Extended attributes block */
    
    /* Generation and version (0xC0-0xC7) */
    uint32_t i_generation;      /* 0xC0: File generation (for NFS) */
    uint32_t i_version;         /* 0xC4: Content version, low 32 bits */
    
    /* RinFS v1.5 uses bytes 0xC8-0xDB for guarded nanotimes.  With the v1.6
     * CONTENT_VERSION64 incompat feature, 0xDC-0xDF stores the high version
     * word. The remaining bytes are canonical zero; persistent poison is
     * RINFS_IFLG_CONTENT_UNCERTAIN. Access tracking through the helpers. */
    uint8_t  i_reserved[104];   /* 0xC8-0x12F */
} RinFS_Inode;

_Static_assert(sizeof(RinFS_Inode) == 304u,
               "RinFS inode disk ABI must remain 304 bytes");
_Static_assert(offsetof(RinFS_Inode, i_generation) == 0xC0u &&
               offsetof(RinFS_Inode, i_version) == 0xC4u &&
               offsetof(RinFS_Inode, i_reserved) == 0xC8u,
               "RinFS inode disk ABI offsets changed");
_Static_assert(offsetof(RinFS_Inode, i_reserved) + 20u == 0xDCu,
               "RinFS content-version high word must remain at 0xDC");

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t entry_count;
    uint32_t bytes_used;
    uint32_t reserved;
} RinFS_XattrHeader;

_Static_assert(sizeof(RinFS_XattrHeader) == 16,
               "RinFS xattr header ABI must remain fixed");

/* Directory entry (variable size, 8-264 bytes) */
typedef struct __attribute__((packed)) {
    uint64_t d_inode;           /* 0x00: Inode number (0 = deleted) */
    uint16_t d_rec_len;         /* 0x08: Record length (for alignment) */
    uint8_t  d_name_len;        /* 0x0A: Name length */
    uint8_t  d_file_type;       /* 0x0B: File type (for fast lookup) */
    char     d_name[RINFS_NAME_MAX + 1]; /* 0x0C: Filename (null-terminated) */
} RinFS_DirEntry;

/* Extent (16 bytes) - for extent-based allocation */
typedef struct __attribute__((packed)) {
    uint64_t e_block;           /* Starting logical block */
    uint32_t e_start;           /* Starting physical block (low 32 bits) */
    uint16_t e_start_hi;        /* Starting physical block (high 16 bits) */
    uint16_t e_len;             /* Number of blocks (max 32768) */
} RinFS_Extent;

/* Extent header (12 bytes) */
typedef struct __attribute__((packed)) {
    uint16_t eh_magic;          /* Magic (0xF30A) */
    uint16_t eh_entries;        /* Number of valid entries */
    uint16_t eh_max;            /* Capacity of entries */
    uint16_t eh_depth;          /* Tree depth (0 = leaf) */
    uint32_t eh_generation;     /* Generation of tree */
} RinFS_ExtentHeader;

/* ═══════════════════════════════════════════════════════════════
 * In-Memory Structures
 * ═══════════════════════════════════════════════════════════════*/

/* Optional per-filesystem I/O provider. Kernel-owned installers use this to
 * retain a controlled RinBlock lease and deadline policy for the full format,
 * mount and verification lifetime. A NULL provider keeps the platform's
 * ordinary RinBlock path. Callbacks return zero on success. A successful
 * flush is a durability and ordering barrier for every preceding write on
 * this device; failure has indeterminate persistence and must never be
 * treated as a completed content-generation commit. */
typedef struct RinFS_DeviceOps {
    int (*read)(void* opaque, int dev_id, uint64_t lba,
                uint32_t sector_count, void* output);
    int (*write)(void* opaque, int dev_id, uint64_t lba,
                 uint32_t sector_count, const void* input);
    int (*flush)(void* opaque, int dev_id);
    void* opaque;
    uint32_t flags;
} RinFS_DeviceOps;

typedef struct {
    uint64_t mount_epoch;
    uint64_t directory_inode;
    uint32_t directory_lifetime_generation;
    uint64_t directory_content_generation;
    uint64_t child_inode;
    uint64_t last_used;
    uint16_t name_length;
    uint8_t file_type;
    uint8_t negative;
    uint8_t valid;
    char name[RINFS_NAME_MAX + 1u];
} RinFS_DentryCacheEntry;

typedef struct {
    volatile uint32_t lock;
    uint64_t clock;
    uint64_t hits;
    uint64_t misses;
    RinFS_DentryCacheEntry entries[RINFS_DENTRY_CACHE_CAPACITY];
} RinFS_DentryCache;

/* Large directories use a bounded open-addressed location index.  The index
 * stores a verified on-disk location rather than a second copy of the name;
 * lookup re-reads that location and compares the complete name before
 * returning the child inode.  Content generation makes entries disposable
 * without a global directory-cache invalidation walk. */
#define RINFS_DIRECTORY_INDEX_CAPACITY 1024u
typedef struct {
    uint64_t hash;
    uint64_t directory_inode;
    uint64_t directory_content_generation;
    uint64_t physical_block;
    uint32_t directory_lifetime_generation;
    uint32_t block_offset;
    uint64_t child_inode;
    uint16_t name_length;
    uint8_t valid;
    uint8_t reserved[5];
} RinFS_DirectoryIndexEntry;

typedef struct {
    volatile uint32_t lock;
    RinFS_DirectoryIndexEntry entries[RINFS_DIRECTORY_INDEX_CAPACITY];
} RinFS_DirectoryIndex;

/* RinFS-owned inode metadata cache. Entries are copies, never borrowed
 * pointers, and are keyed by the mount lifetime plus the inode's content
 * identity. This keeps metadata reuse inside the filesystem owner. */
#define RINFS_INODE_CACHE_CAPACITY 256u
typedef struct {
    uint64_t mount_epoch;
    uint64_t inode_num;
    uint64_t content_version;
    uint64_t last_used;
    uint32_t inode_generation;
    uint8_t valid;
    uint8_t reserved[3];
    RinFS_Inode inode;
} RinFS_InodeCacheEntry;

typedef struct {
    volatile uint32_t lock;
    uint64_t clock;
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    RinFS_InodeCacheEntry entries[RINFS_INODE_CACHE_CAPACITY];
} RinFS_InodeCache;

typedef enum {
    RINFS_PAGE_CACHE_FREE = 0,
    RINFS_PAGE_CACHE_CLEAN = 1,
    RINFS_PAGE_CACHE_DIRTY = 2,
    RINFS_PAGE_CACHE_FILLING = 3,
    RINFS_PAGE_CACHE_WRITEBACK = 4
} RinFS_PageCacheState;

typedef enum {
    RINFS_PAGE_CACHE_INACTIVE = 0,
    RINFS_PAGE_CACHE_ACTIVE = 1
} RinFS_PageCacheGeneration;

typedef struct {
    uint64_t mount_epoch;
    uint64_t inode_num;
    uint64_t content_version;
    uint64_t page_index;
    uint64_t physical_block;
    uint64_t last_used;
    uint64_t dirty_since;
    uint32_t inode_generation;
    uint32_t dirty_start;
    uint32_t dirty_end;
    int32_t writeback_error;
    uint32_t references;
    uint8_t state;
    uint8_t valid;
    uint8_t generation;
    uint8_t readahead;
    uint8_t* data;
    /* Freestanding mounts may back this entry with an allocator-owned
     * physical page. Hosted fixtures leave this zero and use storage. */
    uint64_t physical_address;
} RinFS_PageCacheEntry;

typedef struct {
    volatile uint32_t lock;
    uint64_t clock;
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t dirty_pages;
    uint64_t dirty_bytes;
    uint64_t writeback_errors;
    uint64_t writeback_ops;
    uint64_t writeback_pages;
    uint64_t writeback_cycles;
    uint64_t readahead_issued;
    uint64_t readahead_useful;
    uint64_t readahead_wasted;
    uint64_t lock_wait_count;
    uint64_t lock_wait_cycles;
    uint8_t* storage;
    uint8_t pressure_level;
    uint8_t device_flags;
    uint16_t reserved0;
    uint32_t readahead_limit_pages;
    RinFS_PageCacheEntry entries[RINFS_PAGE_CACHE_CAPACITY];
} RinFS_PageCache;

/* Mount info */
typedef struct {
    int              mounted;
    int              readonly;
    uint32_t         mount_flags;
    RinFS_Superblock sb;
    
    /* Cached pointers */
    uint64_t         block_bitmap_block;
    uint64_t         inode_bitmap_block;
    uint64_t         inode_table_block;
    
    /* Block device info */
    int              dev_id;
    uint64_t         dev_offset;    /* Partition offset in sectors */
    uint64_t         dev_sector_count; /* 0 only for legacy unbounded callers */
    RinFS_DeviceOps  device_ops;
    int              has_device_ops;
    uint32_t         device_flags;
    
    /* Buffers */
    uint8_t*         block_buffer;
    uint32_t         buffer_block;
    int              buffer_dirty;

    /* Internal synchronization/cache-safety state.  Logical content leases
     * are inode/file-object scoped; the striped locks protect only the short
     * physical inode-table read/modify/write operations. */
    volatile uint32_t inode_table_locks[64];
    volatile uint32_t block_allocation_lock;
    volatile uint32_t inode_allocation_lock;
    volatile uint32_t superblock_lock;
    volatile uint32_t content_lease_lock;
    /* Serializes the single on-disk rename/rmdir journal transaction. */
    volatile uint32_t namespace_journal_lock;
    uint32_t          content_lease_closing;
    void*             content_leases;
    uint64_t          content_lease_generation;
    uint32_t          content_tracking_runtime_disabled;
    /* Boot-local mount identity.  Zero disables dentry sharing; it is not a
     * persistent filesystem generation and is never serialized to disk. */
    uint64_t           mount_epoch;
    RinFS_DentryCache* dentry_cache;
    RinFS_DirectoryIndex* directory_index;
    RinFS_InodeCache*  inode_cache;
    RinFS_PageCache* page_cache;
    uint64_t           coalesced_read_ops;
    uint64_t           coalesced_read_bytes;
    uint64_t           coalesced_write_ops;
    uint64_t           coalesced_write_bytes;
} RinFS_Mount;

/* Open file */
typedef struct {
    int              in_use;
    uint64_t         inode_num;
    RinFS_Inode      inode;
    uint64_t         position;
    int              flags;         /* O_RDONLY, O_WRONLY, O_RDWR */
    RinFS_Mount*     mount;
    uint64_t         content_pin_token;
    uint32_t         content_pin_generation;
    int              content_pin_active;
    /* The final open reference may discover an unlinked inode whose block
     * reclaim needs a durable write.  Keep the handle live when that write
     * fails so a later close can retry instead of losing the lifetime. */
    int              content_reclaim_pending;
    uint64_t         close_reference_generation;
    uint64_t         close_reference_cookie;
    uint64_t         close_reference_mount_epoch;
    /* Per-open-description access detector.  These fields are bounded and
     * inode-handle local, so a new file lifetime never inherits a previous
     * object's read pattern. */
    uint64_t         read_pattern_last_page;
    uint32_t         read_pattern_window_pages;
    uint32_t         read_pattern_sequential_hits;
    uint8_t          read_pattern_kind;
    uint8_t          read_pattern_valid;
    uint8_t          read_advice;
    uint8_t          read_pattern_reserved;
} RinFS_File;

/* Directory iterator */
typedef struct {
    int              in_use;
    uint64_t         inode_num;
    RinFS_Inode      inode;
    uint64_t         position;
    RinFS_Mount*     mount;
    uint64_t         content_pin_token;
    uint32_t         content_pin_generation;
    int              content_pin_active;
    int              content_reclaim_pending;
    uint64_t         close_reference_generation;
    uint64_t         close_reference_cookie;
    uint64_t         close_reference_mount_epoch;
} RinFS_Dir;

/* Opaque inode-scoped read lease for an exact, atime-free content snapshot.
 * The captured inode and immutable identity remain stable until end(). */
typedef struct {
    RinFS_Mount* mount;
    void* lease_cookie;
    uint64_t inode_num;
    uint32_t inode_generation;
    uint64_t lease_generation;
    RinFS_Inode inode;
    int active;
} RinFS_ContentSnapshot;

_Static_assert(sizeof(RinFS_ContentSnapshot) <= 384u,
               "RinFS content snapshot must fit the VFS opaque lease ABI");

/* A file-backed VMA owns an opaque reference to one exact inode lifetime.
 * Unlike an open-file cursor this object is shareable by split/forked VMAs;
 * its final release drops the independent inode pin. */
typedef struct RinFS_MmapSource RinFS_MmapSource;

/* A synchronous kernel consumer may borrow one complete, generation-bound
 * page-cache page without exposing a user mapping.  cache_token is an opaque
 * owner token and must be returned exactly once through
 * rinfs_page_cache_release_view(). */
typedef struct {
    const uint8_t* data;
    uint64_t physical_address;
    uintptr_t cache_token;
} RinFS_PageCacheView;

typedef struct {
    uint64_t actual_free_blocks;
    uint64_t actual_free_inodes;
    uint32_t issues;
    uint32_t repaired_issues;
} RinFS_CheckReport;

/* Read-only structural checker issue bits.  Structural damage is never
 * repaired implicitly while mounting: callers must inspect this report and
 * choose an explicit offline recovery policy. */
#define RINFS_FULL_ISSUE_INVALID_INODE       0x00000001u
#define RINFS_FULL_ISSUE_INVALID_BLOCK_REF   0x00000002u
#define RINFS_FULL_ISSUE_DUPLICATE_BLOCK     0x00000004u
#define RINFS_FULL_ISSUE_LEAKED_BLOCK        0x00000008u
#define RINFS_FULL_ISSUE_DIRECTORY           0x00000010u
#define RINFS_FULL_ISSUE_UNREACHABLE_INODE   0x00000020u
#define RINFS_FULL_ISSUE_LINK_COUNT           0x00000040u
#define RINFS_FULL_ISSUE_INODE_BLOCK_COUNT    0x00000080u
#define RINFS_FULL_ISSUE_AMBIGUOUS_METADATA   0x00000100u
/* The reference is in range and structurally admitted, but its allocation
 * bitmap bit is clear. This is repairable; INVALID_BLOCK_REF is not. */
#define RINFS_FULL_ISSUE_UNALLOCATED_BLOCK    0x00000200u
#define RINFS_FULL_REPAIR_SAFE_METADATA        0x00000001u
#define RINFS_FULL_REPAIR_RECONNECT_FILES      0x00000002u
#define RINFS_FULL_REPAIR_CLONE_DATA_DUPLICATES   0x00000004u
/* Source compatibility for callers built against the direct-only policy.
 * The bit now also admits data leaves under validated indirect trees. */
#define RINFS_FULL_REPAIR_CLONE_DIRECT_DUPLICATES \
    RINFS_FULL_REPAIR_CLONE_DATA_DUPLICATES
#define RINFS_FULL_REPAIR_RECONNECT_SUBTREES   0x00000008u
#define RINFS_FULL_REPAIR_QUARANTINE_DUPLICATE_NAMES 0x00000010u
#define RINFS_FULL_REPAIR_QUARANTINE_SPECIAL_FILES  0x00000020u
#define RINFS_FULL_REPAIR_CLONE_SHARED_INDIRECT_ROOTS 0x00000040u
#define RINFS_FULL_REPAIR_REBUILD_AMBIGUOUS_INDIRECT 0x00000080u
#define RINFS_FULL_REPAIR_ALL_SAFE \
    (RINFS_FULL_REPAIR_SAFE_METADATA | RINFS_FULL_REPAIR_RECONNECT_FILES | \
     RINFS_FULL_REPAIR_CLONE_DATA_DUPLICATES | \
     RINFS_FULL_REPAIR_RECONNECT_SUBTREES | \
     RINFS_FULL_REPAIR_QUARANTINE_DUPLICATE_NAMES | \
     RINFS_FULL_REPAIR_QUARANTINE_SPECIAL_FILES | \
     RINFS_FULL_REPAIR_CLONE_SHARED_INDIRECT_ROOTS | \
     RINFS_FULL_REPAIR_REBUILD_AMBIGUOUS_INDIRECT)
#define RINFS_FULL_REPAIR_MAX_DUPLICATE_BLOCKS 64u
#define RINFS_FULL_REPAIR_MAX_SHARED_METADATA_BLOCKS 64u
#define RINFS_FULL_REPAIRABLE_ISSUES \
    (RINFS_FULL_ISSUE_LEAKED_BLOCK | RINFS_FULL_ISSUE_LINK_COUNT | \
     RINFS_FULL_ISSUE_INODE_BLOCK_COUNT | \
     RINFS_FULL_ISSUE_UNALLOCATED_BLOCK)

typedef struct {
    uint64_t allocated_inodes;
    uint64_t reachable_inodes;
    uint64_t referenced_blocks;
    uint64_t duplicate_block_references;
    uint64_t shared_indirect_metadata_references;
    uint64_t cyclic_indirect_metadata_references;
    uint64_t unallocated_block_references;
    uint64_t leaked_blocks;
    uint64_t invalid_inodes;
    uint64_t unreachable_inodes;
    uint64_t unreachable_special_inodes;
    uint64_t invalid_directory_entries;
    uint64_t duplicate_directory_names;
    uint64_t link_count_mismatches;
    uint64_t inode_block_count_mismatches;
    uint64_t reconnected_inodes;
    uint64_t reconnected_subtrees;
    uint64_t cloned_duplicate_blocks;
    uint64_t cloned_shared_indirect_metadata_blocks;
    uint64_t quarantined_directory_entries;
    uint64_t quarantined_special_inodes;
    uint32_t issues;
    uint32_t repaired_issues;
} RinFS_FullCheckReport;

/* Filesystem timestamps are Unix epoch seconds.  Platforms may install a
 * trusted wall-clock source during early boot; hosted tests can install a
 * deterministic source.  A NULL provider restores the platform default. */
typedef uint64_t (*RinFS_TimeProvider)(void* context);
void rinfs_set_time_provider(RinFS_TimeProvider provider, void* context);
uint64_t rinfs_now_seconds(void);

#define RINFS_INODE_TIME_BIRTH  0x00000001u
#define RINFS_INODE_TIME_ACCESS 0x00000002u
#define RINFS_INODE_TIME_WRITE  0x00000004u
#define RINFS_INODE_TIME_MASK   0x00000007u

/* The public VFS timestamp ABI has signed Unix seconds plus nanoseconds.
 * RinFS v1.5 stores this exactly when the incompatible nanotime feature is
 * present; older volumes retain their historical positive-second format. */
typedef struct {
    int64_t seconds;
    uint32_t nanoseconds;
    uint32_t reserved;
} RinFS_InodeTimestamp;

typedef struct {
    RinFS_InodeTimestamp birth;
    RinFS_InodeTimestamp access;
    RinFS_InodeTimestamp write;
    uint32_t valid_mask;
    uint32_t reserved;
} RinFS_InodeTimes;

_Static_assert(sizeof(RinFS_InodeTimestamp) == 16u,
               "RinFS inode timestamp ABI must remain fixed");
_Static_assert(sizeof(RinFS_InodeTimes) == 56u,
               "RinFS inode times ABI must remain fixed");

/* ═══════════════════════════════════════════════════════════════
 * API Functions
 * ═══════════════════════════════════════════════════════════════*/

/* Formatting */
int rinfs_mkfs(int dev_id, uint64_t offset, uint64_t size_blocks, uint32_t block_size);
int rinfs_mkfs_with_uuid(int dev_id, uint64_t offset, uint64_t size_blocks,
                         uint32_t block_size, const uint8_t uuid[16]);
int rinfs_mkfs_with_uuid_io(int dev_id, uint64_t offset,
                            uint64_t size_blocks, uint32_t block_size,
                            const uint8_t uuid[16],
                            const RinFS_DeviceOps* device_ops);

/* Mounting */
int rinfs_mount(int dev_id, uint64_t offset, uint32_t flags, RinFS_Mount* mount);
int rinfs_mount_sized(int dev_id, uint64_t offset, uint64_t sector_count,
                      uint32_t flags, RinFS_Mount* mount);
int rinfs_mount_sized_io(int dev_id, uint64_t offset, uint64_t sector_count,
                         uint32_t flags,
                         const RinFS_DeviceOps* device_ops,
                         RinFS_Mount* mount);
int rinfs_unmount(RinFS_Mount* mount);
/* Discard a failed writable mount without publishing CLEAN. The caller must
 * still own the mount and all open file, directory, and mmap handles must be
 * closed. Persistent state remains dirty so the next mount runs recovery. */
int rinfs_abandon_dirty_mount(RinFS_Mount* mount);
/* Publish a device/media state change to all RinFS I/O paths.  OFFLINE is a
 * terminal read/write barrier until a new mount is established. */
int rinfs_mount_set_device_flags(RinFS_Mount* mount, uint32_t device_flags);
/* VFS may replace the low-level boot-local epoch with its lifecycle epoch.
 * Zero retires the namespace and makes dentry sharing ineligible. */
void rinfs_mount_set_epoch(RinFS_Mount* mount, uint64_t mount_epoch);
int rinfs_sync(RinFS_Mount* mount);

/* Replace the bounded UTF-8 superblock volume name and persist it. */
int rinfs_set_volume_name(RinFS_Mount* mount, const char* name,
                          uint32_t name_length);
int rinfs_check_allocation_metadata(RinFS_Mount* mount, uint32_t flags,
                                    RinFS_CheckReport* report);
int rinfs_check_full(RinFS_Mount* mount, RinFS_FullCheckReport* report);
/* Explicit maintenance-mode repair. A valid graph reference whose allocation
 * bit is missing is restored before any repair action that can allocate.
 * Ordinary-file duplicate data leaves may
 * be cloned under unique direct/indirect metadata ownership. The legacy root
 * policy admits one bounded acyclic root shared by two ordinary files. The
 * rebuild policy instead republishes every affected ordinary-file root from a
 * bounded edge-expanded tree, clones metadata/data aliases, and cuts cyclic
 * metadata back-edges to sparse holes without selecting an on-disk owner.
 * Mixed-type ownership remains quarantined. Exact
 * duplicate directory names quarantine every conflicting edge rather than
 * selecting a winner. Regular-file, symlink and subtree orphans may be
 * reconnected only into the fixed Rin recovery namespace. A standalone,
 * blockless special inode can be neutralized into an inert Recovery file only
 * with the explicit special-file quarantine policy; all other unsupported
 * ambiguity remains quarantined without deleting user data. */
int rinfs_repair_full(RinFS_Mount* mount, uint32_t flags,
                      RinFS_FullCheckReport* report);
/* Offline, recoverable resize. The selected partition must be quiesced and
 * the mount opened with RINFS_MNT_RESIZE. RINFS_ERR_PENDING means the durable
 * filesystem intent is ready for the caller to change the GPT boundary and
 * remount at the exact target size; mounting then resumes and completes it. */
int rinfs_resize(RinFS_Mount* mount, uint64_t target_blocks);

/* Inode operations */
int rinfs_inode_read(RinFS_Mount* mount, uint64_t ino, RinFS_Inode* inode);
int rinfs_inode_write(RinFS_Mount* mount, uint64_t ino, const RinFS_Inode* inode);
int rinfs_inode_set_times(RinFS_Mount* mount, uint64_t ino,
                          uint32_t valid_mask, uint64_t birth_time,
                          uint64_t access_time, uint64_t write_time,
                          RinFS_Inode* committed_inode);
/* Exact signed-second/nanosecond timestamp transaction.  It is available
 * only on a volume that advertises RINFS_FEATURE_INCOMPAT_NANO_TIMESTAMPS. */
int rinfs_inode_get_times_precise(const RinFS_Mount* mount,
                                  const RinFS_Inode* inode,
                                  RinFS_InodeTimes* times_out);
int rinfs_inode_set_times_precise(
    RinFS_Mount* mount, uint64_t ino, uint32_t valid_mask,
    const RinFS_InodeTimestamp* birth,
    const RinFS_InodeTimestamp* access,
    const RinFS_InodeTimestamp* write,
    RinFS_Inode* committed_inode);
/* Read the logical 64-bit content version and persistent tracking state.
 * Returns RINFS_OK on success. Volumes without CONTENT_VERSION64 return
 * RINFS_ERR_NOT_SUPPORTED; zero versions and nonzero state are not reusable
 * verified identities even though decoding itself succeeds. */
int rinfs_inode_content_tracking(const RinFS_Mount* mount,
                                 const RinFS_Inode* inode,
                                 uint64_t* version_out,
                                 uint32_t* state_out);
/* Acquire an inode-scoped read lease, then capture/read/revalidate one exact
 * regular-file byte sequence without atime mutation. */
int rinfs_content_snapshot_begin(RinFS_Mount* mount, uint64_t ino,
                                 RinFS_ContentSnapshot* snapshot);
int rinfs_content_snapshot_read_exact(RinFS_ContentSnapshot* snapshot,
                                      void* output, uint64_t size);
int rinfs_content_snapshot_revalidate(RinFS_ContentSnapshot* snapshot);
void rinfs_content_snapshot_end(RinFS_ContentSnapshot* snapshot);
int rinfs_mmap_source_create(const RinFS_File* file,
                             RinFS_MmapSource** source_out,
                             uint64_t* inode_out,
                             uint64_t* size_out,
                             uint64_t* reference_generation_out,
                             uint64_t* reference_cookie_out);
/* Clone one exact source reference. The returned source has its own
 * generation/cookie and its own content pin; the input remains owned by the
 * caller. */
int rinfs_mmap_source_retain(const RinFS_MmapSource* source,
                             uint64_t reference_generation,
                             uint64_t reference_cookie,
                             RinFS_MmapSource** retained_out,
                             uint64_t* retained_generation_out,
                             uint64_t* retained_cookie_out);
/* Acquire one cache-page mapping reference for a complete, read-only file
 * page. The reference is held until the user mapping is unmapped. */
int rinfs_mmap_source_get_page(RinFS_MmapSource* source,
                               uint64_t expected_inode,
                               uint64_t reference_generation,
                               uint64_t reference_cookie,
                               uint64_t page_index,
                               uint64_t* physical_out);
int rinfs_mmap_source_get_page_view(RinFS_MmapSource* source,
                                    uint64_t expected_inode,
                                    uint64_t reference_generation,
                                    uint64_t reference_cookie,
                                    uint64_t page_index,
                                    RinFS_PageCacheView* view_out);
/* Retain a second mapping reference for an already-present shared page. */
int rinfs_mmap_source_retain_page(RinFS_MmapSource* source,
                                  uint64_t expected_inode,
                                  uint64_t reference_generation,
                                  uint64_t reference_cookie,
                                  uint64_t page_index,
                                  uint64_t physical_address);
/* Release a mapping reference by its exact physical page. */
int rinfs_page_cache_release_mapped_page(RinFS_Mount* mount,
                                         uint64_t physical_address);
int rinfs_page_cache_release_view(RinFS_Mount* mount,
                                  uintptr_t cache_token);
int64_t rinfs_mmap_source_read(RinFS_MmapSource* source,
                               uint64_t expected_inode,
                               uint64_t reference_generation,
                               uint64_t reference_cookie,
                               uint64_t offset, void* output,
                               uint32_t size);
int rinfs_mmap_source_release(RinFS_MmapSource* source,
                              uint64_t reference_generation,
                              uint64_t reference_cookie);
int rinfs_inode_alloc(RinFS_Mount* mount, uint64_t* ino);
int rinfs_inode_free(RinFS_Mount* mount, uint64_t ino);

/* Block operations */
int rinfs_block_read(RinFS_Mount* mount, uint64_t block, void* buf);
int rinfs_block_write(RinFS_Mount* mount, uint64_t block, const void* buf);
int rinfs_block_alloc(RinFS_Mount* mount, uint64_t* block);
int rinfs_block_free(RinFS_Mount* mount, uint64_t block);

typedef struct {
    uint64_t coalesced_read_ops;
    uint64_t coalesced_read_bytes;
    uint64_t coalesced_write_ops;
    uint64_t coalesced_write_bytes;
    uint64_t dentry_hits;
    uint64_t dentry_misses;
    uint64_t inode_cache_hits;
    uint64_t inode_cache_misses;
    uint64_t inode_cache_evictions;
    uint64_t page_cache_hits;
    uint64_t page_cache_misses;
    uint64_t page_cache_dirty_pages;
    uint64_t page_cache_dirty_bytes;
    uint64_t page_cache_writeback_errors;
    uint64_t page_cache_evictions;
    uint64_t page_cache_writeback_ops;
    uint64_t page_cache_writeback_pages;
    uint64_t page_cache_writeback_cycles;
    uint64_t page_cache_readahead_issued;
    uint64_t page_cache_readahead_useful;
    uint64_t page_cache_readahead_wasted;
    uint64_t page_cache_lock_wait_count;
    uint64_t page_cache_lock_wait_cycles;
} RinFS_ReadStats;

/* Diagnostics are monotonic per mount and intentionally do not affect I/O
 * correctness.  They let boot probes prove that the cache/coalescing fast
 * paths were actually exercised rather than inferring it from wall time. */
void rinfs_read_stats(const RinFS_Mount* mount, RinFS_ReadStats* stats_out);
void rinfs_read_stats_reset(RinFS_Mount* mount);
/* Reclaim up to max_entries clean, unreferenced file pages. Dirty and
 * in-flight entries are never discarded. */
int rinfs_page_cache_reclaim(RinFS_Mount* mount, uint32_t max_entries,
                             uint32_t* reclaimed_out);
/* Process at most max_entries dirty pages from the mounted file cache.
 * This is the bounded background-worker primitive; dirty data and the first
 * writeback error remain observable when the device rejects the request. */
int rinfs_page_cache_writeback_step(RinFS_Mount* mount, uint32_t max_entries,
                                    uint32_t* written_out);
/* Pressure is supplied by the PMM/VFS owner.  It reduces advisory prefetch and
 * promotes bounded dirty writeback: WARNING flushes one page, CRITICAL flushes
 * up to eight, and OOM flushes the cache capacity.  A writeback error is
 * returned and dirty data remains observable. */
int rinfs_page_cache_set_pressure(RinFS_Mount* mount,
                                  RinFS_PageCachePressure pressure);

/* Extended attributes use a compact [u16 name length][u32 value length]
 * record sequence after RinFS_XattrHeader. Names are byte strings rather than
 * C strings so callers can preserve opaque metadata without lossy decoding.
 * list() emits NUL-separated names and always reports the required length. */
int rinfs_xattr_set(RinFS_Mount* mount, uint64_t ino, const char* name,
                    uint32_t name_length, const void* value,
                    uint32_t value_length);
int rinfs_xattr_get(RinFS_Mount* mount, uint64_t ino, const char* name,
                    uint32_t name_length, void* value,
                    uint32_t value_capacity, uint32_t* value_length_out);
int rinfs_xattr_list(RinFS_Mount* mount, uint64_t ino, char* output,
                     uint32_t output_capacity, uint32_t* output_length_out);
int rinfs_xattr_remove(RinFS_Mount* mount, uint64_t ino, const char* name,
                       uint32_t name_length);
/* Clones the complete validated attribute block into destination.  It never
 * aliases metadata blocks, so later edits cannot mutate the source inode. */
int rinfs_xattr_copy(RinFS_Mount* source_mount, uint64_t source_ino,
                     RinFS_Mount* destination_mount,
                     uint64_t destination_ino);
/* Only persistent behaviour flags are copied. Allocation-format and fsck
 * quarantine bits are representation/safety state and are never propagated. */
int rinfs_inode_copy_persistent_flags(RinFS_Mount* source_mount,
                                      uint64_t source_ino,
                                      RinFS_Mount* destination_mount,
                                      uint64_t destination_ino);

/* File operations */
int rinfs_lookup(RinFS_Mount* mount, uint64_t dir_ino, const char* name, uint64_t* ino);
int rinfs_dirent_add(RinFS_Mount* mount, uint64_t dir_ino, const char* name,
                     uint64_t child_ino, uint8_t file_type);
int rinfs_path_lookup(RinFS_Mount* mount, const char* path, uint64_t* ino,
                      RinFS_Inode* inode);
int rinfs_path_lookup_nofollow(RinFS_Mount* mount, const char* path, uint64_t* ino,
                               RinFS_Inode* inode);
int rinfs_create(RinFS_Mount* mount, const char* path, uint16_t mode);
int rinfs_mkdir(RinFS_Mount* mount, const char* path, uint16_t mode);
int rinfs_create_owned(RinFS_Mount* mount, const char* path, uint16_t mode,
                       uint32_t uid, uint32_t gid);
/* Create one regular file below an already resolved parent inode. The name
 * contains one component only; no path traversal or symlink resolution is
 * performed by this operation. */
int rinfs_createat_owned(RinFS_Mount* mount, uint64_t parent_ino,
                         const char* name, uint16_t mode, uint32_t uid,
                         uint32_t gid, uint64_t* created_ino);
/* Create one device/FIFO inode below a resolved parent. Character/block
 * device numbers use the public 8:8 dev_t encoding; FIFO and regular files
 * require device_number=0. SPECIAL_INODES is committed before publication. */
int rinfs_mknodat_owned(RinFS_Mount* mount, uint64_t parent_ino,
                        const char* name, uint16_t mode,
                        uint32_t device_number, uint32_t uid, uint32_t gid,
                        uint64_t* created_ino);
uint32_t rinfs_inode_device_number(const RinFS_Inode* inode);
/* Create an unnamed, zero-link regular inode below a validated parent. The
 * returned open lifetime owns deferred reclamation until a durable link is
 * published or the last descriptor closes. */
int rinfs_create_tmpfile_owned(RinFS_Mount* mount, uint64_t parent_ino,
                               uint16_t mode, uint32_t uid, uint32_t gid,
                               int open_flags, RinFS_File* file);
int rinfs_mkdir_owned(RinFS_Mount* mount, const char* path, uint16_t mode,
                      uint32_t uid, uint32_t gid);
/* Creates one directory component beneath an already resolved parent inode.
 * The name must not contain separators and the operation never follows a
 * symbolic link while selecting the parent. */
int rinfs_mkdirat_owned(RinFS_Mount* mount, uint64_t parent_ino,
                        const char* name, uint16_t mode, uint32_t uid,
                        uint32_t gid, uint64_t* created_ino);
/* Create one directory and return an open lifetime pinned to that exact
 * inode before releasing namespace mutation serialization. */
int rinfs_mkdirat_open_owned(RinFS_Mount* mount, uint64_t parent_ino,
                             const char* name, uint16_t mode, uint32_t uid,
                             uint32_t gid, RinFS_Dir* opened_dir);
int rinfs_unlink(RinFS_Mount* mount, uint64_t dir_ino, const char* name);
int rinfs_unlink_expected(RinFS_Mount* mount, uint64_t dir_ino,
                          const char* name, uint64_t expected_inode,
                          uint32_t expected_generation);
int rinfs_rmdir(RinFS_Mount* mount, uint64_t dir_ino, const char* name);
int rinfs_rmdir_expected(RinFS_Mount* mount, uint64_t dir_ino,
                         const char* name, uint64_t expected_inode,
                         uint32_t expected_generation);
/* Defer removal of an exact directory entry until every open reference to
 * the target inode generation has closed. This is kernel-owned state and
 * remains live across process teardown. */
int rinfs_delete_on_close_register(RinFS_Mount* mount,
                                   uint64_t parent_ino,
                                   uint32_t parent_generation,
                                   const char* name, uint64_t target_ino,
                                   uint32_t target_generation,
                                   int directory, const char* path);
/* Retry all process-exit-safe pending pathname removals for a mounted volume. */
int rinfs_delete_on_close_reap(RinFS_Mount* mount);
/* Attach Win32 access/share admission to this exact open-description owner.
 * Rights use the WinCompat READ/WRITE/DELETE bit layout (1/2/4). */
int rinfs_wincompat_share_register(RinFS_Mount* mount, uint64_t inode_num,
                                   uint32_t inode_generation,
                                   uint64_t content_pin_token,
                                   uint64_t close_generation,
                                   uint64_t close_cookie,
                                   uint64_t mount_epoch,
                                   uint32_t access, uint32_t share_mode);
int rinfs_unlink_entry_expected(RinFS_Mount* mount, uint64_t parent_ino,
                                uint32_t parent_generation, const char* name,
                                uint64_t expected_inode,
                                uint32_t expected_generation);
int rinfs_rmdir_entry_expected(RinFS_Mount* mount, uint64_t parent_ino,
                               uint32_t parent_generation, const char* name,
                               uint64_t expected_inode,
                               uint32_t expected_generation);
int rinfs_rename(RinFS_Mount* mount, uint64_t old_dir, const char* old_name, 
                 uint64_t new_dir, const char* new_name);
/* Atomically rename only when the destination name is absent. */
int rinfs_rename_no_replace(RinFS_Mount* mount, uint64_t old_dir,
                            const char* old_name, uint64_t new_dir,
                            const char* new_name);
/* Atomically rename without replacement only when the source inode and
 * generation still match the caller's pinned identity. */
int rinfs_rename_no_replace_expected(
    RinFS_Mount* mount, uint64_t old_dir, const char* old_name,
    uint64_t new_dir, const char* new_name, uint64_t expected_source_inode,
    uint32_t expected_source_generation);
int rinfs_link(RinFS_Mount* mount, uint64_t dir_ino, const char* name, uint64_t target_ino);
/* Publish an O_TMPFILE lifetime under one name, recovering a persisted
 * directory entry through its orphan-intent marker if power is lost. */
int rinfs_link_tmpfile(RinFS_File* file, uint64_t dir_ino,
                       const char* name);
int rinfs_symlink(RinFS_Mount* mount, uint64_t dir_ino, const char* name, const char* target);
int rinfs_symlink_owned(RinFS_Mount* mount, uint64_t dir_ino, const char* name,
                        const char* target, uint32_t uid, uint32_t gid);
/* Copies at most size target bytes and never appends a terminator. */
int rinfs_readlink(RinFS_Mount* mount, uint64_t ino, char* buf, uint32_t size);
int rinfs_truncate_ino(RinFS_Mount* mount, uint64_t ino, uint64_t size);

/* File I/O */
int rinfs_open(RinFS_Mount* mount, const char* path, int flags, RinFS_File* file);
/* Open a previously validated inode without performing another pathname
 * traversal.  Kernel owners that walk a directory by inode use this to avoid
 * racing a symlink substitution between a checked lookup and file I/O. */
int rinfs_open_ino(RinFS_Mount* mount, uint64_t ino, int flags,
                   RinFS_File* file);
int rinfs_close(RinFS_File* file);
/* Exact close owners report only (consumed=1,retryable=0) or
 * (consumed=0,retryable=1); (0,0) leaves the caller's owner quarantined. */
int rinfs_close_with_disposition(RinFS_File* file, int* consumed_out,
                                 int* retryable_out);
int64_t rinfs_read(RinFS_File* file, void* buf, uint64_t size);
int64_t rinfs_write(RinFS_File* file, const void* buf, uint64_t size);
/* Positional I/O never advances the caller's open-file position.  The
 * inode snapshot is refreshed only after the delegated operation succeeds,
 * so a failed positional operation cannot leave a stale size/timestamp in
 * that descriptor. */
int64_t rinfs_pread(RinFS_File* file, void* buf, uint64_t size,
                    uint64_t offset);
int64_t rinfs_pwrite(RinFS_File* file, const void* buf, uint64_t size,
                     uint64_t offset);
/* Sparse extent positions share the POSIX SEEK_DATA/SEEK_HOLE values. */
#define RINFS_SEEK_DATA 3
#define RINFS_SEEK_HOLE 4
int64_t rinfs_seek(RinFS_File* file, int64_t offset, int whence);
int64_t rinfs_tell(RinFS_File* file);
int rinfs_truncate(RinFS_File* file, uint64_t size);
int rinfs_fsync(RinFS_File* file);

/* Directory operations */
int rinfs_opendir(RinFS_Mount* mount, const char* path, RinFS_Dir* dir);
/* Directory counterpart to rinfs_open_ino(); no pathname components are
 * resolved by this operation. */
int rinfs_opendir_ino(RinFS_Mount* mount, uint64_t ino, RinFS_Dir* dir);
int rinfs_readdir(RinFS_Dir* dir, RinFS_DirEntry* entry);
int rinfs_closedir(RinFS_Dir* dir);
/* Uses the same exact, mutually exclusive disposition contract as file close. */
int rinfs_closedir_with_disposition(RinFS_Dir* dir, int* consumed_out,
                                    int* retryable_out);
void rinfs_rewinddir(RinFS_Dir* dir);
int rinfs_seekdir(RinFS_Dir* dir, uint64_t position);

/* Path operations */
int rinfs_stat(RinFS_Mount* mount, const char* path, RinFS_Inode* inode);

/* Utility */
uint32_t rinfs_checksum(const void* data, uint32_t len);
const char* rinfs_strerror(int err);

#ifndef RIN_FREESTANDING
/* Hosted test/image tooling. These functions are not part of the Rin ABI. */
int rinfs_host_open_disk(const char* path);
void rinfs_host_close_disk(void);
void rinfs_host_fail_writes_after(int successful_writes);
void rinfs_host_fail_flushes_after(int successful_flushes);
#endif

/* Error codes */
#define RINFS_OK            0
#define RINFS_ERR           -1
#define RINFS_ERR_IO        -2
#define RINFS_ERR_NOMEM     -3
#define RINFS_ERR_NOSPC     -4
#define RINFS_ERR_NOENT     -5
#define RINFS_ERR_EXIST     -6
#define RINFS_ERR_NOTDIR    -7
#define RINFS_ERR_ISDIR     -8
#define RINFS_ERR_NOTEMPTY  -9
#define RINFS_ERR_NAMETOOLONG -10
#define RINFS_ERR_INVAL     -11
#define RINFS_ERR_ROFS      -12
#define RINFS_ERR_CORRUPT   -13
#define RINFS_ERR_LOOP      -14
#define RINFS_ERR_PENDING   -15
#define RINFS_ERR_OVERFLOW  -17
#define RINFS_ERR_NOT_SUPPORTED -16
#define RINFS_ERR_STALE     -18
#define RINFS_ERR_EMLINK    -19
#define RINFS_ERR_BUSY      -20

/* i_links is a fixed-width on-disk count.  Do not let a hard-link mutation
 * wrap it back to zero: callers receive EMLINK at the POSIX boundary. */
#define RINFS_LINK_MAX      UINT32_MAX

#endif /* RINFS_H */
