#ifndef IPF_H_
#define IPF_H_

#include <assert.h>
#include <list.h>
#include "lru_cache.h"

#ifndef __UNUSED
#define __UNUSED(x) do { (void)(x); } while (0)
#endif

#pragma pack(push, 1)

/*! Size of the AES-GCM encryption key */
#define PF_KEY_SIZE  16

/*! Size of IV for AES-GCM */
#define PF_IV_SIZE   12

/*! Size of MAC fields */
#define PF_MAC_SIZE  16

typedef uint8_t pf_iv_t[PF_IV_SIZE];
typedef uint8_t pf_mac_t[PF_MAC_SIZE];
typedef uint8_t pf_key_t[PF_KEY_SIZE];
typedef uint8_t pf_keyid_t[32];

typedef enum _pf_status_t {
    PF_STATUS_SUCCESS           = 0,
    PF_STATUS_UNKNOWN_ERROR     = -1,
    PF_STATUS_UNINITIALIZED     = -2,
    PF_STATUS_INVALID_PARAMETER = -3,
    PF_STATUS_INVALID_MODE      = -4,
    PF_STATUS_INVALID_CONTEXT   = -5,
    PF_STATUS_NO_MEMORY         = -6,
    PF_STATUS_INVALID_VERSION   = -7,
    PF_STATUS_INVALID_HEADER    = -8,
    PF_STATUS_INVALID_PATH      = -9,
    PF_STATUS_MAC_MISMATCH      = -10,
    PF_STATUS_NOT_IMPLEMENTED   = -11,
    PF_STATUS_CALLBACK_FAILED   = -12,
    PF_STATUS_PATH_TOO_LONG     = -13,
    PF_STATUS_RECOVERY_NEEDED   = -14,
    PF_STATUS_FLUSH_ERROR       = -15,
    PF_STATUS_CRYPTO_ERROR      = -16,
    PF_STATUS_CORRUPTED         = -17,
    PF_STATUS_WRITE_TO_DISK_FAILED = -18,
    PF_STATUS_RECOVERY_IMPOSSIBLE  = -19,
} pf_status_t;

#define PF_SUCCESS(status) ((status) == PF_STATUS_SUCCESS)
#define PF_FAILURE(status) ((status) != PF_STATUS_SUCCESS)

/*! PF open/map modes */
typedef enum _pf_file_mode_t {
    PF_FILE_MODE_READ  = 1,
    PF_FILE_MODE_WRITE = 2,
} pf_file_mode_t;

/*! Opaque file handle type, interpreted by callbacks as necessary */
typedef void* pf_handle_t;

/*!
 * \brief Allocate memory callback
 *
 * \param [in] size Size to allocate
 * \return Allocated address or NULL if failed
 *
 * \details Must zero the allocated buffer
 */
typedef void* (*pf_malloc_f)(size_t size);

/*!
 * \brief Free memory callback
 *
 * \param [in] address Address to free
 *
 * \details Must accept NULL pointers
 */
typedef void (*pf_free_f)(void* address);

/*!
 * \brief File map callback
 *
 * \param [in] handle File handle
 * \param [in] mode Access mode
 * \param [in] offset Starting offset of the region to map
 * \param [in] size Size of the region to map
 * \param [out] address Mapped address
 * \return PF status
 */
typedef pf_status_t (*pf_map_f)(pf_handle_t handle, pf_file_mode_t mode, size_t offset, size_t size,
                                void** address);

/*!
 * \brief File unmap callback
 *
 * \param [in] address Address to unmap
 * \param [in] size Size of mapped region
 * \return PF status
 */
typedef pf_status_t (*pf_unmap_f)(void* address, size_t size);

/*!
 * \brief File truncate callback
 *
 * \param [in] handle File handle
 * \param [in] size Target file size
 * \return PF status
 */
typedef pf_status_t (*pf_truncate_f)(pf_handle_t handle, size_t size);

/*!
 * \brief File flush callback
 *
 * \param [in] handle File handle
 * \return PF status
 */
typedef pf_status_t (*pf_flush_f)(pf_handle_t handle);

/*!
 * \brief File open callback
 *
 * \param [in] path File path
 * \param [in] mode Open mode
 * \param [out] handle File handle
 * \param [out] size (optional) File size
 * \return PF status
 */
typedef pf_status_t (*pf_open_f)(const char* path, pf_file_mode_t mode, pf_handle_t* handle, size_t* size);

/*!
 * \brief File close callback
 *
 * \param [in] handle File handle
 * \return PF status
 */
typedef pf_status_t (*pf_close_f)(pf_handle_t handle);

/*!
 * \brief File delete callback
 *
 * \param [in] path File path
 * \return PF status
 */
typedef pf_status_t (*pf_delete_f)(const char* path);

/*!
 * \brief Debug print callback
 *
 * \param [in] msg Message to print
 */
typedef void (*pf_debug_f)(const char* msg);

/*!
 * \brief AES-GCM encrypt callback
 *
 * \param [in] key AES-GCM key
 * \param [in] iv Initialization vector
 * \param [in] aad (optional) Additional authenticated data
 * \param [in] aad_size Size of \a aad in bytes
 * \param [in] input Plaintext data
 * \param [in] input_size Size of \a input in bytes
 * \param [out] output Buffer for encrypted data (size: \a input_size)
 * \param [out] mac MAC computed for \a input and \a aad
 * \return PF status
 */
typedef pf_status_t (*pf_crypto_aes_gcm_encrypt_f)(const pf_key_t* key, const pf_iv_t* iv,
                                                   const void* aad, size_t aad_size,
                                                   const void* input, size_t input_size,
                                                   void* output, pf_mac_t* mac);

/*!
 * \brief AES-GCM decrypt callback
 *
 * \param [in] key AES-GCM key
 * \param [in] iv Initialization vector
 * \param [in] aad (optional) Additional authenticated data
 * \param [in] aad_size Size of \a aad in bytes
 * \param [in] input Encrypted data
 * \param [in] input_size Size of \a input in bytes
 * \param [out] output Buffer for decrypted data (size: \a input_size)
 * \param [in] mac Expected MAC
 * \return PF status
 */
typedef pf_status_t (*pf_crypto_aes_gcm_decrypt_f)(const pf_key_t* key, const pf_iv_t* iv,
                                                   const void* aad, size_t aad_size,
                                                   const void* input, size_t input_size,
                                                   void* output, const pf_mac_t* mac);

/*!
 * \brief Cryptographic random number generator callback
 *
 * \param [out] buffer Buffer to fill with random bytes
 * \param [in] size Size of \a buffer in bytes
 * \return PF status
 */
typedef pf_status_t (*pf_crypto_random_f)(uint8_t* buffer, size_t size);

/*!
 * \brief Initialize I/O callbacks
 *
 * \param [in] malloc_f Allocate memory callback
 * \param [in] free_f Free memory callback
 * \param [in] map_f File map callback
 * \param [in] unmap_f File unmap callback
 * \param [in] truncate_f File truncate callback
 * \param [in] flush_f File flush callback
 * \param [in] open_f File open callback
 * \param [in] close_f File close callback
 * \param [in] delete_f File delete callback
 * \param [in] debug_f (optional) Debug print callback
 *
 * \details Must be called before any actual APIs
 */
void pf_set_callbacks(pf_malloc_f malloc_f, pf_free_f free_f, pf_map_f map_f, pf_unmap_f unmap_f,
                      pf_truncate_f truncate_f, pf_flush_f flush_f, pf_open_f open_f,
                      pf_close_f close_f, pf_delete_f delete_f, pf_debug_f debug_f);

/*!
 * \brief Initialize cryptographic callbacks
 *
 * \param [in] crypto_aes_gcm_encrypt_f AES-GCM encrypt callback
 * \param [in] crypto_aes_gcm_decrypt_f AES-GCM decrypt callback
 * \param [in] crypto_aes_cmac_f AES-CMAC callback
 * \param [in] crypto_random_f Cryptographic random number generator callback
 *
 * \details Must be called before any actual APIs
 */
void pf_set_crypto_callbacks(pf_crypto_aes_gcm_encrypt_f crypto_aes_gcm_encrypt_f,
                             pf_crypto_aes_gcm_decrypt_f crypto_aes_gcm_decrypt_f,
                             pf_crypto_random_f crypto_random_f);


#define PF_DEBUG_PRINT_SIZE_MAX 4096


// Intel format follows
#define SGX_FILE_ID            0x5347585F46494C45 // SGX_FILE
#define SGX_FILE_MAJOR_VERSION 0x01
#define SGX_FILE_MINOR_VERSION 0x00

#define NODE_SIZE 4096

typedef struct _meta_data_plain {
    uint64_t file_id;
    uint8_t  major_version;
    uint8_t  minor_version;

    pf_keyid_t meta_data_key_id;
    //sgx_cpu_svn_t    cpu_svn;
    //sgx_isv_svn_t    isv_svn;
    //uint8_t          use_user_kdk_key; // always true
    //sgx_attributes_t attribute_mask;

    pf_mac_t meta_data_gmac;
    uint8_t  update_flag;
} meta_data_plain_t;

// these are all defined as relative to node size, so we can decrease node size in tests and have deeper tree
#define FILENAME_MAX_LEN  260
#define MD_USER_DATA_SIZE (NODE_SIZE*3/4)  // 3072
static_assert(MD_USER_DATA_SIZE == 3072, "bad struct size");

typedef struct _meta_data_encrypted {
    char     clean_filename[FILENAME_MAX_LEN];
    int64_t  size;
    pf_key_t mht_key;
    pf_mac_t mht_gmac;
    uint8_t  data[MD_USER_DATA_SIZE];
} meta_data_encrypted_t;

typedef uint8_t meta_data_encrypted_blob_t[sizeof(meta_data_encrypted_t)];

#define META_DATA_NODE_SIZE NODE_SIZE
typedef uint8_t meta_data_padding_t[META_DATA_NODE_SIZE - (sizeof(meta_data_plain_t) + sizeof(meta_data_encrypted_blob_t))];

typedef struct _meta_data_node {
    meta_data_plain_t          plain_part;
    meta_data_encrypted_blob_t encrypted_part;
    meta_data_padding_t        padding;
} meta_data_node_t;

static_assert(sizeof(meta_data_node_t) == NODE_SIZE, "sizeof_meta_data_node_t");

typedef struct _data_node_crypto {
    pf_key_t key;
    pf_mac_t gmac;
} gcm_crypto_data_t;

// for NODE_SIZE == 4096, we have 96 attached data nodes and 32 mht child nodes
// for NODE_SIZE == 2048, we have 48 attached data nodes and 16 mht child nodes
// for NODE_SIZE == 1024, we have 24 attached data nodes and 8 mht child nodes
#define ATTACHED_DATA_NODES_COUNT ((NODE_SIZE/sizeof(gcm_crypto_data_t))*3/4) // 3/4 of the node size is dedicated to data nodes
static_assert(ATTACHED_DATA_NODES_COUNT == 96, "attached_data_nodes_count");
#define CHILD_MHT_NODES_COUNT ((NODE_SIZE/sizeof(gcm_crypto_data_t))*1/4) // 1/4 of the node size is dedicated to child mht nodes
static_assert(CHILD_MHT_NODES_COUNT == 32, "child_mht_nodes_count");

typedef struct _mht_node {
    gcm_crypto_data_t data_nodes_crypto[ATTACHED_DATA_NODES_COUNT];
    gcm_crypto_data_t mht_nodes_crypto[CHILD_MHT_NODES_COUNT];
} mht_node_t;

static_assert(sizeof(mht_node_t) == NODE_SIZE, "sizeof_mht_node_t");

typedef struct _data_node {
    uint8_t data[NODE_SIZE];
} data_node_t;

static_assert(sizeof(data_node_t) == NODE_SIZE, "sizeof_data_node_t");

typedef struct _encrypted_node {
    uint8_t cipher[NODE_SIZE];
} encrypted_node_t;

static_assert(sizeof(encrypted_node_t) == NODE_SIZE, "sizeof_encrypted_node_t");

typedef struct _recovery_node {
    uint64_t physical_node_number;
    uint8_t  node_data[NODE_SIZE];
} recovery_node_t;

/// FILE FORMAT

#define MAX_PAGES_IN_CACHE 48

typedef union {
    struct {
        uint8_t read   :1;
        uint8_t write  :1;
        uint8_t append :1;
        uint8_t update :1;
    };
    uint8_t raw;
} open_mode_t;

typedef enum {
    FILE_MHT_NODE_TYPE = 1,
    FILE_DATA_NODE_TYPE = 2,
} mht_node_type_e;

#define PATHNAME_MAX_LEN      (512)
#define FULLNAME_MAX_LEN      (PATHNAME_MAX_LEN + FILENAME_MAX_LEN)
#define RECOVERY_FILE_MAX_LEN (FULLNAME_MAX_LEN + 10)

DEFINE_LIST(_file_mht_node);
typedef struct _file_mht_node {
    LIST_TYPE(_file_mht_node) list;
    /* these are exactly the same as file_data_node_t below, any change should apply to both (both are saved in the cache as void*) */
    uint8_t type;
    uint64_t mht_node_number;
    struct _file_mht_node* parent;
    bool need_writing;
    bool new_node;
    union {
        struct {
            uint64_t physical_node_number;
            encrypted_node_t encrypted; // the actual data from the disk
        };
        recovery_node_t recovery_node;
    };
    /* from here the structures are different */
    mht_node_t plain; // decrypted data
} file_mht_node_t;
DEFINE_LISTP(_file_mht_node);

DEFINE_LIST(_file_data_node);
typedef struct _file_data_node {
    LIST_TYPE(_file_data_node) list;
    /* these are exactly the same as file_mht_node_t above, any change should apply to both (both are saved in the cache as void*) */
    uint8_t type;
    uint64_t data_node_number;
    file_mht_node_t* parent;
    bool need_writing;
    bool new_node;
    union {
        struct {
            uint64_t physical_node_number;
            encrypted_node_t encrypted; // the actual data from the disk
        };
        recovery_node_t recovery_node;
    };
    /* from here the structures are different */
    data_node_t plain; // decrypted data
} file_data_node_t;
DEFINE_LISTP(_file_data_node);

extern pf_status_t pf_last_error; // last operation error

#pragma pack(pop)

typedef struct _ipf_context {
    union {
        struct {
            uint64_t meta_data_node_number; // for recovery purpose, so it is easy to write this node
            meta_data_node_t file_meta_data; // actual data from disk's meta data node
        };
        recovery_node_t meta_data_recovery_node;
    };

    meta_data_encrypted_t encrypted_part_plain; // encrypted part of meta data node, decrypted
    file_mht_node_t root_mht; // the root of the mht is always needed (for files bigger than 3KB)
    pf_handle_t file; // TODO: rename to handle
    open_mode_t open_mode;
    uint8_t read_only;
    int64_t offset; // current file position (user's view)
    bool end_of_file; // flag
    size_t real_file_size;
    bool need_writing; // flag
    pf_status_t file_status;
    // mutex
    pf_key_t user_kdk_key;
    pf_key_t cur_key;
    pf_key_t session_master_key;
    uint32_t master_key_count;
    char recovery_filename[RECOVERY_FILE_MAX_LEN]; // might include full path to the file
    lruc_context_t cache;
    char* debug_buffer; //!< Buffer for debug output
} pf_context;

typedef pf_context* pf_context_t;

// private
// file_init.cpp
bool ipf_cleanup_filename(const char* src, char* dest);
void ipf_init_fields(pf_context_t ipf);
bool ipf_file_recovery(pf_context_t ipf, const char* filename);
bool ipf_init_existing_file(pf_context_t ipf, const char* filename, const char* clean_filename/*, const pf_key_t* import_key*/);
bool ipf_init_new_file(pf_context_t ipf, const char* clean_filename);

// sgx_uprotected_fs.cpp
bool ipf_read_node(pf_handle_t file, uint64_t node_number, void* buffer, uint32_t node_size);
bool ipf_write_node(pf_handle_t file, uint64_t node_number, void* buffer, uint32_t node_size);

// file_crypto.cpp
bool ipf_generate_secure_blob(pf_key_t* key, const char* label, uint64_t physical_node_number, pf_mac_t* output);
bool ipf_generate_secure_blob_from_user_kdk(pf_context_t ipf, bool restore);
bool ipf_init_session_master_key(pf_context_t ipf);
bool ipf_derive_random_node_key(pf_context_t ipf, uint64_t physical_node_number);
bool ipf_generate_random_meta_data_key(pf_context_t ipf);
bool ipf_restore_current_meta_data_key(pf_context_t ipf/*, const pf_key_t* import_key*/);

file_data_node_t* ipf_get_data_node(pf_context_t ipf);
file_data_node_t* ipf_read_data_node(pf_context_t ipf);
file_data_node_t* ipf_append_data_node(pf_context_t ipf);
file_mht_node_t*  ipf_get_mht_node(pf_context_t ipf);
file_mht_node_t*  ipf_read_mht_node(pf_context_t ipf, uint64_t mht_node_number);
file_mht_node_t*  ipf_append_mht_node(pf_context_t ipf, uint64_t mht_node_number);
bool ipf_write_recovery_file(pf_context_t ipf);
bool ipf_set_update_flag(pf_context_t ipf, bool flush_to_disk);
void ipf_clear_update_flag(pf_context_t ipf);
bool ipf_update_all_data_and_mht_nodes(pf_context_t ipf);
bool ipf_update_meta_data_node(pf_context_t ipf);
bool ipf_write_all_changes_to_disk(pf_context_t ipf, bool flush_to_disk);
bool ipf_erase_recovery_file(pf_context_t ipf);
bool ipf_internal_flush(pf_context_t ipf, /*bool mc,*/ bool flush_to_disk);
bool ipf_do_file_recovery(const char* filename, const char* recovery_filename, uint32_t node_size);
bool ipf_pre_close(pf_context_t ipf/*, pf_key_t* key, bool import*/);
bool ipf_clear_cache(pf_context_t ipf);

pf_context_t ipf_open(const char* filename, open_mode_t mode, pf_handle_t file, size_t real_size, const pf_key_t* kdk_key);
bool ipf_close(pf_context_t ipf);
size_t ipf_read(pf_context_t ipf, void* ptr, size_t size, size_t count);
size_t ipf_write(pf_context_t ipf, const void* ptr, size_t size, size_t count);
int64_t ipf_tell(pf_context_t ipf);
bool ipf_seek(pf_context_t ipf, int64_t new_offset, int origin);
bool ipf_get_eof(pf_context_t ipf);
pf_status_t ipf_get_error(pf_context_t ipf);
void ipf_clear_error(pf_context_t ipf);
bool ipf_flush(pf_context_t ipf/*, bool mc*/);
bool ipf_remove(const char* filename);

#ifndef SEEK_SET
#define	SEEK_SET	0	/* set file offset to offset */
#endif
#ifndef SEEK_CUR
#define	SEEK_CUR	1	/* set file offset to current plus offset */
#endif
#ifndef SEEK_END
#define	SEEK_END	2	/* set file offset to EOF plus offset */
#endif

// public

/*!
 * \brief Open a protected file
 *
 * \param [in] handle Opened underlying file handle
 * \param [in] path Path to the file. If NULL and \a create is false, don't check path for validity.
 * \param [in] underlying_size Underlying file size
 * \param [in] mode Access mode
 * \param [in] create Overwrite file contents if true
 * \param [in] key Wrap key
 * \param [out] context PF context for later calls
 * \return PF status
 */
pf_status_t pf_open(pf_handle_t handle, const char* path, size_t underlying_size, pf_file_mode_t mode,
                    bool create, const pf_key_t* key, pf_context_t* context);

/*!
 * \brief Close a protected file and commit all changes to disk
 *
 * \param [in] pf PF context
 * \return PF status
 */
pf_status_t pf_close(pf_context_t pf);

/*!
 * \brief Read from a protected file
 *
 * \param [in] pf PF context
 * \param [in] offset Data offset to read from
 * \param [in] size Number of bytes to read
 * \param [out] output Destination buffer
 * \return PF status
 */
pf_status_t pf_read(pf_context_t pf, uint64_t offset, size_t size, void* output);

/*!
 * \brief Write to a protected file
 *
 * \param [in] pf PF context
 * \param [in] offset Data offset to write to
 * \param [in] size Number of bytes to write
 * \param [in] input Source buffer
 * \return PF status
 */
pf_status_t pf_write(pf_context_t pf, uint64_t offset, size_t size, const void* input);

#if 0 // new format probably won't use these
/*!
 * \brief Decrypt a single chunk
 *
 * \param [in] pf PF context
 * \param [in] chunk_number Expected chunk number
 * \param [in] chunk Encrypted chunk with metadata (pf_chunk_t)
 * \param [in] chunk_size Size of \a output
 * \param [out] output Decrypted chunk data
 * \return PF status
 */
pf_status_t pf_decrypt_chunk(pf_context_t pf, uint64_t chunk_number, const pf_chunk_t* chunk,
                             uint32_t chunk_size, void* output);

/*!
 * \brief Encrypt a single chunk
 *
 * \param [in] pf PF context
 * \param [in] chunk_number Chunk number
 * \param [in] input Chunk data to encrypt
 * \param [in] chunk_size Size of \a input
 * \param [out] output Output encrypted chunk, size PF_CHUNK_SIZE
 * \return PF status
 */
pf_status_t pf_encrypt_chunk(pf_context_t pf, uint64_t chunk_number, const void* input,
                             uint32_t chunk_size, pf_chunk_t* output);
#endif

/*!
 * \brief Check whether a PF was opened with specified access mode
 *
 * \param [in] pf PF context
 * \param [in] mode Access mode to check for
 * \param [out] result True if the PF was opened with specified access mode
 * \return PF status
 */
pf_status_t pf_has_mode(pf_context_t pf, pf_file_mode_t mode, bool* result);

/*!
 * \brief Get data size of a PF
 *
 * \param [in] pf PF context
 * \param [out] size Data size of \a pf
 * \return PF status
 */
pf_status_t pf_get_size(pf_context_t pf, size_t* size);

/*!
 * \brief Set data size of a PF
 *
 * \param [in] pf PF context
 * \param [in] size Data size to set
 * \return PF status
 */
pf_status_t pf_set_size(pf_context_t pf, size_t size);

#endif
