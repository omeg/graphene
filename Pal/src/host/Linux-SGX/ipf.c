#include "ipf.h"
#include <pal_crypto.h>

// global/util
#if 1
inline bool consttime_memequal(const void* a, const void* b, size_t size) {
    uint32_t x;

    __asm(
    "movq   %3, %%rcx\n"
    "xorl   %0, %0\n"
    "jmp    2f\n"
"1:\n"
    "movzbl (%1, %%rcx), %%edx\n"
    "movzbl (%2, %%rcx), %%eax\n"
    "xorl   %%edx, %%eax\n"
    "orl    %%eax, %0\n"
"2:\n"
    "decq   %%rcx\n"
    "jns    1b\n"

    :"=r"(x) /* x = %0 */
    :"r"(a), "r"(b), "g"(size) /* a = %1, b = %2, size = %3 */
    :"%rax", "%rcx", "%rdx"
    );
    return x == 0;
}
#endif

char* strncpy(char* dest, const char* src, size_t size) {
    size_t src_len = strlen(src) + 1;
    size_t len = src_len < size ? src_len : size;
    memcpy(dest, src, len);
    return dest;
}

// ocalls

// file_version.cpp

#define STRFILEVER "2.7.101.3"
char sgx_tprotectedfs_version[] = "SGX_TPROTECTEDFS_VERSION_" STRFILEVER;

// file_crypto.cpp
#define MASTER_KEY_NAME       "SGX-PROTECTED-FS-MASTER-KEY"
#define RANDOM_KEY_NAME       "SGX-PROTECTED-FS-RANDOM-KEY"
#define METADATA_KEY_NAME     "SGX-PROTECTED-FS-METADATA-KEY"
#define MAX_LABEL_LEN         64
#define MAX_MASTER_KEY_USAGES 65536

typedef struct {
    uint32_t index;
    char label[MAX_LABEL_LEN];
    uint64_t node_number; // context 1
    union { // context 2
        pf_mac_t nonce16;
        sgx_key_id_t nonce32;
    };
    uint32_t output_len; // in bits
} kdf_input_t;

bool ipf_generate_secure_blob(pf_key_t* key, const char* label, uint64_t physical_node_number, pf_mac_t* output) {
    kdf_input_t buf = {0};

    uint32_t len = (uint32_t)strnlen(label, MAX_LABEL_LEN + 1);
    if (len > MAX_LABEL_LEN) {
        ipf_last_error = IPF_STATUS_INVALID_PARAMETER;
        return false;
    }

    // index
    // SP800-108:
    // i - A counter, a binary string of length r that is an input to each iteration of a PRF in counter mode [...].
    buf.index = 0x01;

    // label
    // SP800-108:
    // Label - A string that identifies the purpose for the derived keying material, which is encoded as a binary string. 
    //         The encoding method for the Label is defined in a larger context, for example, in the protocol that uses a KDF.
    strncpy(buf.label, label, len);

    // context and nonce
    // SP800-108: 
    // Context - A binary string containing the information related to the derived keying material.
    //           It may include identities of parties who are deriving and / or using the derived keying material and, 
    //           optionally, a nonce known by the parties who derive the keys.
    buf.node_number = physical_node_number;

    int status = _DkRandomBitsRead(&buf.nonce16, sizeof(buf.nonce16));
    if (status != 0) {
        ipf_last_error = IPF_STATUS_RANDOM_ERROR;
        return false;
    }

    // length of output (128 bits)
    buf.output_len = 0x80;

    //status = sgx_rijndael128_cmac_msg(key, (const uint8_t*)&buf, sizeof(buf), output);
    status = lib_AESCMAC((const uint8_t*)key, sizeof(*key), (const uint8_t*)&buf, sizeof(buf),
        (uint8_t*)output, sizeof(*output));
    if (status != 0) {
        ipf_last_error = IPF_STATUS_CRYPTO_ERROR;
        return false;
    }

    memset(&buf, 0, sizeof(buf)); // TODO: memset_s

    return true;
}

bool ipf_generate_secure_blob_from_user_kdk(ipf_context_t ipf, bool restore) {
    kdf_input_t buf = {0};
    int status = -1;

    // index
    // SP800-108:
    // i - A counter, a binary string of length r that is an input to each iteration of a PRF in counter mode [...].
    buf.index = 0x01;

    // label
    // SP800-108:
    // Label - A string that identifies the purpose for the derived keying material, which is encoded as a binary string. 
    //         The encoding method for the Label is defined in a larger context, for example, in the protocol that uses a KDF.
    strncpy(buf.label, METADATA_KEY_NAME, strlen(METADATA_KEY_NAME));

    // context and nonce
    // SP800-108: 
    // Context - A binary string containing the information related to the derived keying material.
    //           It may include identities of parties who are deriving and / or using the derived keying material and, 
    //           optionally, a nonce known by the parties who derive the keys.
    buf.node_number = 0;

    // use 32 bytes here just for compatibility with the seal key API
    if (!restore) {
        status = _DkRandomBitsRead(&buf.nonce32, sizeof(buf.nonce32));
        if (status != 0) {
            ipf_last_error = IPF_STATUS_RANDOM_ERROR;
            return false;
        }
    } else {
        memcpy(&buf.nonce32, &ipf->file_meta_data.plain_part.meta_data_key_id, sizeof(buf.nonce32));
    }
    

    // length of output (128 bits)
    buf.output_len = 0x80;

    //status = sgx_rijndael128_cmac_msg(&user_kdk_key, (const uint8_t*)&buf, sizeof(kdf_input_t), &cur_key);
    status = lib_AESCMAC((const uint8_t*)&ipf->user_kdk_key, sizeof(ipf->user_kdk_key),
        (const uint8_t*)&buf, sizeof(buf), (uint8_t*)&ipf->cur_key, sizeof(ipf->cur_key));
    if (status != 0) {
        ipf_last_error = IPF_STATUS_CRYPTO_ERROR;
        return false;
    }

    if (!restore) {
        memcpy(&ipf->file_meta_data.plain_part.meta_data_key_id, &buf.nonce32,
            sizeof(ipf->file_meta_data.plain_part.meta_data_key_id));
    }

    memset(&buf, 0, sizeof(kdf_input_t)); // TODO: memset_s

    return true;
}

bool ipf_init_session_master_key(ipf_context_t ipf) {
    pf_key_t empty_key = {0};
        
    if (!ipf_generate_secure_blob(&empty_key, MASTER_KEY_NAME, 0, (pf_mac_t*)&ipf->session_master_key))
        return false;

    ipf->master_key_count = 0;

    return true;
}

bool ipf_derive_random_node_key(ipf_context_t ipf, uint64_t physical_node_number) {
    if (ipf->master_key_count++ > MAX_MASTER_KEY_USAGES) {
        if (!ipf_init_session_master_key(ipf))
            return false;
    }

    if (!ipf_generate_secure_blob(&ipf->session_master_key, RANDOM_KEY_NAME, physical_node_number,
        (pf_mac_t*)&ipf->cur_key))
        return false;

    return true;
}

bool ipf_generate_random_meta_data_key(ipf_context_t ipf) {
    // we don't use autogenerated keys
    return ipf_generate_secure_blob_from_user_kdk(ipf, false);

/*
    if (use_user_kdk_key == 1)
    {
        return generate_secure_blob_from_user_kdk(false);
    }

    // derive a random key from the enclave sealing key 
    sgx_key_request_t key_request;
    memset(&key_request, 0, sizeof(sgx_key_request_t)); 
        
    key_request.key_name = SGX_KEYSELECT_SEAL;
    key_request.key_policy = SGX_KEYPOLICY_MRSIGNER;

    memcpy(&key_request.cpu_svn, &report.body.cpu_svn, sizeof(sgx_cpu_svn_t));
    memcpy(&key_request.isv_svn, &report.body.isv_svn, sizeof(sgx_isv_svn_t));

    key_request.attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    key_request.attribute_mask.xfrm = 0x0;

    key_request.misc_mask = TSEAL_DEFAULT_MISCMASK;
        
    sgx_status_t status = sgx_read_rand((unsigned char*)&key_request.key_id, sizeof(sgx_key_id_t));
    if (status != SGX_SUCCESS)
    {
        last_error = status;
        return false;
    }
    
    status = sgx_get_key(&key_request, &cur_key);
    if (status != SGX_SUCCESS)
    {
        last_error = status;
        return false;
    }

    // save the key_id and svn's so the key can be restored even if svn's are updated
    memcpy(&file_meta_data.plain_part.meta_data_key_id, &key_request.key_id, sizeof(sgx_key_id_t)); // save this value in the meta data
    memcpy(&file_meta_data.plain_part.cpu_svn, &key_request.cpu_svn, sizeof(sgx_cpu_svn_t));
    memcpy(&file_meta_data.plain_part.isv_svn, &key_request.isv_svn, sizeof(sgx_isv_svn_t));

    return true;
    */
}

bool ipf_restore_current_meta_data_key(ipf_context_t ipf, const pf_key_t* import_key) {
    if (import_key != NULL) {       
        memcpy(&ipf->cur_key, import_key, sizeof(ipf->cur_key));
        return true;
    }
    // we don't use autogenerated keys
    return ipf_generate_secure_blob_from_user_kdk(ipf, true);

/*
    if (use_user_kdk_key == 1)
    {
        return generate_secure_blob_from_user_kdk(true);
    }

    sgx_key_id_t empty_key_id = {0};
    if (consttime_memequal(&file_meta_data.plain_part.meta_data_key_id, &empty_key_id, sizeof(sgx_key_id_t)) == 1)
    {
        last_error = SGX_ERROR_FILE_NO_KEY_ID;
        return false;
    }

    sgx_key_request_t key_request;
    memset(&key_request, 0, sizeof(sgx_key_request_t));

    key_request.key_name = SGX_KEYSELECT_SEAL;
    key_request.key_policy = SGX_KEYPOLICY_MRSIGNER;

    key_request.attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    key_request.attribute_mask.xfrm = 0x0;

    key_request.misc_mask = TSEAL_DEFAULT_MISCMASK;

    memcpy(&key_request.cpu_svn, &file_meta_data.plain_part.cpu_svn, sizeof(sgx_cpu_svn_t));
    memcpy(&key_request.isv_svn, &file_meta_data.plain_part.isv_svn, sizeof(sgx_isv_svn_t));
    memcpy(&key_request.key_id, &file_meta_data.plain_part.meta_data_key_id, sizeof(sgx_key_id_t));

    sgx_status_t status = sgx_get_key(&key_request, &cur_key);
    if (status != SGX_SUCCESS)
    {
        last_error = status;
        return false;
    }

    return true;
*/
}

// file_init.cpp

bool ipf_cleanup_filename(const char* src, char* dest) {
    const char* p = src;
    const char* name = src;

    while (*p) {
        if ((*p) == '\\' || (*p) == '/')
            name = p + 1;
        p++;
    }

    if (strnlen(name, FILENAME_MAX_LEN) >= FILENAME_MAX_LEN - 1) {
        ipf_last_error = IPF_STATUS_NAME_TOO_LONG;
        return false;
    }

    memcpy(dest, name, FILENAME_MAX_LEN - 1);
    dest[FILENAME_MAX_LEN - 1] = '\0';

    if (strnlen(dest, 1) == 0) {
        ipf_last_error = IPF_STATUS_INVALID_PARAMETER;
        return false;
    }

    return true;
}

void ipf_init_fields(ipf_context_t ipf) {
    ipf->meta_data_node_number = 0;
    memset(&ipf->file_meta_data, 0, sizeof(ipf->file_meta_data));
    memset(&ipf->encrypted_part_plain, 0, sizeof(ipf->encrypted_part_plain));
    memset(&ipf->empty_iv, 0, sizeof(ipf->empty_iv));
    memset(&ipf->root_mht, 0, sizeof(ipf->root_mht));

    ipf->root_mht.type = FILE_MHT_NODE_TYPE;
    ipf->root_mht.physical_node_number = 1;
    ipf->root_mht.mht_node_number = 0;
    ipf->root_mht.new_node = true;
    ipf->root_mht.need_writing = false;

    ipf->offset = 0;
    ipf->file = -1;
    ipf->end_of_file = false;
    ipf->need_writing = false;
    ipf->read_only = 0;
    ipf->file_status = IPF_STATUS_NOT_INITIALIZED;
    ipf_last_error = IPF_STATUS_OK;
    ipf->real_file_size = 0;
    ipf->open_mode.raw = 0;
    ipf->master_key_count = 0;

    ipf->recovery_filename[0] = '\0';

    //memset(&mutex, 0, sizeof(sgx_thread_mutex_t));

    // set hash size to fit MAX_PAGES_IN_CACHE
    //ipf->cache.rehash(MAX_PAGES_IN_CACHE);
}

// constructor
ipf_context_t ipf_init(const char* filename, open_mode_t mode, int fd, size_t real_size, const pf_key_t* kdk_key) {
    //int status = 0;
    //uint8_t result = 0;
    //int32_t result32 = 0;
    ipf_context* ipf = malloc(sizeof(ipf_context));

    // TODO: free on failure
    if (!ipf) {
        ipf_last_error = IPF_STATUS_NO_MEMORY;
        return NULL;
    }

    ipf_init_fields(ipf);

    if (filename == NULL || strnlen(filename, 1) == 0 || kdk_key == NULL || 
        (mode.write == 0 && mode.read == 0 && mode.append == 0)) {

        ipf_last_error = IPF_STATUS_INVALID_PARAMETER;
        return NULL;
    }

    if (strnlen(filename, FULLNAME_MAX_LEN) >= FULLNAME_MAX_LEN - 1) {
        ipf_last_error = IPF_STATUS_NAME_TOO_LONG;
        return NULL;
    }

    // we don't use autogenerated keys, use_user_kdk_key is always true
/*
    if (import_key != NULL && kdk_key != NULL)
    {// import key is used only with auto generated keys
        last_error = EINVAL;
        return;
    }
*/
    if (!ipf_init_session_master_key(ipf))
        // last_error already set
        return NULL;

    //if (kdk_key != NULL)
    {
        // for new file, this value will later be saved in the meta data plain part (init_new_file)
        // for existing file, we will later compare this value with the value from the file (init_existing_file)
        //use_user_kdk_key = 1; 
        pf_key_t empty_key = {0};
        if (consttime_memequal(kdk_key, &empty_key, sizeof(kdk_key))) {
            ipf_last_error = IPF_STATUS_INVALID_PARAMETER;
            return NULL;
        }
        memcpy(&ipf->user_kdk_key, kdk_key, sizeof(ipf->user_kdk_key));
    }

    // get the clean file name (original name might be clean or with relative path or with absolute path...)
    char clean_filename[FILENAME_MAX_LEN];
    if (!ipf_cleanup_filename(filename, clean_filename))
        // last_error already set
        return NULL;
    /*
    if (import_key != NULL)
    {// verify the key is not empty - note from SAFE review
        sgx_aes_gcm_128bit_key_t empty_aes_key = {0};
        if (consttime_memequal(import_key, &empty_aes_key, sizeof(sgx_aes_gcm_128bit_key_t)) == 1)
        {
            last_error = EINVAL;
            return;
        }
    }*/
/*
    if (parse_mode(mode) == false)
    {
        last_error = EINVAL;
        return;
    }
*/
    ipf->open_mode = mode;
/* // this stuff should be done by higher layer (open handler)
    status = u_sgxprotectedfs_check_if_file_exists(&result, filename);
    // if result == 1 --> file exists
    if (status != 0) {
        last_error = status;
        return;
    }

    if (open_mode.write == 1 && result == 1) {
        // try to delete existing file
        int32_t saved_errno = 0;

        result32 = remove(filename);
        if (result32 != 0) {
            // either can't delete or the file was already deleted by someone else
            saved_errno = errno;
            errno = 0;
        }

        // re-check
        status = u_sgxprotectedfs_check_if_file_exists(&result, filename);
        if (status != SGX_SUCCESS || result == 1) {
            last_error = (status != SGX_SUCCESS) ? status :
                         (saved_errno != 0) ? saved_errno : EACCES;
            return;
        }
    }

    if (open_mode.read == 1 && result == 0) {
        // file must exists
        last_error = ENOENT;
        return;
    }
*/
/*
    if (import_key != NULL && result == 0) {
        // file must exists - otherwise the user key is not used
        last_error = ENOENT;
        return;
    }
*/
    // Intel's implementation opens the file, we should get the fd and size from the open handler
    ipf->read_only = (ipf->open_mode.read == 1 && ipf->open_mode.update == 0);
    // read only files can be opened simultaneously by many enclaves

    if (fd < 0) {
        ipf_last_error = IPF_STATUS_INVALID_PARAMETER;
        return NULL;
    }

    if (real_size % NODE_SIZE != 0) {
        ipf_last_error = IPF_STATUS_FILE_NOT_SGX_FILE;
        return NULL;
    }

    ipf->file = fd;
    ipf->real_file_size = real_size;

    strncpy(ipf->recovery_filename, filename, FULLNAME_MAX_LEN - 1); // copy full file name
    ipf->recovery_filename[FULLNAME_MAX_LEN - 1] = '\0'; // just to be safe
    size_t full_name_len = strnlen(ipf->recovery_filename, RECOVERY_FILE_MAX_LEN);
    strncpy(&ipf->recovery_filename[full_name_len], "_recovery", 10);

    if (ipf->real_file_size > 0) {
        // existing file
        if (ipf->open_mode.write == 1) {
            // redundant check, just in case
            ipf_last_error = IPF_STATUS_DENIED;
            return NULL;
        }

        if (!ipf_init_existing_file(ipf, filename, clean_filename/*, import_key*/))
            return NULL;

        if (ipf->open_mode.append == 1 && ipf->open_mode.update == 0)
            ipf->offset = ipf->encrypted_part_plain.size;
    } else {
        // new file
        if (!ipf_init_new_file(ipf, clean_filename))
            return NULL;
    }

    ipf->file_status = IPF_STATUS_OK;
    /*
    if (ipf->file_status != IPF_FILE_STATUS_OK) {
        if (file != NULL) {
            u_sgxprotectedfs_fclose(&result32, file); // we don't care about the result
            file = NULL;
        }
    }
    */
    return ipf;
}
