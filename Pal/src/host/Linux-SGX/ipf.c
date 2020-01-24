/* Copyright (C) 2019 Invisible Things Lab
                      Rafal Wojdyla <omeg@invisiblethingslab.com>

   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>
#include "ipf.h"

size_t strnlen(const char *str, size_t maxlen);

int _strncmp(const char *_l, const char *_r, size_t n) {
    const unsigned char *l=(void *)_l, *r=(void *)_r;
    if (!n--) return 0;
    for (; *l && *r && n && *l == *r ; l++, r++, n--);
    return *l - *r;
}

/* Host callbacks (from ITL's implementation) */
static pf_malloc_f   cb_malloc   = NULL;
static pf_free_f     cb_free     = NULL;
static pf_map_f      cb_map      = NULL;
static pf_unmap_f    cb_unmap    = NULL;
static pf_truncate_f cb_truncate = NULL;
static pf_flush_f    cb_flush    = NULL;
static pf_open_f     cb_open     = NULL;
static pf_close_f    cb_close    = NULL;
static pf_delete_f   cb_delete   = NULL;
static pf_debug_f    cb_debug    = NULL;

static pf_crypto_aes_gcm_encrypt_f cb_crypto_aes_gcm_encrypt = NULL;
static pf_crypto_aes_gcm_decrypt_f cb_crypto_aes_gcm_decrypt = NULL;
static pf_crypto_random_f          cb_crypto_random          = NULL;

/* Debug print without function name prefix. Implicit param: pf (context pointer). */
#define __DEBUG_PF(format, ...) \
    do { \
        if (cb_debug) { \
            snprintf(pf->debug_buffer, PF_DEBUG_PRINT_SIZE_MAX, format, ##__VA_ARGS__); \
            cb_debug(pf->debug_buffer); \
        } \
    } while(0)

/* Debug print with function name prefix. Implicit param: pf (context pointer). */
#define DEBUG_PF(format, ...) \
    do { \
        if (cb_debug) { \
            snprintf(pf->debug_buffer, PF_DEBUG_PRINT_SIZE_MAX, "%s: " format, __FUNCTION__, ##__VA_ARGS__); \
            cb_debug(pf->debug_buffer); \
        } \
    } while(0)

/* Debug print buffer as hex byte values. */
void __hexdump(const void* data, size_t size) {
    if (!cb_debug)
        return;

    const char* digits = "0123456789abcdef";
    uint8_t* ptr = (uint8_t*)data;
    char b[3];

    for (size_t i = 0; i < size; i++) {
        b[0] = digits[ptr[i] / 16];
        b[1] = digits[ptr[i] % 16];
        b[2] = 0;
        cb_debug(b);
    }
}

#define HEXDUMP(x) __hexdump((void*)&(x), sizeof(x))

/* nl suffix: add new line at the end */
#define __HEXDUMPNL(data, size) { if (cb_debug) { __hexdump(data, size); __DEBUG_PF("\n"); } }
#define HEXDUMPNL(x) __HEXDUMPNL((void*)&(x), sizeof(x))

void pf_set_callbacks(pf_malloc_f malloc_f, pf_free_f free_f, pf_map_f map_f, pf_unmap_f unmap_f,
                      pf_truncate_f truncate_f, pf_flush_f flush_f, pf_open_f open_f,
                      pf_close_f close_f, pf_delete_f delete_f, pf_debug_f debug_f) {
    cb_malloc   = malloc_f;
    cb_free     = free_f;
    cb_map      = map_f;
    cb_unmap    = unmap_f;
    cb_truncate = truncate_f;
    cb_flush    = flush_f;
    cb_open     = open_f;
    cb_close    = close_f;
    cb_delete   = delete_f;
    cb_debug    = debug_f;
}

void pf_set_crypto_callbacks(pf_crypto_aes_gcm_encrypt_f crypto_aes_gcm_encrypt_f,
                             pf_crypto_aes_gcm_decrypt_f crypto_aes_gcm_decrypt_f,
                             pf_crypto_random_f crypto_random_f) {
    cb_crypto_aes_gcm_encrypt = crypto_aes_gcm_encrypt_f;
    cb_crypto_aes_gcm_decrypt = crypto_aes_gcm_decrypt_f;
    cb_crypto_random = crypto_random_f;
}

pf_status_t check_callbacks() {
    return (cb_malloc != NULL &&
            cb_free != NULL &&
            cb_map != NULL &&
            cb_unmap != NULL &&
            cb_truncate != NULL &&
            cb_flush != NULL &&
            cb_crypto_aes_gcm_encrypt != NULL &&
            cb_crypto_aes_gcm_decrypt != NULL &&
            cb_crypto_random != NULL) ? PF_STATUS_SUCCESS : PF_STATUS_UNINITIALIZED;
}

static pf_iv_t empty_iv = {0};
pf_status_t pf_last_error;

// global/util

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

char* strncpy(char* dest, const char* src, size_t size) {
    size_t src_len = strlen(src) + 1;
    size_t len = src_len < size ? src_len : size;
    memcpy(dest, src, len);
    return dest;
}

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
        pf_keyid_t nonce32; // sgx_key_id_t
    };
    uint32_t output_len; // in bits
} kdf_input_t;

bool ipf_generate_secure_blob(pf_key_t* key, const char* label, uint64_t physical_node_number, pf_mac_t* output) {
    kdf_input_t buf = {0};

    uint32_t len = (uint32_t)strnlen(label, MAX_LABEL_LEN + 1);
    if (len > MAX_LABEL_LEN) {
        pf_last_error = PF_STATUS_INVALID_PARAMETER;
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

    pf_status_t status = cb_crypto_random((uint8_t*)&buf.nonce16, sizeof(buf.nonce16));
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    // length of output (128 bits)
    buf.output_len = 0x80;

    //status = cb_crypto_aes_cmac(key, &buf, sizeof(buf), output);
    status = cb_crypto_aes_gcm_encrypt(key, &empty_iv, &buf, sizeof(buf), NULL, 0, NULL, output);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    memset(&buf, 0, sizeof(buf)); // TODO: memset_s

    return true;
}

bool ipf_generate_secure_blob_from_user_kdk(pf_context_t pf, bool restore) {
    kdf_input_t buf = {0};
    pf_status_t status;

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
        status = cb_crypto_random((uint8_t*)&buf.nonce32, sizeof(buf.nonce32));
        if (status != PF_STATUS_SUCCESS) {
            pf_last_error = status;
            return false;
        }
    } else {
        memcpy(&buf.nonce32, &pf->file_meta_data.plain_part.meta_data_key_id, sizeof(buf.nonce32));
    }

    // length of output (128 bits)
    buf.output_len = 0x80;

    //status = cb_crypto_aes_cmac(&pf->user_kdk_key, &buf, sizeof(buf), &pf->cur_key);
    status = cb_crypto_aes_gcm_encrypt(&pf->user_kdk_key, &empty_iv, &buf, sizeof(buf), NULL, 0,
                                       NULL, &pf->cur_key);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    if (!restore) {
        memcpy(&pf->file_meta_data.plain_part.meta_data_key_id, &buf.nonce32,
            sizeof(pf->file_meta_data.plain_part.meta_data_key_id));
    }

    memset(&buf, 0, sizeof(buf)); // TODO: memset_s

    return true;
}

bool ipf_init_session_master_key(pf_context_t pf) {
    pf_key_t empty_key = {0};

    if (!ipf_generate_secure_blob(&empty_key, MASTER_KEY_NAME, 0, (pf_mac_t*)&pf->session_master_key))
        return false;

    pf->master_key_count = 0;

    return true;
}

bool ipf_derive_random_node_key(pf_context_t pf, uint64_t physical_node_number) {
    if (pf->master_key_count++ > MAX_MASTER_KEY_USAGES) {
        if (!ipf_init_session_master_key(pf))
            return false;
    }

    if (!ipf_generate_secure_blob(&pf->session_master_key, RANDOM_KEY_NAME, physical_node_number,
                                  (pf_mac_t*)&pf->cur_key))
        return false;

    return true;
}

bool ipf_generate_random_meta_data_key(pf_context_t pf) {
    // we don't use autogenerated keys
    return ipf_generate_secure_blob_from_user_kdk(pf, false);

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

bool ipf_restore_current_meta_data_key(pf_context_t pf/*, const pf_key_t* import_key*/) {
    /*
    if (import_key != NULL) {
        memcpy(&pf->cur_key, import_key, sizeof(pf->cur_key));
        return true;
    }*/
    // we don't use autogenerated keys
    return ipf_generate_secure_blob_from_user_kdk(pf, true);

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

// strips path components, leaves file name
bool ipf_cleanup_filename(const char* src, char* dest) {
    const char* p = src;
    const char* name = src;

    while (*p) {
        if ((*p) == '\\' || (*p) == '/')
            name = p + 1;
        p++;
    }

    if (strnlen(name, FILENAME_MAX_LEN) >= FILENAME_MAX_LEN - 1) {
        pf_last_error = PF_STATUS_PATH_TOO_LONG;
        return false;
    }

    memcpy(dest, name, FILENAME_MAX_LEN - 1);
    dest[FILENAME_MAX_LEN - 1] = '\0';

    if (strnlen(dest, 1) == 0) {
        pf_last_error = PF_STATUS_INVALID_PARAMETER;
        return false;
    }

    return true;
}

void ipf_init_fields(pf_context_t pf) {
    pf->meta_data_node_number = 0;
    memset(&pf->file_meta_data, 0, sizeof(pf->file_meta_data));
    memset(&pf->encrypted_part_plain, 0, sizeof(pf->encrypted_part_plain));
    memset(&empty_iv, 0, sizeof(empty_iv));
    memset(&pf->root_mht, 0, sizeof(pf->root_mht));

    pf->root_mht.type = FILE_MHT_NODE_TYPE;
    pf->root_mht.physical_node_number = 1;
    pf->root_mht.mht_node_number = 0;
    pf->root_mht.new_node = true;
    pf->root_mht.need_writing = false;

    pf->offset = 0;
    pf->file = NULL;
    pf->end_of_file = false;
    pf->need_writing = false;
    pf->read_only = 0;
    pf->file_status = PF_STATUS_UNINITIALIZED;
    pf_last_error = PF_STATUS_SUCCESS;
    pf->real_file_size = 0;
    pf->open_mode.raw = 0;
    pf->master_key_count = 0;

    pf->recovery_filename[0] = '\0';

    //memset(&mutex, 0, sizeof(sgx_thread_mutex_t));

    pf->cache = lruc_create();
    // set hash size to fit MAX_PAGES_IN_CACHE
    //pf->cache.rehash(MAX_PAGES_IN_CACHE);
}

// constructor
pf_context_t ipf_open(const char* filename, open_mode_t mode, pf_handle_t file, size_t real_size,
                      const pf_key_t* kdk_key) {
    pf_context* pf = cb_malloc(sizeof(pf_context));

    if (!pf) {
        pf_last_error = PF_STATUS_NO_MEMORY;
        goto out;
    }

    ipf_init_fields(pf);

    // ITL: filename can be NULL for existing files, then we skip path verification
    if (/*filename == NULL || strnlen(filename, 1) == 0 || */kdk_key == NULL ||
        (mode.write == 0 && mode.read == 0/* && mode.append == 0*/)) {

        pf_last_error = PF_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (filename && strnlen(filename, FULLNAME_MAX_LEN) >= FULLNAME_MAX_LEN - 1) {
        pf_last_error = PF_STATUS_PATH_TOO_LONG;
        goto out;
    }

    // we don't use autogenerated keys, use_user_kdk_key is always true
/*
    if (import_key != NULL && kdk_key != NULL)
    {// import key is used only with auto generated keys
        last_error = EINVAL;
        return;
    }
*/
    if (!ipf_init_session_master_key(pf)) {
        // last_error already set
        goto out;
    }

    //if (kdk_key != NULL)
    {
        // for new file, this value will later be saved in the meta data plain part (init_new_file)
        // for existing file, we will later compare this value with the value from the file (init_existing_file)
        //use_user_kdk_key = 1;
        pf_key_t empty_key = {0};
        if (consttime_memequal(kdk_key, &empty_key, sizeof(kdk_key))) {
            pf_last_error = PF_STATUS_INVALID_PARAMETER;
            goto out;
        }
        memcpy(&pf->user_kdk_key, kdk_key, sizeof(pf->user_kdk_key));
    }

    /* // ITL: we require a canonical full path to file
    // get the clean file name (original name might be clean or with relative path or with absolute path...)
    char clean_filename[FILENAME_MAX_LEN];
    if (!ipf_cleanup_filename(filename, clean_filename)) {
        // last_error already set
        goto out;
    }*/

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

    pf->open_mode = mode;
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
    // Intel's implementation opens the file, we should get the fd and size from the Graphene open handler
    pf->read_only = (pf->open_mode.read == 1 && pf->open_mode.update == 0);
    // read only files can be opened simultaneously by many enclaves

    if (!file) {
        pf_last_error = PF_STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (real_size % NODE_SIZE != 0) {
        pf_last_error = PF_STATUS_INVALID_HEADER;
        goto out;
    }

    pf->file = file;
    pf->real_file_size = real_size;

    if (filename) {
        strncpy(pf->recovery_filename, filename, FULLNAME_MAX_LEN - 1); // copy full file name
        pf->recovery_filename[FULLNAME_MAX_LEN - 1] = '\0'; // just to be safe
        size_t full_name_len = strnlen(pf->recovery_filename, RECOVERY_FILE_MAX_LEN);
        strncpy(&pf->recovery_filename[full_name_len], "_recovery", 10);
    }

    if (pf->real_file_size > 0) {
        // existing file
        if (pf->open_mode.write == 1) {
            // redundant check, just in case
            pf_last_error = PF_STATUS_INVALID_MODE;
            goto out;
        }

        if (!ipf_init_existing_file(pf, filename, /*clean_*/filename/*, import_key*/))
            goto out;

        //if (pf->open_mode.append == 1 && pf->open_mode.update == 0)
        //    pf->offset = pf->encrypted_part_plain.size;
    } else {
        // new file
        if (!ipf_init_new_file(pf, /*clean_*/filename))
            goto out;
    }

    pf_last_error = pf->file_status = PF_STATUS_SUCCESS;

out:
    if (pf_last_error != PF_STATUS_SUCCESS) {
        cb_free(pf);
        pf = NULL;
    }

    return pf;
}

bool ipf_file_recovery(pf_context_t pf, const char* filename) {
    pf_status_t status;
    size_t new_file_size = 0;

    if (!filename) { // no path was passed during open
        pf_last_error = PF_STATUS_RECOVERY_IMPOSSIBLE;
        return false;
    }

    status = cb_close(pf->file);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    pf->file = NULL;

    status = ipf_do_file_recovery(filename, pf->recovery_filename, NODE_SIZE);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    status = cb_open(filename, pf->read_only ? PF_FILE_MODE_READ : PF_FILE_MODE_WRITE,
                     &pf->file, &new_file_size);
    if (status != PF_STATUS_SUCCESS || pf->file == NULL) {
        pf_last_error = status;
        return false;
    }

    // recovery only change existing data, it does not shrink or grow the file
    if (new_file_size != pf->real_file_size) {
        pf_last_error = PF_STATUS_UNKNOWN_ERROR;
        return false;
    }

    if (!ipf_read_node(pf->file, 0, (uint8_t*)&pf->file_meta_data, NODE_SIZE)) {
        return false;
    }

    return true;
}

bool ipf_read_node(pf_handle_t file, uint64_t node_number, void* buffer, uint32_t node_size) {
    uint64_t offset = node_number * node_size;

    void* ptr;
    pf_status_t status = cb_map(file, PF_FILE_MODE_READ, offset, node_size, &ptr);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    memcpy(buffer, ptr, node_size);

    status = cb_unmap(ptr, node_size);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    return true;
}

bool ipf_write_file(pf_handle_t file, uint64_t offset, void* buffer, uint32_t size) {
    void* ptr;
    pf_status_t status = cb_map(file, PF_FILE_MODE_WRITE, offset, size, &ptr);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    memcpy(ptr, buffer, size);

    status = cb_unmap(ptr, size);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    return true;
}

bool ipf_write_node(pf_handle_t file, uint64_t node_number, void* buffer, uint32_t node_size) {
    return ipf_write_file(file, node_number * node_size, buffer, node_size);
}

bool ipf_init_existing_file(pf_context_t pf, const char* filename, const char* clean_filename/*, const pf_key_t* import_key*/) {
    pf_status_t status;

    // read meta-data node
    status = ipf_read_node(pf->file, 0, (uint8_t*)&pf->file_meta_data, NODE_SIZE);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    if (pf->file_meta_data.plain_part.file_id != SGX_FILE_ID) {
        // such a file exists, but it is not an SGX file
        pf_last_error = PF_STATUS_INVALID_HEADER;
        return false;
    }

    if (pf->file_meta_data.plain_part.major_version != SGX_FILE_MAJOR_VERSION) {
        pf_last_error = PF_STATUS_INVALID_VERSION;
        return false;
    }

    if (pf->file_meta_data.plain_part.update_flag == 1) {
        // file was in the middle of an update, must do a recovery
        if (!ipf_file_recovery(pf, filename)) {
            // override internal error
            pf_last_error = PF_STATUS_RECOVERY_NEEDED;
            return false;
        }

        if (pf->file_meta_data.plain_part.update_flag == 1) {
            // recovery failed, flag is still set!
            pf_last_error = PF_STATUS_RECOVERY_NEEDED;
            return false;
        }

        // re-check after recovery
        if (pf->file_meta_data.plain_part.major_version != SGX_FILE_MAJOR_VERSION) {
            pf_last_error = PF_STATUS_INVALID_VERSION;
            return false;
        }
    }
/*  // we always use custom keys
    if (file_meta_data.plain_part.use_user_kdk_key != use_user_kdk_key) {
        last_error = EINVAL;
        return false;
    }
*/
    if (!ipf_restore_current_meta_data_key(pf/*, import_key*/))
        return false;

    // decrypt the encrypted part of the meta-data
    status = cb_crypto_aes_gcm_decrypt(&pf->cur_key, &empty_iv, NULL, 0,
                                       &pf->file_meta_data.encrypted_part, sizeof(pf->file_meta_data.encrypted_part),
                                       &pf->encrypted_part_plain,
                                       &pf->file_meta_data.plain_part.meta_data_gmac);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    if (_strncmp(clean_filename, pf->encrypted_part_plain.clean_filename, FILENAME_MAX_LEN) != 0) {
        pf_last_error = PF_STATUS_INVALID_PATH;
        return false;
    }

/*
    sgx_mc_uuid_t empty_mc_uuid = {0};
    // check if the file contains an active monotonic counter
    if (consttime_memequal(&empty_mc_uuid, &encrypted_part_plain.mc_uuid, sizeof(sgx_mc_uuid_t)) == 0)
    {
        uint32_t mc_value = 0;
        status = sgx_read_monotonic_counter(&encrypted_part_plain.mc_uuid, &mc_value);
        if (status != SGX_SUCCESS)
        {
            last_error = status;
            return false;
        }
        if (encrypted_part_plain.mc_value < mc_value)
        {
            last_error = SGX_ERROR_FILE_MONOTONIC_COUNTER_IS_BIGGER;
            return false;
        }
        if (encrypted_part_plain.mc_value == mc_value + 1) // can happen if AESM failed - file value stayed one higher
        {
            sgx_status_t status = sgx_increment_monotonic_counter(&encrypted_part_plain.mc_uuid, &mc_value);
            if (status != SGX_SUCCESS)
            {
                file_status = SGX_FILE_STATUS_MC_NOT_INCREMENTED;
                last_error = status;
                return false;
            }
        }
        if (encrypted_part_plain.mc_value != mc_value)
        {
            file_status = SGX_FILE_STATUS_CORRUPTED;
            last_error = SGX_ERROR_UNEXPECTED;
            return false;
        }
    }
    else
    {
        assert(encrypted_part_plain.mc_value == 0);
        encrypted_part_plain.mc_value = 0; // do this anyway for release...
    }
*/
    if (pf->encrypted_part_plain.size > MD_USER_DATA_SIZE) {
        // read the root node of the mht
        if (!ipf_read_node(pf->file, 1, &pf->root_mht.encrypted.cipher, NODE_SIZE))
            return false;

        // this also verifies the root mht gmac against the gmac in the meta-data encrypted part
        status = cb_crypto_aes_gcm_decrypt(&pf->encrypted_part_plain.mht_key, &empty_iv,
                                           NULL, 0, // aad
                                           &pf->root_mht.encrypted.cipher, NODE_SIZE,
                                           &pf->root_mht.plain,
                                           &pf->encrypted_part_plain.mht_gmac);
        if (status != PF_STATUS_SUCCESS) {
            pf_last_error = status;
            return false;
        }

        pf->root_mht.new_node = false;
    }

    return true;
}

bool ipf_init_new_file(pf_context_t pf, const char* clean_filename) {
    pf->file_meta_data.plain_part.file_id = SGX_FILE_ID;
    pf->file_meta_data.plain_part.major_version = SGX_FILE_MAJOR_VERSION;
    pf->file_meta_data.plain_part.minor_version = SGX_FILE_MINOR_VERSION;

    //pf->file_meta_data.plain_part.use_user_kdk_key = use_user_kdk_key; // always true

    strncpy(pf->encrypted_part_plain.clean_filename, clean_filename, FILENAME_MAX_LEN);

    pf->need_writing = true;

    return true;
}

// destructor
bool ipf_close(pf_context_t pf) {
    void* data;
    bool retval = true;

    if (!ipf_pre_close(pf)) {
        retval = false;
        //goto out; // destroy the memory content anyway
    }

    while ((data = lruc_get_last(pf->cache)) != NULL) {
        if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) {
            // type is in the same offset in both node types, need to scrub the plaintext
            file_data_node_t* file_data_node = (file_data_node_t*)data;
            memset(&file_data_node->plain, 0, sizeof(data_node_t)); // TODO: memset_s
            cb_free(file_data_node);
        } else {
            file_mht_node_t* file_mht_node = (file_mht_node_t*)data;
            memset(&file_mht_node->plain, 0, sizeof(mht_node_t)); // TODO: memset_s
            cb_free(file_mht_node);
        }
        lruc_remove_last(pf->cache);
    }

    // scrub the last encryption key and the session key
    // TODO: memset_s
    memset(&pf->cur_key, 0, sizeof(pf->cur_key));
    memset(&pf->session_master_key, 0, sizeof(pf->session_master_key));

    // scrub first 3KB of user data and the gmac_key
    memset(&pf->encrypted_part_plain, 0, sizeof(pf->encrypted_part_plain));

    lruc_destroy(pf->cache);

    //sgx_thread_mutex_destroy(&mutex);
    memset(pf, 0, sizeof(pf_context));
    cb_free(pf);

    return retval;
}

bool ipf_pre_close(pf_context_t pf/*, pf_key_t* key, bool import*/) {
    bool retval = true;
    //pf_status_t status;

    //sgx_thread_mutex_lock(&mutex);

    /*if (import) {
        // always true
        //if (use_user_kdk_key == 1) // import file is only needed for auto-key
            retval = false;
        //else
        //    need_writing = true; // will re-encrypt the neta-data node with local key
    }*/

    if (pf->file_status != PF_STATUS_SUCCESS) {
        //sgx_thread_mutex_unlock(&mutex);
        ipf_clear_error(pf); // last attempt to fix it
        //sgx_thread_mutex_lock(&mutex);
    } else {
        ipf_internal_flush(pf, /*false,*/ true);
    }

    if (pf->file_status != PF_STATUS_SUCCESS)
        retval = false;

    /* this is done by PAL handler
    if (pf->file != NULL) {
        status = u_sgxprotectedfs_fclose(&result32, file);
        if (status != SGX_SUCCESS || result32 != 0)
        {
            last_error = (status != SGX_SUCCESS) ? status :
                         (result32 != -1) ? result32 : SGX_ERROR_FILE_CLOSE_FAILED;
            retval = false;
        }

        file = NULL;
    }

    if (file_status == SGX_FILE_STATUS_OK &&
        last_error == SGX_SUCCESS) // else...maybe something bad happened and the recovery file will be needed
        erase_recovery_file();
    */

    /*if (key != NULL) {
        // always true
        //if (use_user_kdk_key == 1) // export key is only used for auto-key
        {
            retval = false;
        }
        else
        {
            if (restore_current_meta_data_key(NULL) == true)
                memcpy(key, cur_key, sizeof(sgx_key_128bit_t));
            else
                retval = false;
        }
    }*/

    pf->file_status = PF_STATUS_UNINITIALIZED;

    //sgx_thread_mutex_unlock(&mutex);

    return retval;
}

// file_flush.cpp

bool ipf_flush(pf_context_t pf/*, bool mc*/) {
    bool result = false;

/*    int32_t result32 = sgx_thread_mutex_lock(&mutex);
    if (result32 != 0)
    {
        last_error = result32;
        file_status = SGX_FILE_STATUS_MEMORY_CORRUPTED;
        return false;
    }*/

    if (pf->file_status != PF_STATUS_SUCCESS) {
        pf_last_error = PF_STATUS_UNKNOWN_ERROR;
        //sgx_thread_mutex_unlock(&mutex);
        return false;
    }

    result = ipf_internal_flush(pf, /*mc,*/ true);
    if (!result) {
        assert(pf->file_status != PF_STATUS_SUCCESS);
        if (pf->file_status == PF_STATUS_SUCCESS)
            pf->file_status = PF_STATUS_FLUSH_ERROR; // for release set this anyway
    }

    //sgx_thread_mutex_unlock(&mutex);

    return result;
}

// DEBUG
#define _RECOVERY_HOOK_(_x) (0)

bool ipf_internal_flush(pf_context_t pf, /*bool mc,*/ bool flush_to_disk) {
    if (!pf->need_writing) // no changes at all
        return true;

/*
    if (mc == true && encrypted_part_plain.mc_value > (UINT_MAX-2))
    {
        last_error = SGX_ERROR_FILE_MONOTONIC_COUNTER_AT_MAX;
        return false;
    }
*/
    if (pf->encrypted_part_plain.size > MD_USER_DATA_SIZE && pf->root_mht.need_writing) {
        // otherwise it's just one write - the meta-data node
        if (_RECOVERY_HOOK_(0) || !ipf_write_recovery_file(pf)) {
            pf->file_status = PF_STATUS_FLUSH_ERROR;
            return false;
        }

        if (_RECOVERY_HOOK_(1) || !ipf_set_update_flag(pf, flush_to_disk)) {
            pf->file_status = PF_STATUS_FLUSH_ERROR;
            return false;
        }

        if (_RECOVERY_HOOK_(2) || !ipf_update_all_data_and_mht_nodes(pf)) {
            ipf_clear_update_flag(pf);
            // this is something that shouldn't happen, can't fix this...
            pf->file_status = PF_STATUS_CRYPTO_ERROR;
            return false;
        }
    }

/*
    sgx_status_t status;
    if (mc == true)
    {
        // increase monotonic counter local value - only if everything is ok, we will increase the real counter
        if (encrypted_part_plain.mc_value == 0)
        {
            // no monotonic counter so far, need to create a new one
            status = sgx_create_monotonic_counter(&encrypted_part_plain.mc_uuid, &encrypted_part_plain.mc_value);
            if (status != SGX_SUCCESS)
            {
                clear_update_flag();
                file_status = SGX_FILE_STATUS_FLUSH_ERROR;
                last_error = status;
                return false;
            }
        }
        encrypted_part_plain.mc_value++;
    }
*/
    if (_RECOVERY_HOOK_(3) || !ipf_update_meta_data_node(pf)) {
        ipf_clear_update_flag(pf);
        /*
        if (mc == true)
            encrypted_part_plain.mc_value--; // don't have to do this as the file cannot be fixed, but doing it anyway to prevent future errors
        */
        // this is something that shouldn't happen, can't fix this...
        pf->file_status = PF_STATUS_CRYPTO_ERROR;
        return false;
    }

    if (_RECOVERY_HOOK_(4) || !ipf_write_all_changes_to_disk(pf, flush_to_disk))
    {
        //if (mc == false)
            // special case, need only to repeat write_all_changes_to_disk in order to repair it
            pf->file_status = PF_STATUS_WRITE_TO_DISK_FAILED;
        //else
            //file_status = SGX_FILE_STATUS_WRITE_TO_DISK_FAILED_NEED_MC; // special case, need to repeat write_all_changes_to_disk AND increase the monotonic counter in order to repair it

        return false;
    }

    pf->need_writing = false;

/* this is causing problems when we delete and create the file rapidly
   we will just leave the file, and re-write it every time
   u_sgxprotectedfs_recovery_file_open opens it with 'w' so it is truncated
    if (encrypted_part_plain.size > MD_USER_DATA_SIZE)
    {
        erase_recovery_file();
    }
*/
/*
    if (mc == true)
    {
        uint32_t mc_value;
        status = sgx_increment_monotonic_counter(&encrypted_part_plain.mc_uuid, &mc_value);
        if (status != SGX_SUCCESS)
        {
            file_status = SGX_FILE_STATUS_MC_NOT_INCREMENTED; // special case - need only to increase the MC in order to repair it
            last_error = status;
            return false;
        }
        assert(mc_value == encrypted_part_plain.mc_value);
    }
*/
    return true;
}

bool ipf_write_recovery_file(pf_context_t pf) {
    pf_handle_t recovery_file = NULL;

    if (!pf->recovery_filename) {
        pf_last_error = PF_STATUS_RECOVERY_IMPOSSIBLE;
        return false;
    }

    pf_status_t status = cb_open(pf->recovery_filename, PF_FILE_MODE_WRITE, &recovery_file, NULL);
    if (status != PF_STATUS_SUCCESS || recovery_file == NULL) {
        pf_last_error = status;
        return false;
    }

    void* data = NULL;
    recovery_node_t* recovery_node = NULL;

    uint64_t node_number = 0;
    for (data = lruc_get_first(pf->cache); data != NULL; data = lruc_get_next(pf->cache)) {
        if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) {
            // type is in the same offset in both node types
            file_data_node_t* file_data_node = (file_data_node_t*)data;
            if (!file_data_node->need_writing || file_data_node->new_node)
                continue;

            recovery_node = &file_data_node->recovery_node;
        } else {
            file_mht_node_t* file_mht_node = (file_mht_node_t*)data;
            assert(file_mht_node->type == FILE_MHT_NODE_TYPE);
            if (!file_mht_node->need_writing || file_mht_node->new_node)
                continue;

            recovery_node = &file_mht_node->recovery_node;
        }

        if (!ipf_write_node(recovery_file, node_number, recovery_node, sizeof(*recovery_node))) {
            cb_close(recovery_file);
            cb_delete(pf->recovery_filename);
            return false;
        }

        node_number++;
    }

    uint64_t offset = node_number * sizeof(*recovery_node);
    if (pf->root_mht.need_writing && !pf->root_mht.new_node) {
        if (!ipf_write_file(recovery_file, offset, &pf->root_mht.recovery_node, sizeof(pf->root_mht.recovery_node))) {
            cb_close(recovery_file);
            cb_delete(pf->recovery_filename);
            return false;
        }

        offset += sizeof(pf->root_mht.recovery_node);
    }

    if (!ipf_write_file(recovery_file, offset, &pf->meta_data_recovery_node, sizeof(pf->meta_data_recovery_node))) {
        cb_close(recovery_file);
        cb_delete(pf->recovery_filename);
        return false;
    }

    cb_close(recovery_file); // TODO - check result

    return true;
}

bool ipf_set_update_flag(pf_context_t pf, bool flush_to_disk) {
    pf_status_t status;

    pf->file_meta_data.plain_part.update_flag = 1;
    // turn it off in memory. at the end of the flush, when we'll write the meta-data to disk, this flag will also be cleared there.
    pf->file_meta_data.plain_part.update_flag = 0;
    if (!ipf_write_node(pf->file, 0, (uint8_t*)&pf->file_meta_data, NODE_SIZE)) {
        return false;
    }

    if (flush_to_disk) {
        status = cb_flush(pf->file);
        if (status != PF_STATUS_SUCCESS) {
            pf_last_error = status;
            // try to clear the update flag, in the OS cache at least...
            ipf_write_node(pf->file, 0, (uint8_t*)&pf->file_meta_data, NODE_SIZE);
            return false;
        }
    }

    return true;
}

void ipf_clear_update_flag(pf_context_t pf) {
    if (_RECOVERY_HOOK_(3))
        return;
    assert(pf->file_meta_data.plain_part.update_flag == 0);
    ipf_write_node(pf->file, 0, (uint8_t*)&pf->file_meta_data, NODE_SIZE);
    cb_flush(pf->file);
}

// sort function, we need the mht nodes sorted before we start to update their gmac's
bool mht_sort(const void* first, const void* second) {
    // higher (lower tree level) node number first
    if (!first || !second)
        return false;

    return (((file_mht_node_t*)first)->mht_node_number >
            ((file_mht_node_t*)second)->mht_node_number);
}

#define LISTP_SORT(LISTP, STRUCT_NAME, SORT_FUNC)                                       \
    do {                                                                                \
        struct STRUCT_NAME* head  = NULL;                                               \
        struct STRUCT_NAME* outer = NULL;                                               \
        struct STRUCT_NAME* inner = NULL;                                               \
        head                = LISTP_FIRST_ENTRY(LISTP, STRUCT_NAME, list);              \
        outer               = head;                                                     \
        bool adjacent_nodes = false;                                                    \
        while (outer != NULL) {                                                         \
            inner = LISTP_NEXT_ENTRY(outer, LISTP, list);                               \
            while (inner != NULL) {                                                     \
                if (!SORT_FUNC(outer, inner)) {                                         \
                    struct STRUCT_NAME* for_swap = NULL;                                \
                    adjacent_nodes =                                                    \
                        (LISTP_NEXT_ENTRY(outer, LISTP, list) == inner) ? true : false; \
                    if (!adjacent_nodes) {                                              \
                        struct STRUCT_NAME* prev_of_inner =                             \
                            LISTP_PREV_ENTRY(inner, LISTP, list);                       \
                        struct STRUCT_NAME* prev_of_outer =                             \
                            LISTP_PREV_ENTRY(outer, LISTP, list);                       \
                        LISTP_DEL(inner, LISTP, list);                                  \
                        LISTP_DEL(outer, LISTP, list);                                  \
                        LISTP_ADD_AFTER(inner, prev_of_outer, LISTP, list);             \
                        LISTP_ADD_AFTER(outer, prev_of_inner, LISTP, list);             \
                    } else {                                                            \
                        LISTP_DEL(outer, LISTP, list);                                  \
                        LISTP_ADD_AFTER(outer, inner, LISTP, list);                     \
                    }                                                                   \
                    for_swap = inner;                                                   \
                    inner    = outer;                                                   \
                    outer    = for_swap;                                                \
                }                                                                       \
                inner = LISTP_NEXT_ENTRY(inner, LISTP, list);                           \
            }                                                                           \
            outer = LISTP_NEXT_ENTRY(outer, LISTP, list);                               \
        }                                                                               \
    } while (0)

bool ipf_update_all_data_and_mht_nodes(pf_context_t pf) {
    LISTP_TYPE(_file_mht_node) mht_list = LISTP_INIT;
    file_mht_node_t* file_mht_node;
    pf_status_t status;
    void* data = lruc_get_first(pf->cache);

    // 1. encrypt the changed data
    // 2. set the IV+GMAC in the parent MHT
    // [3. set the need_writing flag for all the parents]
    while (data != NULL) {
        if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) {
            // type is in the same offset in both node types
            file_data_node_t* data_node = (file_data_node_t*)data;

            if (data_node->need_writing) {
                if (!ipf_derive_random_node_key(pf, data_node->physical_node_number))
                    return false;

                gcm_crypto_data_t* gcm_crypto_data = &data_node->parent->plain.data_nodes_crypto[data_node->data_node_number % ATTACHED_DATA_NODES_COUNT];

                // encrypt the data, this also saves the gmac of the operation in the mht crypto node
                status = cb_crypto_aes_gcm_encrypt(&pf->cur_key, &empty_iv,
                                                   NULL, 0, // aad
                                                   data_node->plain.data, NODE_SIZE,
                                                   data_node->encrypted.cipher,
                                                   &gcm_crypto_data->gmac);
                if (status != PF_STATUS_SUCCESS) {
                    pf_last_error = status;
                    return false;
                }

                // save the key used for this encryption
                memcpy(gcm_crypto_data->key, pf->cur_key, sizeof(gcm_crypto_data->key));

                file_mht_node = data_node->parent;
                // this loop should do nothing, add it here just to be safe
                while (file_mht_node->mht_node_number != 0) {
                    assert(file_mht_node->need_writing == true);
                    file_mht_node->need_writing = true; // just in case, for release
                    file_mht_node = file_mht_node->parent;
                }
            }
        }
        data = lruc_get_next(pf->cache);
    }

    // add all the mht nodes that needs writing to a list
    data = lruc_get_first(pf->cache);
    while (data != NULL) {
        if (((file_mht_node_t*)data)->type == FILE_MHT_NODE_TYPE) {
            // type is in the same offset in both node types
            file_mht_node = (file_mht_node_t*)data;

            if (file_mht_node->need_writing)
                LISTP_ADD(file_mht_node, &mht_list, list);
        }

        data = lruc_get_next(pf->cache);
    }

    // sort the list from the last node to the first (bottom layers first)
    LISTP_SORT(&mht_list, _file_mht_node, mht_sort);

    // update the gmacs in the parents
    struct _file_mht_node* node;
    struct _file_mht_node* tmp;

    LISTP_FOR_EACH_ENTRY_SAFE(node, tmp, &mht_list, list) {
        file_mht_node = node;

        gcm_crypto_data_t* gcm_crypto_data = &file_mht_node->parent->plain.mht_nodes_crypto[(file_mht_node->mht_node_number - 1) % CHILD_MHT_NODES_COUNT];

        if (!ipf_derive_random_node_key(pf, file_mht_node->physical_node_number)) {
            //mht_list.clear(); // not needed
            return false;
        }

        status = cb_crypto_aes_gcm_encrypt(&pf->cur_key, &empty_iv,
                                           NULL, 0,
                                           &file_mht_node->plain, NODE_SIZE,
                                           &file_mht_node->encrypted.cipher,
                                           &gcm_crypto_data->gmac);
        if (status != PF_STATUS_SUCCESS) {
            //mht_list.clear(); // not needed
            pf_last_error = status;
            return false;
        }

        // save the key used for this gmac
        memcpy(&gcm_crypto_data->key, pf->cur_key, sizeof(gcm_crypto_data->key));

        LISTP_DEL(node, &mht_list, list);
        cb_free(node); // TODO: verify this is fine
    }

    // update mht root gmac in the meta data node
    if (!ipf_derive_random_node_key(pf, pf->root_mht.physical_node_number))
        return false;

    status = cb_crypto_aes_gcm_encrypt(&pf->cur_key, &empty_iv,
                                       NULL, 0,
                                       &pf->root_mht.plain, NODE_SIZE,
                                       &pf->root_mht.encrypted.cipher,
                                       &pf->encrypted_part_plain.mht_gmac);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    // save the key used for this gmac
    memcpy(&pf->encrypted_part_plain.mht_key, pf->cur_key, sizeof(pf->encrypted_part_plain.mht_key));

    return true;
}

bool ipf_update_meta_data_node(pf_context_t pf) {
    pf_status_t status;

    // randomize a new key, saves the key _id_ in the meta data plain part
    if (!ipf_generate_random_meta_data_key(pf)) {
        // last error already set
        return false;
    }

    // encrypt meta data encrypted part, also updates the gmac in the meta data plain part
    status = cb_crypto_aes_gcm_encrypt(&pf->cur_key, &empty_iv,
                                       NULL, 0,
                                       &pf->encrypted_part_plain, sizeof(meta_data_encrypted_t),
                                       &pf->file_meta_data.encrypted_part,
                                       &pf->file_meta_data.plain_part.meta_data_gmac);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    return true;
}

bool ipf_write_all_changes_to_disk(pf_context_t pf, bool flush_to_disk) {
    pf_status_t status;

    if (pf->encrypted_part_plain.size > MD_USER_DATA_SIZE && pf->root_mht.need_writing) {
        void* data = NULL;
        uint8_t* data_to_write;
        uint64_t node_number;
        file_data_node_t* file_data_node;
        file_mht_node_t* file_mht_node;

        for (data = lruc_get_first(pf->cache); data != NULL; data = lruc_get_next(pf->cache)) {
            file_data_node = NULL;
            file_mht_node = NULL;

            if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) {
                // type is in the same offset in both node types
                file_data_node = (file_data_node_t*)data;
                if (!file_data_node->need_writing)
                    continue;

                data_to_write = (uint8_t*)&file_data_node->encrypted;
                node_number = file_data_node->physical_node_number;
            } else {
                file_mht_node = (file_mht_node_t*)data;
                assert(file_mht_node->type == FILE_MHT_NODE_TYPE);
                if (!file_mht_node->need_writing)
                    continue;

                data_to_write = (uint8_t*)&file_mht_node->encrypted;
                node_number = file_mht_node->physical_node_number;
            }

            if (!ipf_write_node(pf->file, node_number, data_to_write, NODE_SIZE)) {
                return false;
            }

            // data written - clear the need_writing and the new_node flags
            // (for future transactions, this node it no longer 'new' and should be written to recovery file)
            if (file_data_node != NULL) {
                file_data_node->need_writing = false;
                file_data_node->new_node = false;
            } else {
                file_mht_node->need_writing = false;
                file_mht_node->new_node = false;
            }
        }

        if (!ipf_write_node(pf->file, 1, &pf->root_mht.encrypted, NODE_SIZE)) {
            return false;
        }

        pf->root_mht.need_writing = false;
        pf->root_mht.new_node = false;
    }

    if (!ipf_write_node(pf->file, 0, &pf->file_meta_data, NODE_SIZE)) {
        return false;
    }

    if (flush_to_disk) {
        status = cb_flush(pf->file);
        if (status != PF_STATUS_SUCCESS) {
            pf_last_error = status;
            return false;
        }
    }

    return true;
}

bool ipf_erase_recovery_file(pf_context_t pf) {
    pf_status_t status;

    if (!pf->recovery_filename) {
        pf_last_error = PF_STATUS_RECOVERY_IMPOSSIBLE;
        return false;
    }

    if (pf->recovery_filename[0] == '\0') // not initialized yet
        return true;

    status = cb_delete(pf->recovery_filename);
    if (status != PF_STATUS_SUCCESS) {
        pf_last_error = status;
        return false;
    }

    return true;
}

int64_t ipf_tell(pf_context_t pf) {
    //sgx_thread_mutex_lock(&mutex);

    if (pf->file_status != PF_STATUS_SUCCESS) {
        pf_last_error = pf->file_status;
        //sgx_thread_mutex_unlock(&mutex);
        return -1;
    }

    //sgx_thread_mutex_unlock(&mutex);

    return pf->offset;
}

// we don't support sparse files, fseek beyond the current file size will fail
bool ipf_seek(pf_context_t pf, int64_t new_offset, int origin) {
    //sgx_thread_mutex_lock(&mutex);

    if (pf->file_status != PF_STATUS_SUCCESS) {
        pf_last_error = pf->file_status;
        //sgx_thread_mutex_unlock(&mutex);
        return false;
    }

    //if (open_mode.binary == 0 && origin != SEEK_SET && new_offset != 0)
    //{
    //  last_error = EINVAL;
    //  sgx_thread_mutex_unlock(&mutex);
    //  return -1;
    //}

    bool result = false;

    switch (origin) {
    case SEEK_SET:
        if (new_offset >= 0 && new_offset <= pf->encrypted_part_plain.size) {
            pf->offset = new_offset;
            result = true;
        }
        break;

    case SEEK_CUR:
        if ((pf->offset + new_offset) >= 0 && (pf->offset + new_offset) <= pf->encrypted_part_plain.size) {
            pf->offset += new_offset;
            result = true;
        }
        break;

    case SEEK_END:
        if (new_offset <= 0 && new_offset >= (0 - pf->encrypted_part_plain.size)) {
            pf->offset = pf->encrypted_part_plain.size + new_offset;
            result = true;
        }
        break;
    }

    if (result)
        pf->end_of_file = false;
    else
        pf_last_error = PF_STATUS_INVALID_PARAMETER;

    //sgx_thread_mutex_unlock(&mutex);

    return result;
}

pf_status_t ipf_get_error(pf_context_t pf) {
    pf_status_t result = PF_STATUS_SUCCESS;

    //sgx_thread_mutex_lock(&mutex);

    if (pf_last_error != PF_STATUS_SUCCESS)
        result = pf_last_error;
    else if (pf->file_status != PF_STATUS_SUCCESS)
        result = pf->file_status;

    //sgx_thread_mutex_unlock(&mutex);

    return result;
}

bool ipf_get_eof(pf_context_t pf) {
    return pf->end_of_file;
}

void ipf_clear_error(pf_context_t pf) {
    //sgx_thread_mutex_lock(&mutex);

    if (pf->file_status == PF_STATUS_UNINITIALIZED ||
        pf->file_status == PF_STATUS_CRYPTO_ERROR ||
        pf->file_status == PF_STATUS_CORRUPTED) {
        // can't fix these...
        //sgx_thread_mutex_unlock(&mutex);
        return;
    }

    if (pf->file_status == PF_STATUS_FLUSH_ERROR) {
        if (ipf_internal_flush(pf, /*false,*/ true))
            pf->file_status = PF_STATUS_SUCCESS;
    }

    if (pf->file_status == PF_STATUS_WRITE_TO_DISK_FAILED) {
        if (ipf_write_all_changes_to_disk(pf, true)) {
            pf->need_writing = false;
            pf->file_status = PF_STATUS_SUCCESS;
        }
    }

/*
    if (file_status == SGX_FILE_STATUS_WRITE_TO_DISK_FAILED_NEED_MC)
    {
        if (write_all_changes_to_disk(true) == true)
        {
            need_writing = false;
            file_status = SGX_FILE_STATUS_MC_NOT_INCREMENTED; // fall through...next 'if' should take care of this one
        }
    }
    if ((file_status == SGX_FILE_STATUS_MC_NOT_INCREMENTED) &&
        (encrypted_part_plain.mc_value <= (UINT_MAX-2)))
    {
        uint32_t mc_value;
        sgx_status_t status = sgx_increment_monotonic_counter(&encrypted_part_plain.mc_uuid, &mc_value);
        if (status == SGX_SUCCESS)
        {
            assert(mc_value == encrypted_part_plain.mc_value);
            file_status = SGX_FILE_STATUS_OK;
        }
        else
        {
            last_error = status;
        }
    }
*/

    if (pf->file_status == PF_STATUS_SUCCESS) {
        pf_last_error = PF_STATUS_SUCCESS;
        pf->end_of_file = false;
    }
    //sgx_thread_mutex_unlock(&mutex);
}

bool ipf_clear_cache(pf_context_t pf) {
    //sgx_thread_mutex_lock(&mutex);

    if (pf->file_status != PF_STATUS_SUCCESS) {
        //sgx_thread_mutex_unlock(&mutex);
        ipf_clear_error(pf); // attempt to fix the file, will also flush it
        //sgx_thread_mutex_lock(&mutex);
    } else {
        ipf_internal_flush(pf, /*false,*/ true);
    }

    if (pf->file_status != PF_STATUS_SUCCESS) {
        // clearing the cache might lead to losing un-saved data
        //sgx_thread_mutex_unlock(&mutex);
        return false;
    }

    while (lruc_size(pf->cache) > 0) {
        void* data = lruc_get_last(pf->cache);

        assert(data != NULL);
        assert(((file_data_node_t*)data)->need_writing == false); // need_writing is in the same offset in both node types
        // for production -
        if (data == NULL || ((file_data_node_t*)data)->need_writing) {
            //sgx_thread_mutex_unlock(&mutex);
            return false;
        }

        lruc_remove_last(pf->cache);

        // before deleting the memory, need to scrub the plain secrets
        if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) {
            // type is in the same offset in both node types
            file_data_node_t* file_data_node = (file_data_node_t*)data;
            memset(&file_data_node->plain, 0, sizeof(file_data_node->plain)); //TODO: memset_s
            cb_free(file_data_node);
        } else {
            file_mht_node_t* file_mht_node = (file_mht_node_t*)data;
            memset(&file_mht_node->plain, 0, sizeof(file_mht_node->plain)); //TODO: memset_s
            cb_free(file_mht_node);
        }
    }

    //sgx_thread_mutex_unlock(&mutex);

    return true;
}

size_t ipf_write(pf_context_t pf, const void* ptr, size_t size, size_t count) {
    if (ptr == NULL || size == 0 || count == 0)
        return 0;

    /*int32_t result32 = sgx_thread_mutex_lock(&mutex);
    if (result32 != 0)
    {
        last_error = result32;
        file_status = SGX_FILE_STATUS_MEMORY_CORRUPTED;
        return 0;
    }*/

    size_t data_left_to_write = size * count;

    // prevent overlap...
    if (((uint64_t)((uint64_t)size * (uint64_t)count)) != (uint64_t)data_left_to_write) {
        pf_last_error = PF_STATUS_INVALID_PARAMETER;
        //sgx_thread_mutex_unlock(&mutex);
        return 0;
    }

    /*if (sgx_is_outside_enclave(ptr, data_left_to_write))
    {
        last_error = SGX_ERROR_INVALID_PARAMETER;
        sgx_thread_mutex_unlock(&mutex);
        return 0;
    }*/

    if (pf->file_status != PF_STATUS_SUCCESS) {
        pf_last_error = pf->file_status;
        //sgx_thread_mutex_unlock(&mutex);
        return 0;
    }

    if (/*pf->open_mode.append == 0 && */pf->open_mode.update == 0 && pf->open_mode.write == 0) {
        pf_last_error = PF_STATUS_INVALID_MODE;
        //sgx_thread_mutex_unlock(&mutex);
        return 0;
    }

    //if (pf->open_mode.append == 1)
    //    pf->offset = pf->encrypted_part_plain.size; // add at the end of the file

    const unsigned char* data_to_write = (const unsigned char*)ptr;

    // the first block of user data is written in the meta-data encrypted part
    if (pf->offset < MD_USER_DATA_SIZE) {
        size_t empty_place_left_in_md = MD_USER_DATA_SIZE - (size_t)pf->offset; // offset is smaller than MD_USER_DATA_SIZE
        if (data_left_to_write <= empty_place_left_in_md) {
            memcpy(&pf->encrypted_part_plain.data[pf->offset], data_to_write, data_left_to_write);
            pf->offset += data_left_to_write;
            data_to_write += data_left_to_write; // not needed, to prevent future errors
            data_left_to_write = 0;
        } else {
            memcpy(&pf->encrypted_part_plain.data[pf->offset], data_to_write, empty_place_left_in_md);
            pf->offset += empty_place_left_in_md;
            data_to_write += empty_place_left_in_md;
            data_left_to_write -= empty_place_left_in_md;
        }

        if (pf->offset > pf->encrypted_part_plain.size)
            pf->encrypted_part_plain.size = pf->offset; // file grew, update the new file size

        pf->need_writing = true;
    }

    while (data_left_to_write > 0) {
        file_data_node_t* file_data_node = NULL;
        file_data_node = ipf_get_data_node(pf); // return the data node of the current offset, will read it from disk or create new one if needed (and also the mht node if needed)
        if (file_data_node == NULL)
            break;

        size_t offset_in_node = (size_t)((pf->offset - MD_USER_DATA_SIZE) % NODE_SIZE);
        size_t empty_place_left_in_node = NODE_SIZE - offset_in_node;

        if (data_left_to_write <= empty_place_left_in_node) {
            // this will be the last write
            memcpy(&file_data_node->plain.data[offset_in_node], data_to_write, data_left_to_write);
            pf->offset += data_left_to_write;
            data_to_write += data_left_to_write; // not needed, to prevent future errors
            data_left_to_write = 0;
        } else {
            memcpy(&file_data_node->plain.data[offset_in_node], data_to_write, empty_place_left_in_node);
            pf->offset += empty_place_left_in_node;
            data_to_write += empty_place_left_in_node;
            data_left_to_write -= empty_place_left_in_node;
        }

        if (pf->offset > pf->encrypted_part_plain.size)
            pf->encrypted_part_plain.size = pf->offset; // file grew, update the new file size

        if (!file_data_node->need_writing) {
            file_data_node->need_writing = true;
            file_mht_node_t* file_mht_node = file_data_node->parent;
            while (file_mht_node->mht_node_number != 0) {
                // set all the mht parent nodes as 'need writing'
                file_mht_node->need_writing = true;
                file_mht_node = file_mht_node->parent;
            }
            pf->root_mht.need_writing = true;
            pf->need_writing = true;
        }
    }

    //sgx_thread_mutex_unlock(&mutex);

    size_t ret_count = ((size * count) - data_left_to_write) / size;
    return ret_count;
}

size_t ipf_read(pf_context_t pf, void* ptr, size_t size, size_t count) {
    if (ptr == NULL || size == 0 || count == 0)
        return 0;

    /*int32_t result32 = sgx_thread_mutex_lock(&mutex);
    if (result32 != 0)
    {
        last_error = result32;
        file_status = SGX_FILE_STATUS_MEMORY_CORRUPTED;
        return 0;
    }*/

    size_t data_left_to_read = size * count;

    // prevent overlap...
    if (((uint64_t)((uint64_t)size * (uint64_t)count)) != (uint64_t)data_left_to_read) {
        pf_last_error = PF_STATUS_INVALID_PARAMETER;
        //sgx_thread_mutex_unlock(&mutex);
        return 0;
    }

    /*if (sgx_is_outside_enclave(ptr, data_left_to_read))
    {
        last_error = EINVAL;
        sgx_thread_mutex_unlock(&mutex);
        return 0;
    }*/

    if (pf->file_status != PF_STATUS_SUCCESS) {
        pf_last_error = pf->file_status;
        //sgx_thread_mutex_unlock(&mutex);
        return 0;
    }

    if (pf->open_mode.read == 0 && pf->open_mode.update == 0) {
        pf_last_error = PF_STATUS_INVALID_MODE;
        //sgx_thread_mutex_unlock(&mutex);
        return 0;
    }

    if (pf->end_of_file) {// not an error
        //sgx_thread_mutex_unlock(&mutex);
        return 0;
    }

    // this check is not really needed, can go on with the code and it will do nothing until the end, but it's more 'right' to check it here
    if (pf->offset == pf->encrypted_part_plain.size) {
        pf->end_of_file = true;
        //sgx_thread_mutex_unlock(&mutex);
        return 0;
    }

    if (((uint64_t)data_left_to_read) > (uint64_t)(pf->encrypted_part_plain.size - pf->offset)) {
        // the request is bigger than what's left in the file
        data_left_to_read = (size_t)(pf->encrypted_part_plain.size - pf->offset);
    }
    size_t data_attempted_to_read = data_left_to_read; // used at the end to return how much we actually read

    unsigned char* out_buffer = (unsigned char*)ptr;

    // the first block of user data is read from the meta-data encrypted part
    if (pf->offset < MD_USER_DATA_SIZE) {
        size_t data_left_in_md = MD_USER_DATA_SIZE - (size_t)pf->offset; // offset is smaller than MD_USER_DATA_SIZE
        if (data_left_to_read <= data_left_in_md) {
            memcpy(out_buffer, &pf->encrypted_part_plain.data[pf->offset], data_left_to_read);
            pf->offset += data_left_to_read;
            out_buffer += data_left_to_read; // not needed, to prevent future errors
            data_left_to_read = 0;
        } else {
            memcpy(out_buffer, &pf->encrypted_part_plain.data[pf->offset], data_left_in_md);
            pf->offset += data_left_in_md;
            out_buffer += data_left_in_md;
            data_left_to_read -= data_left_in_md;
        }
    }

    while (data_left_to_read > 0) {
        file_data_node_t* file_data_node = NULL;
        file_data_node = ipf_get_data_node(pf); // return the data node of the current offset, will read it from disk if needed (and also the mht node if needed)
        if (file_data_node == NULL)
            break;

        size_t offset_in_node = (pf->offset - MD_USER_DATA_SIZE) % NODE_SIZE;
        size_t data_left_in_node = NODE_SIZE - offset_in_node;

        if (data_left_to_read <= data_left_in_node) {
            memcpy(out_buffer, &file_data_node->plain.data[offset_in_node], data_left_to_read);
            pf->offset += data_left_to_read;
            out_buffer += data_left_to_read; // not needed, to prevent future errors
            data_left_to_read = 0;
        } else {
            memcpy(out_buffer, &file_data_node->plain.data[offset_in_node], data_left_in_node);
            pf->offset += data_left_in_node;
            out_buffer += data_left_in_node;
            data_left_to_read -= data_left_in_node;
        }
    }

    //sgx_thread_mutex_unlock(&mutex);

    if (data_left_to_read == 0 && data_attempted_to_read != (size * count)) {
        // user wanted to read more and we had to shrink the request
        assert(pf->offset == pf->encrypted_part_plain.size);
        pf->end_of_file = true;
    }

    size_t ret_count = (data_attempted_to_read - data_left_to_read) / size;
    return ret_count;
}

// this is a very 'specific' function, tied to the architecture of the file layout,
// returning the node numbers according to the offset in the file
void get_node_numbers(uint64_t offset, uint64_t* mht_node_number, uint64_t* data_node_number,
                      uint64_t* physical_mht_node_number, uint64_t* physical_data_node_number) {
    // node 0 - meta data node
    // node 1 - mht
    // nodes 2-97 - data (ATTACHED_DATA_NODES_COUNT == 96)
    // node 98 - mht
    // node 99-195 - data
    // etc.
    uint64_t _mht_node_number;
    uint64_t _data_node_number;
    uint64_t _physical_mht_node_number;
    uint64_t _physical_data_node_number;

    assert(offset >= MD_USER_DATA_SIZE);

    _data_node_number = (offset - MD_USER_DATA_SIZE) / NODE_SIZE;
    _mht_node_number = _data_node_number / ATTACHED_DATA_NODES_COUNT;
    _physical_data_node_number = _data_node_number
                                 + 1 // meta data node
                                 + 1 // mht root
                                 + _mht_node_number; // number of mht nodes in the middle (the root mht mht_node_number is 0)
    _physical_mht_node_number = _physical_data_node_number
                                - _data_node_number % ATTACHED_DATA_NODES_COUNT // now we are at the first data node attached to this mht node
                                - 1; // and now at the mht node itself!

    if (mht_node_number != NULL)
        *mht_node_number = _mht_node_number;
    if (data_node_number != NULL)
        *data_node_number = _data_node_number;
    if (physical_mht_node_number != NULL)
        *physical_mht_node_number = _physical_mht_node_number;
    if (physical_data_node_number != NULL)
        *physical_data_node_number = _physical_data_node_number;
}

file_data_node_t* ipf_get_data_node(pf_context_t pf) {
    file_data_node_t* file_data_node = NULL;

    if (pf->offset < MD_USER_DATA_SIZE) {
        pf_last_error = PF_STATUS_UNKNOWN_ERROR;
        return NULL;
    }

    if ((pf->offset - MD_USER_DATA_SIZE) % NODE_SIZE == 0 && pf->offset == pf->encrypted_part_plain.size) {
        // new node
        file_data_node = ipf_append_data_node(pf);
    } else {
        // existing node
        file_data_node = ipf_read_data_node(pf);
    }

    // bump all the parents mht to reside before the data node in the cache
    if (file_data_node != NULL) {
        file_mht_node_t* file_mht_node = file_data_node->parent;
        while (file_mht_node->mht_node_number != 0) {
            lruc_get(pf->cache, file_mht_node->physical_node_number); // bump the mht node to the head of the lru
            file_mht_node = file_mht_node->parent;
        }
    }

    // even if we didn't get the required data_node, we might have read other nodes in the process
    while (lruc_size(pf->cache) > MAX_PAGES_IN_CACHE) {
        void* data = lruc_get_last(pf->cache);
        assert(data != NULL);
        // for production -
        if (data == NULL) {
            pf_last_error = PF_STATUS_UNKNOWN_ERROR;
            return NULL;
        }

        if (((file_data_node_t*)data)->need_writing == false) {
            // need_writing is in the same offset in both node types
            lruc_remove_last(pf->cache);

            // before deleting the memory, need to scrub the plain secrets
            if (((file_data_node_t*)data)->type == FILE_DATA_NODE_TYPE) {
                // type is in the same offset in both node types
                file_data_node_t* file_data_node1 = (file_data_node_t*)data;
                memset(&file_data_node1->plain, 0, sizeof(file_data_node1->plain)); // TODO: memset_s
                cb_free(file_data_node1);
            } else {
                file_mht_node_t* file_mht_node = (file_mht_node_t*)data;
                memset(&file_mht_node->plain, 0, sizeof(file_mht_node->plain)); // TODO: memset_s
                cb_free(file_mht_node);
            }
        } else {
            if (!ipf_internal_flush(pf, /*false,*/ false)) {
                // error, can't flush cache, file status changed to error
                assert(pf->file_status != PF_STATUS_SUCCESS);
                if (pf->file_status == PF_STATUS_SUCCESS)
                    pf->file_status = PF_STATUS_FLUSH_ERROR; // for release set this anyway
                return NULL; // even if we got the data_node!
            }
        }
    }

    return file_data_node;
}

file_data_node_t* ipf_append_data_node(pf_context_t pf) {
    file_mht_node_t* file_mht_node = ipf_get_mht_node(pf);
    if (file_mht_node == NULL) // some error happened
        return NULL;

    file_data_node_t* new_file_data_node = NULL;

    new_file_data_node = cb_malloc(sizeof(*new_file_data_node));
    if (!new_file_data_node) {
        pf_last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }
    memset(new_file_data_node, 0, sizeof(*new_file_data_node));

    new_file_data_node->type = FILE_DATA_NODE_TYPE;
    new_file_data_node->new_node = true;
    new_file_data_node->parent = file_mht_node;
    get_node_numbers(pf->offset, NULL, &new_file_data_node->data_node_number, NULL,
                     &new_file_data_node->physical_node_number);

    if (!lruc_add(pf->cache, new_file_data_node->physical_node_number, new_file_data_node)) {
        cb_free(new_file_data_node);
        pf_last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    return new_file_data_node;
}

file_data_node_t* ipf_read_data_node(pf_context_t pf) {
    uint64_t data_node_number;
    uint64_t physical_node_number;
    file_mht_node_t* file_mht_node;
    pf_status_t status;

    get_node_numbers(pf->offset, NULL, &data_node_number, NULL, &physical_node_number);

    file_data_node_t* file_data_node = (file_data_node_t*)lruc_get(pf->cache, physical_node_number);
    if (file_data_node != NULL)
        return file_data_node;

    // need to read the data node from the disk

    file_mht_node = ipf_get_mht_node(pf);
    if (file_mht_node == NULL) // some error happened
        return NULL;

    file_data_node = cb_malloc(sizeof(*file_data_node));
    if (!file_data_node) {
        pf_last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }
    memset(file_data_node, 0, sizeof(*file_data_node));
    file_data_node->type = FILE_DATA_NODE_TYPE;
    file_data_node->data_node_number = data_node_number;
    file_data_node->physical_node_number = physical_node_number;
    file_data_node->parent = file_mht_node;

    if (!ipf_read_node(pf->file, file_data_node->physical_node_number, file_data_node->encrypted.cipher, NODE_SIZE)) {
        cb_free(file_data_node);
        return NULL;
    }

    gcm_crypto_data_t* gcm_crypto_data = &file_data_node->parent->plain.data_nodes_crypto[file_data_node->data_node_number % ATTACHED_DATA_NODES_COUNT];

    // this function decrypt the data _and_ checks the integrity of the data against the gmac
    status = cb_crypto_aes_gcm_decrypt(&gcm_crypto_data->key, &empty_iv,
                                       NULL, 0,
                                       file_data_node->encrypted.cipher, NODE_SIZE,
                                       file_data_node->plain.data,
                                       &gcm_crypto_data->gmac);

    if (status != PF_STATUS_SUCCESS) {
        cb_free(file_data_node);
        pf_last_error = status;
        if (status == PF_STATUS_MAC_MISMATCH)
            pf->file_status = PF_STATUS_CORRUPTED;
        return NULL;
    }

    if (!lruc_add(pf->cache, file_data_node->physical_node_number, file_data_node)) {
        // scrub the plaintext data
        memset(&file_data_node->plain, 0, sizeof(file_data_node->plain)); // TODO: memset_s
        cb_free(file_data_node);
        pf_last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    return file_data_node;
}

file_mht_node_t* ipf_get_mht_node(pf_context_t pf) {
    file_mht_node_t* file_mht_node;
    uint64_t mht_node_number;
    uint64_t physical_mht_node_number;

    if (pf->offset < MD_USER_DATA_SIZE) {
        pf_last_error = PF_STATUS_UNKNOWN_ERROR;
        return NULL;
    }

    get_node_numbers(pf->offset, &mht_node_number, NULL, &physical_mht_node_number, NULL);

    if (mht_node_number == 0)
        return &pf->root_mht;

    // file is constructed from 128*4KB = 512KB per MHT node.
    if ((pf->offset - MD_USER_DATA_SIZE) % (ATTACHED_DATA_NODES_COUNT * NODE_SIZE) == 0 &&
         pf->offset == pf->encrypted_part_plain.size) {
        file_mht_node = ipf_append_mht_node(pf, mht_node_number);
    } else {
        file_mht_node = ipf_read_mht_node(pf, mht_node_number);
    }

    return file_mht_node;
}

file_mht_node_t* ipf_append_mht_node(pf_context_t pf, uint64_t mht_node_number) {
    file_mht_node_t* parent_file_mht_node = ipf_read_mht_node(pf, (mht_node_number - 1) / CHILD_MHT_NODES_COUNT);
    if (parent_file_mht_node == NULL) // some error happened
        return NULL;

    uint64_t physical_node_number = 1 + // meta data node
                                    mht_node_number * (1 + ATTACHED_DATA_NODES_COUNT); // the '1' is for the mht node preceding every 96 data nodes

    file_mht_node_t* new_file_mht_node = NULL;
    new_file_mht_node = cb_malloc(sizeof(*new_file_mht_node));
    if (!new_file_mht_node) {
        pf_last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }
    memset(new_file_mht_node, 0, sizeof(*new_file_mht_node));

    new_file_mht_node->type = FILE_MHT_NODE_TYPE;
    new_file_mht_node->new_node = true;
    new_file_mht_node->parent = parent_file_mht_node;
    new_file_mht_node->mht_node_number = mht_node_number;
    new_file_mht_node->physical_node_number = physical_node_number;

    if (!lruc_add(pf->cache, new_file_mht_node->physical_node_number, new_file_mht_node)) {
        cb_free(new_file_mht_node);
        pf_last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    return new_file_mht_node;
}

file_mht_node_t* ipf_read_mht_node(pf_context_t pf, uint64_t mht_node_number) {
    pf_status_t status;

    if (mht_node_number == 0)
        return &pf->root_mht;

    uint64_t physical_node_number = 1 + // meta data node
                                    mht_node_number * (1 + ATTACHED_DATA_NODES_COUNT); // the '1' is for the mht node preceding every 96 data nodes

    file_mht_node_t* file_mht_node = (file_mht_node_t*)lruc_find(pf->cache, physical_node_number);
    if (file_mht_node != NULL)
        return file_mht_node;

    file_mht_node_t* parent_file_mht_node = ipf_read_mht_node(pf, (mht_node_number - 1) / CHILD_MHT_NODES_COUNT);
    if (parent_file_mht_node == NULL) // some error happened
        return NULL;

    file_mht_node = cb_malloc(sizeof(*file_mht_node));
    if (!file_mht_node) {
        pf_last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    memset(file_mht_node, 0, sizeof(*file_mht_node));
    file_mht_node->type = FILE_MHT_NODE_TYPE;
    file_mht_node->mht_node_number = mht_node_number;
    file_mht_node->physical_node_number = physical_node_number;
    file_mht_node->parent = parent_file_mht_node;

    if (!ipf_read_node(pf->file, file_mht_node->physical_node_number, file_mht_node->encrypted.cipher, NODE_SIZE)) {
        cb_free(file_mht_node);
        return NULL;
    }

    gcm_crypto_data_t* gcm_crypto_data = &file_mht_node->parent->plain.mht_nodes_crypto[(file_mht_node->mht_node_number - 1) % CHILD_MHT_NODES_COUNT];

    // this function decrypt the data _and_ checks the integrity of the data against the gmac
    status = cb_crypto_aes_gcm_decrypt(&gcm_crypto_data->key, &empty_iv,
                                       NULL, 0,
                                       file_mht_node->encrypted.cipher, NODE_SIZE,
                                       &file_mht_node->plain,
                                       &gcm_crypto_data->gmac);
    if (status != PF_STATUS_SUCCESS) {
        cb_free(file_mht_node);
        pf_last_error = status;
        if (status == PF_STATUS_MAC_MISMATCH)
            pf->file_status = PF_STATUS_CORRUPTED;
        return NULL;
    }

    if (!lruc_add(pf->cache, file_mht_node->physical_node_number, file_mht_node)) {
        memset(&file_mht_node->plain, 0, sizeof(file_mht_node->plain)); // todo: memset_s
        cb_free(file_mht_node);
        pf_last_error = PF_STATUS_NO_MEMORY;
        return NULL;
    }

    return file_mht_node;
}

bool ipf_do_file_recovery(const char* filename, const char* recovery_filename, uint32_t node_size) {
    pf_handle_t recovery_file = NULL;
    pf_handle_t source_file = NULL;
    uint32_t nodes_count = 0;
    uint32_t recovery_node_size = (uint32_t)(sizeof(uint64_t)) + node_size; // node offset + data
    uint64_t file_size = 0;
    uint8_t* recovery_node = NULL;
    uint32_t i = 0;
    bool ret = false;

    do {
        if (filename == NULL || strnlen(filename, 1) == 0) {
            pf_last_error = PF_STATUS_RECOVERY_IMPOSSIBLE;
            return false;
        }

        if (recovery_filename == NULL || strnlen(recovery_filename, 1) == 0) {
            pf_last_error = PF_STATUS_RECOVERY_IMPOSSIBLE;
            return false;
        }

        pf_status_t status = cb_open(recovery_filename, PF_FILE_MODE_READ, &recovery_file, &file_size);
        if (status != PF_STATUS_SUCCESS){
            pf_last_error = status;
            break;
        }

        if (file_size % recovery_node_size != 0) {
            // corrupted recovery file
            pf_last_error = PF_STATUS_CORRUPTED;
            break;
        }

        nodes_count = (uint32_t)(file_size / recovery_node_size);

        recovery_node = (uint8_t*)cb_malloc(recovery_node_size);
        if (recovery_node == NULL) {
            pf_last_error = PF_STATUS_NO_MEMORY;
            break;
        }

        status = cb_open(filename, PF_FILE_MODE_READ|PF_FILE_MODE_WRITE, &source_file, NULL);
        if (status != PF_STATUS_SUCCESS){
            pf_last_error = status;
            break;
        }

        for (i = 0; i < nodes_count; i++) {
            if (!ipf_read_node(recovery_file, i, recovery_node, recovery_node_size)) {
                // last error already set
                break;
            }

            uint64_t node_number = *((uint64_t*)recovery_node);
            if (!ipf_write_node(source_file, node_number, &recovery_node[sizeof(uint64_t)], node_size)) {
                // last error already set
                break;
            }
            /*
            // seek the regular file to the required offset
            if ((result = fseeko(source_file, (*((uint64_t*)recovery_node)) * node_size, SEEK_SET)) != 0)
            {
                DEBUG_PRINT("fseeko returned %d\n", result);
                if (errno != 0)
                    ret = errno;
                break;
            }

            // write down the original data from the recovery file
            if ((count = fwrite(&recovery_node[sizeof(uint64_t)], node_size, 1, source_file)) != 1)
            {
                DEBUG_PRINT("fwrite returned %ld [!= 1]\n", count);
                err = ferror(source_file);
                if (err != 0)
                    ret = err;
                else if (errno != 0)
                    ret = errno;
                break;
            }*/
        }

        if (i != nodes_count) // the 'for' loop exited with error
            break;

        status = cb_flush(source_file);
        if (status != PF_STATUS_SUCCESS) {
            pf_last_error = status;
            break;
        }

        ret = true;

    } while (0);

    cb_free(recovery_node);
    cb_close(source_file);
    cb_close(recovery_file);

    if (ret)
        cb_delete(recovery_filename);

    return ret;
}

// public API

pf_status_t pf_open(pf_handle_t handle, const char* path, size_t underlying_size, pf_file_mode_t mode,
                    bool create, const pf_key_t* key, pf_context_t* context) {
    open_mode_t om = {0};
    om.read = mode & PF_FILE_MODE_READ;
    om.write = mode & PF_FILE_MODE_WRITE;
    om.update = !create;
    *context = ipf_open(path, om, handle, underlying_size, key);
    if (*context)
        return PF_STATUS_SUCCESS;
    return pf_last_error;
}

pf_status_t pf_close(pf_context_t pf) {
    if (ipf_close(pf))
        return PF_STATUS_SUCCESS;
    return pf_last_error;
}

pf_status_t pf_get_size(pf_context_t pf, size_t* size) {
    *size = pf->encrypted_part_plain.size;
    return PF_STATUS_SUCCESS;
}

// TODO: just write zeros at the end for extending, shrinking may be harder
pf_status_t pf_set_size(pf_context_t pf, size_t size) {
    __UNUSED(pf);
    __UNUSED(size);
    return PF_STATUS_NOT_IMPLEMENTED;
}

pf_status_t pf_read(pf_context_t pf, uint64_t offset, size_t size, void* output) {
    if (!ipf_seek(pf, offset, SEEK_SET))
        return pf_last_error;
    if (!ipf_read(pf, output, 1, size))
        return pf_last_error;
    return PF_STATUS_SUCCESS;
}

pf_status_t pf_write(pf_context_t pf, uint64_t offset, size_t size, const void* input) {
    if (!ipf_seek(pf, offset, SEEK_SET))
        return pf_last_error;
    if (!ipf_write(pf, input, 1, size))
        return pf_last_error;
    return PF_STATUS_SUCCESS;
}
