module bindbc.libmicrohttpd.dynamiccfg;

version(BindBC_Static) {}
else version(BindLibMicroHTTPD_Static) {}
else:

public import bindbc.libmicrohttpd.header;
public import bindbc.libmicrohttpd.config;

import bindbc.loader;
import bindbc.loader.sharedlib;

extern (C) @nogc nothrow
{
    alias pMHD_start_daemon_va = MHD_Daemon* function(
        uint flags,
        uint16_t port,
        MHD_AcceptPolicyCallback apc,
        void *apc_cls,
        MHD_AccessHandlerCallback dh,
        void *dh_cls,
        va_list ap);
    alias pMHD_start_daemon = MHD_Daemon* function(
        uint flags,
        uint16_t port,
        MHD_AcceptPolicyCallback apc, void *apc_cls,
        MHD_AccessHandlerCallback dh, void *dh_cls,
        ...);
    alias pMHD_quiesce_daemon = MHD_socket function(MHD_Daemon *daemon);
    alias pMHD_stop_daemon = void function(MHD_Daemon *daemon);
    alias pMHD_add_connection = MHD_Result function(
        MHD_Daemon *daemon,
        MHD_socket client_socket,
        const(sockaddr) *addr,
        socklen_t addrlen);
    alias pMHD_get_fdset = MHD_Result function(
        MHD_Daemon *daemon,
        fd_set *read_fd_set,
        fd_set *write_fd_set,
        fd_set *except_fd_set,
        MHD_socket *max_fd);
    alias pMHD_get_fdset2 = MHD_Result function(
        MHD_Daemon *daemon,
        fd_set *read_fd_set,
        fd_set *write_fd_set,
        fd_set *except_fd_set,
        MHD_socket *max_fd,
        uint fd_setsize);
    alias pMHD_get_timeout = MHD_Result function(
        MHD_Daemon *daemon,
        MHD_UNSIGNED_LONG_LONG *timeout);
    alias pMHD_free = void function(void *ptr);
    //alias pMHD_get_timeout64 = MHD_Result function(MHD_Daemon *daemon, uint64_t *timeout);
    //alias pMHD_get_timeout64s = int64_t function(MHD_Daemon *daemon);
    //alias pMHD_get_timeout_i = int function(MHD_Daemon *daemon);
    alias pMHD_run = MHD_Result function(MHD_Daemon *daemon);
    alias pMHD_run_wait = MHD_Result function(MHD_Daemon *daemon, int32_t millisec);
    alias pMHD_run_from_select = MHD_Result function(
        MHD_Daemon *daemon,
        const(fd_set) *read_fd_set,
        const(fd_set) *write_fd_set,
        const(fd_set) *except_fd_set);
    alias pMHD_get_connection_values = int function(
        MHD_Connection *connection,
        MHD_ValueKind kind,
        MHD_KeyValueIterator iterator,
        void *iterator_cls);
    alias pMHD_get_connection_values_n = int function(
        MHD_Connection *connection,
        MHD_ValueKind kind,
        MHD_KeyValueIteratorN iterator,
        void *iterator_cls);
    alias pMHD_set_connection_value = MHD_Result function(
        MHD_Connection *connection,
        MHD_ValueKind kind,
        const(char) *key,
        const(char) *value);
    alias pMHD_set_connection_value_n = MHD_Result function(
        MHD_Connection *connection,
        MHD_ValueKind kind,
        const(char) *key, size_t key_size,
        const(char) *value, size_t value_size);
    alias pMHD_set_panic_func = void function(MHD_PanicCallback cb, void *cls);
    alias pMHD_http_unescape = size_t function(char *val);
    alias pMHD_lookup_connection_value = const(char)* function(
        MHD_Connection *connection,
        MHD_ValueKind kind,
        const(char) *key);
    alias pMHD_lookup_connection_value_n = MHD_Result function(
        MHD_Connection *connection,
        MHD_ValueKind kind,
        const(char) *key,
        size_t key_size,
        const(char) **value_ptr,
        size_t *value_size_ptr);
    alias pMHD_queue_response = MHD_Result function(
        MHD_Connection *connection,
        uint status_code,
        MHD_Response *response);
    alias pMHD_suspend_connection = void function(MHD_Connection *connection);
    alias pMHD_resume_connection = void function(MHD_Connection *connection);
    alias pMHD_set_response_options = MHD_Result function(
        MHD_Response *response,
        MHD_ResponseFlags flags,
        ...);
    alias pMHD_create_response_from_callback = MHD_Response* function(
        uint64_t size,
        size_t block_size,
        MHD_ContentReaderCallback crc, void *crc_cls,
        MHD_ContentReaderFreeCallback crfc);
    alias pMHD_create_response_from_buffer = MHD_Response* function(
        size_t size,
        void *buffer,
        MHD_ResponseMemoryMode mode);
    /*alias pMHD_create_response_from_buffer_static = MHD_Response* function(
        size_t size,
        const(void) *buffer);*/
    /*alias pMHD_create_response_from_buffer_copy = MHD_Response* function(
        size_t size,
        const(void) *buffer);*/
    alias pMHD_create_response_from_buffer_with_free_callback = MHD_Response* function(
        size_t size,
        void *buffer,
        MHD_ContentReaderFreeCallback crfc);
    alias pMHD_create_response_from_buffer_with_free_callback_cls = MHD_Response* function(
        size_t size,
        const(void) *buffer,
        MHD_ContentReaderFreeCallback crfc,
        void *crfc_cls);
    alias pMHD_create_response_from_fd = MHD_Response* function(size_t size, int fd);
    alias pMHD_create_response_from_pipe = MHD_Response* function(int fd);
    alias pMHD_create_response_from_fd64 = MHD_Response* function(uint64_t size, int fd);
    alias pMHD_create_response_from_fd_at_offset64 = MHD_Response* function(
        uint64_t size,
        int fd,
        uint64_t offset);
    alias pMHD_create_response_from_iovec = MHD_Response* function(
        const(MHD_IoVec) *iov,
        uint iovcnt,
        MHD_ContentReaderFreeCallback free_cb,
        void *cls);
    //alias pMHD_create_response_empty = MHD_Response* function(MHD_ResponseFlags flags);
    alias pMHD_upgrade_action = MHD_Result function(
        MHD_UpgradeResponseHandle *urh,
        MHD_UpgradeAction action,
        ...);
    alias pMHD_create_response_for_upgrade = MHD_Response* function(
        MHD_UpgradeHandler upgrade_handler,
        void *upgrade_handler_cls);
    alias pMHD_destroy_response = void function(MHD_Response *response);
    alias pMHD_add_response_header = MHD_Result function(
        MHD_Response *response,
        const(char) *header,
        const(char) *content);
    alias pMHD_add_response_footer = MHD_Result function(
        MHD_Response *response,
        const(char) *footer,
        const(char) *content);
    alias pMHD_del_response_header = MHD_Result function(
        MHD_Response *response,
        const(char) *header,
        const(char) *content);
    alias pMHD_get_response_headers = int function(
        MHD_Response *response,
        MHD_KeyValueIterator iterator,
        void *iterator_cls);
    alias pMHD_get_response_header = const(char)* function(
        MHD_Response *response,
        const(char) *key);
    alias pMHD_create_post_processor = MHD_PostProcessor* function(
        MHD_Connection *connection,
        size_t buffer_size,
        MHD_PostDataIterator iter, void *iter_cls);
    alias pMHD_post_process = MHD_Result function(
        MHD_PostProcessor *pp,
        const(char) *post_data,
        size_t post_data_len);
    alias pMHD_destroy_post_processor = MHD_Result function(MHD_PostProcessor *pp);
    //alias pMHD_digest_get_hash_size = size_t function(MHD_DigestAuthAlgo3 algo3);
    /*alias pMHD_digest_auth_calc_userhash = MHD_Result function(
        MHD_DigestAuthAlgo3 algo3,
        const(char) *username,
        const(char) *realm,
        void *userhash_bin,
        size_t bin_buf_size);*/
    /*alias pMHD_digest_auth_calc_userhash_hex = MHD_Result function(
        MHD_DigestAuthAlgo3 algo3,
        const(char) *username,
        const(char) *realm,
        char *userhash_hex,
        size_t hex_buf_size);*/
    /*alias pMHD_digest_auth_get_request_info3 = MHD_DigestAuthInfo* function(
        MHD_Connection *connection);
    alias pMHD_digest_auth_get_username3 = MHD_DigestAuthUsernameInfo* function(
        MHD_Connection *connection);
    alias pMHD_digest_auth_check3 = MHD_DigestAuthResult function(
        MHD_Connection *connection,
        const(char) *realm,
        const(char) *username,
        const(char) *password,
        uint nonce_timeout,
        uint32_t max_nc,
        MHD_DigestAuthMultiQOP mqop,
        MHD_DigestAuthMultiAlgo3 malgo3);
    alias pMHD_digest_auth_calc_userdigest = MHD_Result function(
        MHD_DigestAuthAlgo3 algo3,
        const(char) *username,
        const(char) *realm,
        const(char) *password,
        void *userdigest_bin,
        size_t bin_buf_size);
    alias pMHD_digest_auth_check_digest3 = MHD_DigestAuthResult function(
        MHD_Connection *connection,
        const(char) *realm,
        const(char) *username,
        const(void) *userdigest,
        size_t userdigest_size,
        uint nonce_timeout,
        uint32_t max_nc,
        MHD_DigestAuthMultiQOP mqop,
        MHD_DigestAuthMultiAlgo3 malgo3);
    alias pMHD_queue_auth_required_response3 = MHD_Result function(
        MHD_Connection *connection,
        const(char) *realm,
        const(char) *opaque,
        const(char) *domain,
        MHD_Response *response,
        int signal_stale,
        MHD_DigestAuthMultiQOP qop,
        MHD_DigestAuthMultiAlgo3 algo,
        int userhash_support,
        int prefer_utf8);*/
    alias pMHD_digest_auth_check2 = int function(
        MHD_Connection *connection,
        const(char) *realm,
        const(char) *username,
        const(char) *password,
        uint nonce_timeout,
        MHD_DigestAuthAlgorithm algo);
    alias pMHD_digest_auth_check = int function(
        MHD_Connection *connection,
        const(char) *realm,
        const(char) *username,
        const(char) *password,
        uint nonce_timeout);
    alias pMHD_digest_auth_check_digest2 = int function(
        MHD_Connection *connection,
        const(char) *realm,
        const(char) *username,
        const(uint8_t) *digest,
        size_t digest_size,
        uint nonce_timeout,
        MHD_DigestAuthAlgorithm algo);
    alias pMHD_digest_auth_check_digest = int function(
        MHD_Connection *connection,
        const(char) *realm,
        const(char) *username,
        const(uint8_t) *digest,
        int nonce_timeout);
    alias pMHD_queue_auth_fail_response2 = MHD_Result function(
        MHD_Connection *connection,
        const(char) *realm,
        const(char) *opaque,
        MHD_Response *response,
        int signal_stale,
        MHD_DigestAuthAlgorithm algo);
    alias pMHD_queue_auth_fail_response = MHD_Result function(
        MHD_Connection *connection,
        const(char) *realm,
        const(char) *opaque,
        MHD_Response *response,
        int signal_stale);
    /*alias pMHD_basic_auth_get_username_password3 = MHD_BasicAuthInfo* function(
        MHD_Connection *connection);*/
    /*alias pMHD_queue_basic_auth_fail_response3 = MHD_Result function(
        MHD_Connection *connection,
        const(char) *realm,
        int prefer_utf8,
        MHD_Response *response);*/
    alias pMHD_queue_basic_auth_fail_response = MHD_Result function(
        MHD_Connection *connection,
        const(char) *realm,
        MHD_Response *response);
    alias pMHD_get_connection_info = const(MHD_ConnectionInfo)* function(
        MHD_Connection *connection,
        MHD_ConnectionInfoType info_type,
        ...);
    alias pMHD_set_connection_option = MHD_Result function(
        MHD_Connection *connection,
        MHD_CONNECTION_OPTION option,
        ...);
    alias pMHD_get_daemon_info = const(MHD_DaemonInfo)* function(
        MHD_Daemon *daemon,
        MHD_DaemonInfoType info_type,
        ...);
    alias pMHD_get_version = const(char)* function();
    alias pMHD_is_feature_supported = MHD_Result function(MHD_FEATURE feature);

    version (LibMicroHTTPD_AllowDeprecated)
    {
        alias pMHD_basic_auth_get_username_password = char* function(
            MHD_Connection *connection,
            char **password);
        alias pMHD_create_response_from_fd_at_offset = MHD_Response* function(
            size_t size,
            int fd,
            off_t offset);
        alias pMHD_create_response_from_data = MHD_Response* function(
            size_t size,
            void *data,
            int must_free,
            int must_copy);
    }
}

public __gshared
{
    pMHD_start_daemon_va    MHD_start_daemon_va;
    pMHD_start_daemon   MHD_start_daemon;
    pMHD_quiesce_daemon     MHD_quiesce_daemon;
    pMHD_stop_daemon    MHD_stop_daemon;
    pMHD_add_connection     MHD_add_connection;
    pMHD_get_fdset  MHD_get_fdset;
    pMHD_get_fdset2     MHD_get_fdset2;
    pMHD_get_timeout    MHD_get_timeout;
    pMHD_free   MHD_free;
    //pMHD_get_timeout64  MHD_get_timeout64;
    //pMHD_get_timeout64s     MHD_get_timeout64s;
    //pMHD_get_timeout_i  MHD_get_timeout_i;
    pMHD_run    MHD_run;
    pMHD_run_from_select    MHD_run_from_select;
    pMHD_get_connection_values  MHD_get_connection_values;
    pMHD_set_connection_value   MHD_set_connection_value;
    pMHD_set_panic_func     MHD_set_panic_func;
    pMHD_http_unescape  MHD_http_unescape;
    pMHD_lookup_connection_value    MHD_lookup_connection_value;
    pMHD_queue_response     MHD_queue_response;
    pMHD_suspend_connection     MHD_suspend_connection;
    pMHD_resume_connection  MHD_resume_connection;
    pMHD_set_response_options   MHD_set_response_options;
    pMHD_create_response_from_callback  MHD_create_response_from_callback;
    pMHD_create_response_from_buffer    MHD_create_response_from_buffer;
    //pMHD_create_response_from_buffer_static     MHD_create_response_from_buffer_static;
    //pMHD_create_response_from_buffer_copy   MHD_create_response_from_buffer_copy;
    pMHD_create_response_from_fd    MHD_create_response_from_fd;
    pMHD_create_response_from_fd64  MHD_create_response_from_fd64;
    pMHD_create_response_from_fd_at_offset64    MHD_create_response_from_fd_at_offset64;
    //pMHD_create_response_empty  MHD_create_response_empty;
    pMHD_upgrade_action     MHD_upgrade_action;
    pMHD_create_response_for_upgrade    MHD_create_response_for_upgrade;
    pMHD_destroy_response   MHD_destroy_response;
    pMHD_add_response_header    MHD_add_response_header;
    pMHD_add_response_footer    MHD_add_response_footer;
    pMHD_del_response_header    MHD_del_response_header;
    pMHD_get_response_headers   MHD_get_response_headers;
    pMHD_get_response_header    MHD_get_response_header;
    pMHD_create_post_processor  MHD_create_post_processor;
    pMHD_post_process   MHD_post_process;
    pMHD_destroy_post_processor     MHD_destroy_post_processor;
    //pMHD_digest_get_hash_size   MHD_digest_get_hash_size;
    //pMHD_digest_auth_calc_userhash  MHD_digest_auth_calc_userhash;
    //pMHD_digest_auth_calc_userhash_hex  MHD_digest_auth_calc_userhash_hex;
    //pMHD_digest_auth_get_request_info3  MHD_digest_auth_get_request_info3;
    //pMHD_digest_auth_get_username3  MHD_digest_auth_get_username3;
    //pMHD_digest_auth_check3     MHD_digest_auth_check3;
    //pMHD_digest_auth_calc_userdigest    MHD_digest_auth_calc_userdigest;
    //pMHD_digest_auth_check_digest3  MHD_digest_auth_check_digest3;
    //pMHD_queue_auth_required_response3  MHD_queue_auth_required_response3;
    pMHD_digest_auth_check  MHD_digest_auth_check;
    pMHD_digest_auth_check_digest   MHD_digest_auth_check_digest;
    pMHD_queue_auth_fail_response   MHD_queue_auth_fail_response;
    //pMHD_basic_auth_get_username_password3  MHD_basic_auth_get_username_password3;
    //pMHD_queue_basic_auth_fail_response3    MHD_queue_basic_auth_fail_response3;
    pMHD_queue_basic_auth_fail_response     MHD_queue_basic_auth_fail_response;
    pMHD_get_connection_info    MHD_get_connection_info;
    pMHD_set_connection_option  MHD_set_connection_option;
    pMHD_get_daemon_info    MHD_get_daemon_info;
    pMHD_get_version    MHD_get_version;
    pMHD_is_feature_supported   MHD_is_feature_supported;
    
    //TODO: These should be included for their respective version
    version (LibMicroHTTPD_AllowDeprecated)
    {
        pMHD_basic_auth_get_username_password MHD_basic_auth_get_username_password;
        pMHD_create_response_from_fd_at_offset MHD_create_response_from_fd_at_offset;
        pMHD_create_response_from_data MHD_create_response_from_data;
    }
    
    // roughly
    static if (MHD_VERSION >= LibMicroHTTPDSupport.v000966)
    {
        pMHD_get_connection_values_n    MHD_get_connection_values_n;
        pMHD_lookup_connection_value_n  MHD_lookup_connection_value_n;
        pMHD_create_response_from_buffer_with_free_callback MHD_create_response_from_buffer_with_free_callback;
        pMHD_digest_auth_check2     MHD_digest_auth_check2;
        pMHD_digest_auth_check_digest2  MHD_digest_auth_check_digest2;
        pMHD_queue_auth_fail_response2  MHD_queue_auth_fail_response2;
    }
    
    // roughly
    static if (MHD_VERSION >= LibMicroHTTPDSupport.v000975)
    {
        pMHD_run_wait   MHD_run_wait;
        pMHD_set_connection_value_n     MHD_set_connection_value_n;
        pMHD_create_response_from_buffer_with_free_callback_cls     MHD_create_response_from_buffer_with_free_callback_cls;
        pMHD_create_response_from_pipe  MHD_create_response_from_pipe;
        pMHD_create_response_from_iovec     MHD_create_response_from_iovec;
    }
}

public LibMicroHTTPDSupport loadLibMicroHTTPD()
{
    version (Windows)
    {
        static immutable const(char)*[] libraries = [
            "libmicrohttpd.dll"
        ];
    }
    else version (OSX)
    {
        static immutable const(char)*[] libraries = [
            "libmicrohttpd.dylib"
        ];
    }
    else version (Posix)
    {
        static immutable const(char)*[] libraries = [
            "libmicrohttpd.so",
            "libmicrohttpd.so.0",
            "libmicrohttpd.so.12",
        ];
    }
    
    foreach (libname; libraries)
    {
        LibMicroHTTPDSupport s = loadLibMicroHTTPD(libname);
        if (s != LibMicroHTTPDSupport.noLibrary) return s;
    }
    
    return LibMicroHTTPDSupport.noLibrary;
}

public LibMicroHTTPDSupport loadLibMicroHTTPD(const(char)* libname)
{
    SharedLib lib = load(libname);
    if (lib == invalidHandle)
        return LibMicroHTTPDSupport.noLibrary;
    
    size_t ecount = errorCount;
    //LibMicroHTTPDSupport support = LibMicroHTTPDSupport.badLibrary;
    
    // NOTE: Commented is stuff found in master branch
    bindSymbol(lib, cast(void**)&MHD_start_daemon_va,   "MHD_start_daemon_va");
    bindSymbol(lib, cast(void**)&MHD_start_daemon,  "MHD_start_daemon");
    bindSymbol(lib, cast(void**)&MHD_quiesce_daemon,    "MHD_quiesce_daemon");
    bindSymbol(lib, cast(void**)&MHD_stop_daemon,   "MHD_stop_daemon");
    bindSymbol(lib, cast(void**)&MHD_add_connection,    "MHD_add_connection");
    bindSymbol(lib, cast(void**)&MHD_get_fdset,     "MHD_get_fdset");
    bindSymbol(lib, cast(void**)&MHD_get_fdset2,    "MHD_get_fdset2");
    bindSymbol(lib, cast(void**)&MHD_get_timeout,   "MHD_get_timeout");
    bindSymbol(lib, cast(void**)&MHD_free,  "MHD_free");
    //bindSymbol(lib, cast(void**)&MHD_get_timeout64,     "MHD_get_timeout64");
    //bindSymbol(lib, cast(void**)&MHD_get_timeout64s,    "MHD_get_timeout64s");
    //bindSymbol(lib, cast(void**)&MHD_get_timeout_i,     "MHD_get_timeout_i");
    bindSymbol(lib, cast(void**)&MHD_run,   "MHD_run");
    bindSymbol(lib, cast(void**)&MHD_run_from_select,   "MHD_run_from_select");
    bindSymbol(lib, cast(void**)&MHD_get_connection_values,     "MHD_get_connection_values");
    bindSymbol(lib, cast(void**)&MHD_set_connection_value,  "MHD_set_connection_value");
    bindSymbol(lib, cast(void**)&MHD_set_panic_func,    "MHD_set_panic_func");
    bindSymbol(lib, cast(void**)&MHD_http_unescape,     "MHD_http_unescape");
    bindSymbol(lib, cast(void**)&MHD_lookup_connection_value,   "MHD_lookup_connection_value");
    bindSymbol(lib, cast(void**)&MHD_queue_response,    "MHD_queue_response");
    bindSymbol(lib, cast(void**)&MHD_suspend_connection,    "MHD_suspend_connection");
    bindSymbol(lib, cast(void**)&MHD_resume_connection,     "MHD_resume_connection");
    bindSymbol(lib, cast(void**)&MHD_set_response_options,  "MHD_set_response_options");
    bindSymbol(lib, cast(void**)&MHD_create_response_from_callback,     "MHD_create_response_from_callback");
    bindSymbol(lib, cast(void**)&MHD_create_response_from_buffer,   "MHD_create_response_from_buffer");
    //bindSymbol(lib, cast(void**)&MHD_create_response_from_buffer_static,    "MHD_create_response_from_buffer_static");
    //bindSymbol(lib, cast(void**)&MHD_create_response_from_buffer_copy,  "MHD_create_response_from_buffer_copy");
    bindSymbol(lib, cast(void**)&MHD_create_response_from_fd,   "MHD_create_response_from_fd");
    bindSymbol(lib, cast(void**)&MHD_create_response_from_fd64,     "MHD_create_response_from_fd64");
    bindSymbol(lib, cast(void**)&MHD_create_response_from_fd_at_offset64,   "MHD_create_response_from_fd_at_offset64");
    //bindSymbol(lib, cast(void**)&MHD_create_response_empty,     "MHD_create_response_empty");
    bindSymbol(lib, cast(void**)&MHD_upgrade_action,    "MHD_upgrade_action");
    bindSymbol(lib, cast(void**)&MHD_create_response_for_upgrade,   "MHD_create_response_for_upgrade");
    bindSymbol(lib, cast(void**)&MHD_destroy_response,  "MHD_destroy_response");
    bindSymbol(lib, cast(void**)&MHD_add_response_header,   "MHD_add_response_header");
    bindSymbol(lib, cast(void**)&MHD_add_response_footer,   "MHD_add_response_footer");
    bindSymbol(lib, cast(void**)&MHD_del_response_header,   "MHD_del_response_header");
    bindSymbol(lib, cast(void**)&MHD_get_response_headers,  "MHD_get_response_headers");
    bindSymbol(lib, cast(void**)&MHD_get_response_header,   "MHD_get_response_header");
    bindSymbol(lib, cast(void**)&MHD_create_post_processor,     "MHD_create_post_processor");
    bindSymbol(lib, cast(void**)&MHD_post_process,  "MHD_post_process");
    bindSymbol(lib, cast(void**)&MHD_destroy_post_processor,    "MHD_destroy_post_processor");
    //bindSymbol(lib, cast(void**)&MHD_digest_get_hash_size,  "MHD_digest_get_hash_size");
    //bindSymbol(lib, cast(void**)&MHD_digest_auth_calc_userhash,     "MHD_digest_auth_calc_userhash");
    //bindSymbol(lib, cast(void**)&MHD_digest_auth_calc_userhash_hex,     "MHD_digest_auth_calc_userhash_hex");
    //bindSymbol(lib, cast(void**)&MHD_digest_auth_get_request_info3,     "MHD_digest_auth_get_request_info3");
    //bindSymbol(lib, cast(void**)&MHD_digest_auth_get_username3,     "MHD_digest_auth_get_username3");
    //bindSymbol(lib, cast(void**)&MHD_digest_auth_check3,    "MHD_digest_auth_check3");
    //bindSymbol(lib, cast(void**)&MHD_digest_auth_calc_userdigest,   "MHD_digest_auth_calc_userdigest");
    //bindSymbol(lib, cast(void**)&MHD_digest_auth_check_digest3,     "MHD_digest_auth_check_digest3");
    //bindSymbol(lib, cast(void**)&MHD_queue_auth_required_response3,     "MHD_queue_auth_required_response3");
    bindSymbol(lib, cast(void**)&MHD_digest_auth_check,     "MHD_digest_auth_check");
    bindSymbol(lib, cast(void**)&MHD_queue_auth_fail_response,  "MHD_queue_auth_fail_response");
    //bindSymbol(lib, cast(void**)&MHD_basic_auth_get_username_password3,     "MHD_basic_auth_get_username_password3");
    //bindSymbol(lib, cast(void**)&MHD_queue_basic_auth_fail_response3,   "MHD_queue_basic_auth_fail_response3");
    bindSymbol(lib, cast(void**)&MHD_queue_basic_auth_fail_response,    "MHD_queue_basic_auth_fail_response");
    bindSymbol(lib, cast(void**)&MHD_get_connection_info,   "MHD_get_connection_info");
    bindSymbol(lib, cast(void**)&MHD_set_connection_option,     "MHD_set_connection_option");
    bindSymbol(lib, cast(void**)&MHD_get_daemon_info,   "MHD_get_daemon_info");
    bindSymbol(lib, cast(void**)&MHD_get_version,   "MHD_get_version");
    bindSymbol(lib, cast(void**)&MHD_is_feature_supported,  "MHD_is_feature_supported");
    
    //TODO: Include them in older versions
    version (LibMicroHTTPD_AllowDeprecated)
    {
        bindSymbol(lib, cast(void**)&MHD_basic_auth_get_username_password, "MHD_basic_auth_get_username_password");
        bindSymbol(lib, cast(void**)&MHD_create_response_from_fd_at_offset, "MHD_create_response_from_fd_at_offset");
        bindSymbol(lib, cast(void**)&MHD_create_response_from_data, "MHD_create_response_from_data");
    }
    
    // roughly
    static if (MHD_VERSION >= LibMicroHTTPDSupport.v000966)
    {
        bindSymbol(lib, cast(void**)&MHD_get_connection_values_n,   "MHD_get_connection_values_n");
        bindSymbol(lib, cast(void**)&MHD_lookup_connection_value_n,     "MHD_lookup_connection_value_n");
        bindSymbol(lib, cast(void**)&MHD_create_response_from_buffer_with_free_callback,
            "MHD_create_response_from_buffer_with_free_callback");
        bindSymbol(lib, cast(void**)&MHD_digest_auth_check2,    "MHD_digest_auth_check2");
        bindSymbol(lib, cast(void**)&MHD_digest_auth_check_digest2,     "MHD_digest_auth_check_digest2");
        bindSymbol(lib, cast(void**)&MHD_queue_auth_fail_response2,     "MHD_queue_auth_fail_response2");
    }
    
    // roughly
    static if (MHD_VERSION >= LibMicroHTTPDSupport.v000975)
    {
        bindSymbol(lib, cast(void**)&MHD_run_wait,  "MHD_run_wait");
        bindSymbol(lib, cast(void**)&MHD_set_connection_value_n,    "MHD_set_connection_value_n");
        bindSymbol(lib, cast(void**)&MHD_create_response_from_buffer_with_free_callback_cls,
            "MHD_create_response_from_buffer_with_free_callback_cls");
        bindSymbol(lib, cast(void**)&MHD_create_response_from_pipe,     "MHD_create_response_from_pipe");
        bindSymbol(lib, cast(void**)&MHD_create_response_from_iovec,    "MHD_create_response_from_iovec");
    }
    
    //TODO: Check version
    //const(char)* ver = MHD_get_version();
    
    return ecount != errorCount ? LibMicroHTTPDSupport.badLibrary : MHD_VERSION;
}
