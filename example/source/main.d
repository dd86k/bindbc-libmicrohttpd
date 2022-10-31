module main;

import bindbc.libmicrohttpd;
import bindbc.loader; // for errors
import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.stdint;
import core.stdc.string;

extern (C):

// Older compiler versions might complain about this when
// using betterC/no-druntime options.
private void _d_dso_registry() {}

immutable const(char)* PAGE =
    "<html><head><title>libmicrohttpd demo</title>"~
    "</head><body>libmicrohttpd demo</body></html>";

MHD_Result ahc_echo(void *cls,
    MHD_Connection *connection,
    const(char) *url,
    const(char) *method,
    const(char) *version_,
    const(char) *upload_data,
    size_t *upload_data_size,
    void **ptr)
{
    __gshared int dummy;
    const(char) *page = cast(const(char)*)cls;

    if (strcmp(method, "GET"))
        return MHD_NO; /* unexpected method */
    
    if (&dummy != *ptr)
    {
        // The first time only the headers are valid,
        // do not respond in the first round...
        *ptr = &dummy;
        return MHD_YES;
    }
    
    if (*upload_data_size)
        return MHD_NO; // upload data in a GET!?
    
    *ptr = null; // clear context pointer
    MHD_Response *response = MHD_create_response_from_buffer(
        strlen(page),
        cast(void*)page,
        MHD_RESPMEM_PERSISTENT);
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

int main(int argc, const(char) **argv)
{
    switch (loadLibMicroHTTPD) with (LibMicroHTTPDSupport)
    {
        case noLibrary:
            foreach (const(ErrorInfo) err; errors)
            {
                printf("error: %s\n", err.message);
            }
            assert(0, "Library not found on system");
        case badLibrary:
            foreach (const(ErrorInfo) err; errors)
            {
                printf("error: %s %s\n", err.error, err.message);
            }
            assert(0, "Could not load some symbols");
        default:
    }
    
    // Defaults
    ushort port = 8088;
    
    if (argc >= 2)
    {
        port = cast(ushort)atoi(argv[1]);
    }
    
    printf("configuration: %08x\n", MHD_VERSION);
    printf("libmicrohttpd version: %s\n", MHD_get_version());
    
    MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION |
            MHD_USE_INTERNAL_POLLING_THREAD |
            MHD_USE_DEBUG,
        port,
        null,
        null,
        &ahc_echo,
        cast(void*)PAGE,
        MHD_OPTION_END);
    if (daemon == null)
    {
        return 1;
    }
    
    printf("Listening on 0.0.0.0:%u\n",
        MHD_get_daemon_info(daemon, MHD_DAEMON_INFO_BIND_PORT).port);
    
    // getc(stdin) was used here but standard streams are misdefined on Windows
    // platforms when the betterC feature is used, and while gets is deprecated,
    // it is the only function useable to reprecate the getc functionality.
    __gshared char[512] __;
    gets(__.ptr);
    
    puts("Stopping daemon...");
    MHD_stop_daemon(daemon);
    return 0;
}