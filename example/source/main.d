module main;

import bindbc.libmicrohttpd;
import bindbc.loader; // for errors
import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.stdint;
import core.stdc.string;

extern (C):

immutable const(char)* PAGE = "<html><head><title>libmicrohttpd demo</title>"~
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
	MHD_Response *response;
	int ret;

	if (strcmp(method, "GET"))
		return MHD_NO; /* unexpected method */
	
	if (&dummy != *ptr)
	{
		/* The first time only the headers are valid,
			do not respond in the first round... */
		*ptr = &dummy;
		return MHD_YES;
	}
	
	if (0 != *upload_data_size)
		return MHD_NO; /* upload data in a GET!? */
	
	*ptr = null; /* clear context pointer */
	response = MHD_create_response_from_buffer(
		strlen(page),
		cast(void*)page,
		MHD_RESPMEM_PERSISTENT);
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
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
			assert(0, "Library not found on system.");
		case badLibrary:
			foreach (const(ErrorInfo) err; errors)
			{
				printf("error: missing symbol %s\n", err.message);
			}
			assert(0, "Could not load some symbols.");
		default:
	}
	
	ushort port = 8088; // Default
	
	if (argc >= 2)
	{
		port = cast(ushort)atoi(argv[1]);
	}
    
    import core.stdc.stdio;
    printf("LibMicroHTTPD Version: %s\n", MHD_get_version());
	
	MHD_Daemon *d = MHD_start_daemon(
		MHD_USE_THREAD_PER_CONNECTION,
		port,
		null,
		null,
		&ahc_echo,
		cast(void*)PAGE,
		MHD_OPTION_END);
	if (d == null)
		return 1;
	
	printf("Listening on port %u\n", port);
	
	getc(stdin);
	MHD_stop_daemon(d);
	return 0;
}