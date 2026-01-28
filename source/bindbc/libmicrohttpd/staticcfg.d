module bindbc.libmicrohttpd.staticcfg;

public import bindbc.libmicrohttpd.header;
public import bindbc.libmicrohttpd.config;

extern (C):

/**
 * Returns the string reason phrase for a response code.
 *
 * If message string is not available for a status code,
 * "Unknown" string will be returned.
 */
const(char) *MHD_get_reason_phrase_for(uint code);

/**
 * Returns the length of the string reason phrase for a response code.
 *
 * If message string is not available for a status code,
 * 0 is returned.
 */
size_t MHD_get_reason_phrase_len_for(uint code);

/// **************** Daemon handling functions *****************

/**
 * Start a webserver on the given port.
 *
 * Params:
 *  flags = combination of `enum MHD_FLAG` values
 *  port = port to bind to (in host byte order),
 *        use '0' to bind to random free port,
 *        ignored if MHD_OPTION_SOCK_ADDR or
 *        MHD_OPTION_LISTEN_SOCKET is provided
 *        or MHD_USE_NO_LISTEN_SOCKET is specified
 *  apc = callback to call to check which clients
 *        will be allowed to connect; you can pass NULL
 *        in which case connections from any IP will be
 *        accepted
 *  apc_cls = extra argument to apc
 *  dh = handler called for all requests (repeatedly)
 *  dh_cls = extra argument to @a dh
 *  ap = list of options (type-value pairs,
 *        terminated with `MHD_OPTION_END`).
 * Returns: NULL on error, handle to daemon on success
 * Ingroup: event
 */
MHD_Daemon* MHD_start_daemon_va(uint flags,
                     uint16_t port,
                     MHD_AcceptPolicyCallback apc, void *apc_cls,
                     MHD_AccessHandlerCallback dh, void *dh_cls,
                     va_list ap);


/**
 * Start a webserver on the given port.  Variadic version of
 * `MHD_start_daemon_va`.
 *
 * Param: flags = combination of `enum MHD_FLAG` values
 * Param: port = port to bind to (in host byte order),
 *        use '0' to bind to random free port,
 *        ignored if MHD_OPTION_SOCK_ADDR or
 *        MHD_OPTION_LISTEN_SOCKET is provided
 *        or MHD_USE_NO_LISTEN_SOCKET is specified
 * Param: apc = callback to call to check which clients
 *        will be allowed to connect; you can pass NULL
 *        in which case connections from any IP will be
 *        accepted
 * Param: apc_cls = extra argument to apc
 * Param: dh = handler called for all requests (repeatedly)
 * Param: dh_cls = extra argument to @a dh
 * Returns: NULL on error, handle to daemon on success
 * Ingroup: event
 */
MHD_Daemon* MHD_start_daemon(uint flags,
                  uint16_t port,
                  MHD_AcceptPolicyCallback apc, void *apc_cls,
                  MHD_AccessHandlerCallback dh, void *dh_cls,
                  ...);


/**
 * Stop accepting connections from the listening socket.  Allows
 * clients to continue processing, but stops accepting new
 * connections.  Note that the caller is responsible for closing the
 * returned socket; however, if MHD is run using threads (anything but
 * "external" sockets polling mode), it must not be closed until AFTER
 * `MHD_stop_daemon` has been called (as it is theoretically possible
 * that an existing thread is still using it).
 *
 * Note that some thread modes require the caller to have passed
 * `MHD_USE_ITC` when using this API.  If this daemon is
 * in one of those modes and this option was not given to
 * `MHD_start_daemon`, this function will return `MHD_INVALID_SOCKET`.
 *
 * Params: daemon = daemon to stop accepting new connections for
 * Returns: old listen socket on success, `MHD_INVALID_SOCKET` if
 *         the daemon was already not listening anymore
 * Ingroup: specialized
 */
MHD_socket MHD_quiesce_daemon(MHD_Daemon *daemon);


/**
 * Shutdown an HTTP daemon.
 *
 * Params: daemon = daemon to stop
 * Ingroup: event
 */
void MHD_stop_daemon(MHD_Daemon *daemon);


/**
 * Add another client connection to the set of connections managed by
 * MHD.  This API is usually not needed (since MHD will accept inbound
 * connections on the server socket).  Use this API in special cases,
 * for example if your HTTP server is behind NAT and needs to connect
 * out to the HTTP client, or if you are building a proxy.
 *
 * If you use this API in conjunction with an "internal" socket polling,
 * you must set the option `MHD_USE_ITC` to ensure that the freshly added
 * connection is immediately processed by MHD.
 *
 * The given client socket will be managed (and closed!) by MHD after
 * this call and must no longer be used directly by the application
 * afterwards.
 *
 * Params:
 *  daemon = daemon that manages the connection
 *  client_socket = socket to manage (MHD will expect
 *        to receive an HTTP request from this socket next).
 *  addr = IP address of the client
 *  addrlen = number of bytes in @a addr
 * Returns: `MHD_YES` on success, `MHD_NO` if this daemon could
 *        not handle the connection (i.e. `malloc()` failed, etc).
 *        The socket will be closed in any case; `errno` is
 *        set to indicate further details about the error.
 * Ingroup: specialized
 */
MHD_Result MHD_add_connection(MHD_Daemon *daemon, MHD_socket client_socket,
    const(sockaddr) *addr, socklen_t addrlen);


/**
 * Obtain the `select()` sets for this daemon.
 * Daemon's FDs will be added to fd_sets. To get only
 * daemon FDs in fd_sets, call FD_ZERO for each fd_set
 * before calling this function. FD_SETSIZE is assumed
 * to be platform's default.
 *
 * This function should be called only when MHD is configured to
 * use "external" sockets polling with 'select()' or with 'epoll'.
 * In the latter case, it will only add the single 'epoll' file
 * descriptor used by MHD to the sets.
 * It's necessary to use `MHD_get_timeout()` to get maximum timeout
 * value for `select()`. Usage of `select()` with indefinite timeout
 * (or timeout larger than returned by `MHD_get_timeout()`) will
 * violate MHD API and may results in pending unprocessed data.
 *
 * This function must be called only for daemon started
 * without `MHD_USE_INTERNAL_POLLING_THREAD` flag.
 *
 * Params:
 *  daemon = daemon to get sets from
 *  read_fd_set = read set
 *  write_fd_set = write set
 *  except_fd_set = except set
 *  max_fd = increased to largest FD added (if larger
 *               than existing value); can be NULL
 * Returns: `MHD_YES` on success, `MHD_NO` if this
 *         daemon was not started with the right
 *         options for this call or any FD didn't
 *         fit fd_set.
 * Ingroup: event
 */
MHD_Result MHD_get_fdset(MHD_Daemon *daemon, fd_set *read_fd_set,
    fd_set *write_fd_set, fd_set *except_fd_set, MHD_socket *max_fd);


/**
 * Obtain the `select()` sets for this daemon.
 * Daemon's FDs will be added to fd_sets. To get only
 * daemon FDs in fd_sets, call FD_ZERO for each fd_set
 * before calling this function.
 *
 * Passing custom FD_SETSIZE as @a fd_setsize allow usage of
 * larger/smaller than platform's default fd_sets.
 *
 * This function should be called only when MHD is configured to
 * use "external" sockets polling with 'select()' or with 'epoll'.
 * In the latter case, it will only add the single 'epoll' file
 * descriptor used by MHD to the sets.
 * It's necessary to use `MHD_get_timeout()` to get maximum timeout
 * value for `select()`. Usage of `select()` with indefinite timeout
 * (or timeout larger than returned by `MHD_get_timeout()`) will
 * violate MHD API and may results in pending unprocessed data.
 *
 * This function must be called only for daemon started
 * without `MHD_USE_INTERNAL_POLLING_THREAD` flag.
 *
 * Params:
 *  daemon = daemon to get sets from
 *  read_fd_set = read set
 *  write_fd_set = write set
 *  except_fd_set = except set
 *  max_fd = increased to largest FD added (if larger
 *               than existing value); can be NULL
 *  fd_setsize = value of FD_SETSIZE
 * Returns: `MHD_YES` on success, `MHD_NO` if this
 *         daemon was not started with the right
 *         options for this call or any FD didn't
 *         fit fd_set.
 * Ingroup: event
 */
MHD_Result MHD_get_fdset2(MHD_Daemon *daemon, fd_set *read_fd_set,
    fd_set *write_fd_set, fd_set *except_fd_set, MHD_socket *max_fd,
    uint fd_setsize);


/* *
 * Obtain the `select()` sets for this daemon.
 * Daemon's FDs will be added to fd_sets. To get only
 * daemon FDs in fd_sets, call FD_ZERO for each fd_set
 * before calling this function. Size of fd_set is
 * determined by current value of FD_SETSIZE.
 *
 * This function should be called only when MHD is configured to
 * use "external" sockets polling with 'select()' or with 'epoll'.
 * In the latter case, it will only add the single 'epoll' file
 * descriptor used by MHD to the sets.
 * It's necessary to use `MHD_get_timeout()` to get maximum timeout
 * value for `select()`. Usage of `select()` with indefinite timeout
 * (or timeout larger than returned by `MHD_get_timeout()`) will
 * violate MHD API and may results in pending unprocessed data.
 *
 * This function must be called only for daemon started
 * without `MHD_USE_INTERNAL_POLLING_THREAD` flag.
 *
 * Params:
 *  daemon = daemon to get sets from
 *  read_fd_set = read set
 *  write_fd_set = write set
 *  except_fd_set = except set
 *  max_fd = increased to largest FD added (if larger
 *               than existing value); can be NULL
 * Returns: `MHD_YES` on success, `MHD_NO` if this
 *         daemon was not started with the right
 *         options for this call or any FD didn't
 *         fit fd_set.
 * Ingroup: event
 */
/*#define MHD_get_fdset(daemon,read_fd_set,write_fd_set,except_fd_set,max_fd) \
  MHD_get_fdset2 ((daemon),(read_fd_set),(write_fd_set),(except_fd_set), \
                  (max_fd),FD_SETSIZE)*/


/**
 * Obtain timeout value for polling function for this daemon.
 *
 * This function set value to the amount of milliseconds for which polling
 * function (`select()`, `poll()` or epoll) should at most block, not the
 * timeout value set for connections.
 *
 * Any "external" sockets polling function must be called with the timeout
 * value provided by this function. Smaller timeout values can be used for
 * polling function if it is required for any reason, but using larger
 * timeout value or no timeout (indefinite timeout) when this function
 * return `MHD_YES` will break MHD processing logic and result in "hung"
 * connections with data pending in network buffers and other problems.
 *
 * It is important to always use this function (or `MHD_get_timeout64()`,
 * `MHD_get_timeout64s()`, `MHD_get_timeout_i()` functions) when "external"
 * polling is used.
 * If this function returns `MHD_YES` then `MHD_run()` (or `MHD_run_from_select()`)
 * must be called right after return from polling function, regardless of
 * the states of MHD FDs.
 *
 * In practice, if `MHD_YES` is returned then `MHD_run()` (or
 * `MHD_run_from_select()`) must be called not later than @a timeout
 * millisecond even if no activity is detected on sockets by sockets
 * polling function.
 *
 * Params:
 *  daemon = daemon to query for timeout
 *  timeout = set to the timeout (in milliseconds)
 * Returns: `MHD_YES` on success, `MHD_NO` if timeouts are
 *         not used and no data processing is pending.
 * Ingroup: event
 */
MHD_Result MHD_get_timeout(MHD_Daemon *daemon, MHD_UNSIGNED_LONG_LONG *timeout);


/**
 * Free the memory allocated by MHD.
 *
 * If any MHD function explicitly mentions that returned pointer must be
 * freed by this function, then no other method must be used to free
 * the memory.
 *
 * Params: ptr = the pointer to free.
 * See_Also: `MHD_digest_auth_get_username()`, `MHD_basic_auth_get_username_password3()`
 * See_Also: `MHD_basic_auth_get_username_password()`
 * Note: Available since `MHD_VERSION` 0x00095600
 * Ingroup: specialized
 */
void MHD_free(void *ptr);

/**
 * Obtain timeout value for external polling function for this daemon.
 *
 * This function set value to the amount of milliseconds for which polling
 * function (`select()`, `poll()` or epoll) should at most block, not the
 * timeout value set for connections.
 *
 * Any "external" sockets polling function must be called with the timeout
 * value provided by this function. Smaller timeout values can be used for
 * polling function if it is required for any reason, but using larger
 * timeout value or no timeout (indefinite timeout) when this function
 * return `MHD_YES` will break MHD processing logic and result in "hung"
 * connections with data pending in network buffers and other problems.
 *
 * It is important to always use this function (or `MHD_get_timeout()`,
 * `MHD_get_timeout64s()`, `MHD_get_timeout_i()` functions) when "external"
 * polling is used.
 * If this function returns `MHD_YES` then `MHD_run()` (or `MHD_run_from_select()`)
 * must be called right after return from polling function, regardless of
 * the states of MHD FDs.
 *
 * In practice, if `MHD_YES` is returned then `MHD_run()` (or
 * `MHD_run_from_select()`) must be called not later than @a timeout
 * millisecond even if no activity is detected on sockets by sockets
 * polling function.
 *
 * Params:
 *  daemon = daemon to query for timeout
 *  timeout = the pointer to the variable to be set to the
 *                  timeout (in milliseconds)
 * Returns: `MHD_YES` if timeout value has been set,
 *         `MHD_NO` if timeouts are not used and no data processing is pending.
 * Note: Available since `MHD_VERSION` 0x00097508
 * Ingroup: event
 */
MHD_Result MHD_get_timeout64(MHD_Daemon *daemon, uint64_t *timeout);


/**
 * Obtain timeout value for external polling function for this daemon.
 *
 * This function set value to the amount of milliseconds for which polling
 * function (`select()`, `poll()` or epoll) should at most block, not the
 * timeout value set for connections.
 *
 * Any "external" sockets polling function must be called with the timeout
 * value provided by this function (if returned value is non-negative).
 * Smaller timeout values can be used for polling function if it is required
 * for any reason, but using larger timeout value or no timeout (indefinite
 * timeout) when this function returns non-negative value will break MHD
 * processing logic and result in "hung" connections with data pending in
 * network buffers and other problems.
 *
 * It is important to always use this function (or `MHD_get_timeout()`,
 * `MHD_get_timeout64()`, `MHD_get_timeout_i()` functions) when "external"
 * polling is used.
 * If this function returns non-negative value then `MHD_run()` (or
 * `MHD_run_from_select()`) must be called right after return from polling
 * function, regardless of the states of MHD FDs.
 *
 * In practice, if zero or positive value is returned then `MHD_run()` (or
 * `MHD_run_from_select()`) must be called not later than returned amount of
 * millisecond even if no activity is detected on sockets by sockets
 * polling function.
 *
 * Params: daemon = the daemon to query for timeout
 * Returns: -1 if connections' timeouts are not set and no data processing
 *         is pending, so external polling function may wait for sockets
 *         activity for indefinite amount of time,
 *         otherwise returned value is the the maximum amount of millisecond
 *         that external polling function must wait for the activity of FDs.
 * Note: Available since `MHD_VERSION` 0x00097509
 * Ingroup: event
 */
int64_t MHD_get_timeout64s(MHD_Daemon *daemon);


/**
 * Obtain timeout value for external polling function for this daemon.
 *
 * This function set value to the amount of milliseconds for which polling
 * function (`select()`, `poll()` or epoll) should at most block, not the
 * timeout value set for connections.
 *
 * Any "external" sockets polling function must be called with the timeout
 * value provided by this function (if returned value is non-negative).
 * Smaller timeout values can be used for polling function if it is required
 * for any reason, but using larger timeout value or no timeout (indefinite
 * timeout) when this function returns non-negative value will break MHD
 * processing logic and result in "hung" connections with data pending in
 * network buffers and other problems.
 *
 * It is important to always use this function (or `MHD_get_timeout()`,
 * `MHD_get_timeout64()`, `MHD_get_timeout64s()` functions) when "external"
 * polling is used.
 * If this function returns non-negative value then `MHD_run()` (or
 * `MHD_run_from_select()`) must be called right after return from polling
 * function, regardless of the states of MHD FDs.
 *
 * In practice, if zero or positive value is returned then `MHD_run()` (or
 * `MHD_run_from_select()`) must be called not later than returned amount of
 * millisecond even if no activity is detected on sockets by sockets
 * polling function.
 *
 * Params: daemon = the daemon to query for timeout
 * Returns: -1 if connections' timeouts are not set and no data processing
 *         is pending, so external polling function may wait for sockets
 *         activity for indefinite amount of time,
 *         otherwise returned value is the the maximum amount of millisecond
 *         (capped at INT_MAX) that external polling function must wait
 *         for the activity of FDs.
 * Note: Available since `MHD_VERSION` 0x00097510
 * Ingroup: event
 */
int MHD_get_timeout_i(MHD_Daemon *daemon);


/**
 * Run webserver operations (without blocking unless in client callbacks).
 *
 * This method should be called by clients in combination with
 * `MHD_get_fdset()` (or `MHD_get_daemon_info()` with MHD_DAEMON_INFO_EPOLL_FD
 * if epoll is used) and `MHD_get_timeout()` if the client-controlled
 * connection polling method is used (i.e. daemon was started without
 * `MHD_USE_INTERNAL_POLLING_THREAD` flag).
 *
 * This function is a convenience method, which is useful if the
 * fd_sets from `MHD_get_fdset` were not directly passed to `select()`;
 * with this function, MHD will internally do the appropriate `select()`
 * call itself again.  While it is acceptable to call `MHD_run` (if
 * `MHD_USE_INTERNAL_POLLING_THREAD` is not set) at any moment, you should
 * call `MHD_run_from_select()` if performance is important (as it saves an
 * expensive call to `select()`).
 *
 * If `MHD_get_timeout()` returned `MHD_YES`, than this function must be called
 * right after polling function returns regardless of detected activity on
 * the daemon's FDs.
 *
 * @param daemon daemon to run
 * Returns: `MHD_YES` on success, `MHD_NO` if this
 *         daemon was not started with the right
 *         options for this call.
 * Ingroup: event
 */
MHD_Result MHD_run(MHD_Daemon *daemon);


/**
 * Run webserver operations. This method should be called by clients
 * in combination with `MHD_get_fdset` and `MHD_get_timeout()` if the
 * client-controlled select method is used.
 *
 * You can use this function instead of `MHD_run` if you called
 * `select()` on the result from `MHD_get_fdset`.  File descriptors in
 * the sets that are not controlled by MHD will be ignored.  Calling
 * this function instead of `MHD_run` is more efficient as MHD will
 * not have to call `select()` again to determine which operations are
 * ready.
 *
 * If `MHD_get_timeout()` returned `MHD_YES`, than this function must be
 * called right after `select()` returns regardless of detected activity
 * on the daemon's FDs.
 *
 * This function cannot be used with daemon started with
 * `MHD_USE_INTERNAL_POLLING_THREAD` flag.
 *
 * Params:
 *  daemon = daemon to run select loop for
 *  read_fd_set = read set
 *  write_fd_set = write set
 *  except_fd_set = except set
 * Returns: `MHD_NO` on serious errors, `MHD_YES` on success
 * Ingroup: event
 */
MHD_Result MHD_run_from_select(MHD_Daemon *daemon,
                     const(fd_set) *read_fd_set,
                     const(fd_set) *write_fd_set,
                     const(fd_set) *except_fd_set);


/// **************** Connection handling functions *****************

/**
 * Get all of the headers from the request.
 *
 * Params:
 *  connection = connection to get values from
 *  kind = types of values to iterate over, can be a bitmask
 *  iterator = callback to call on each header;
 *        may be NULL (then just count headers)
 *  iterator_cls = extra argument to @a iterator
 * Returns: number of entries iterated over,
 *         -1 if connection is NULL.
 * Ingroup: request
 */
int MHD_get_connection_values(MHD_Connection *connection,
                           MHD_ValueKind kind,
                           MHD_KeyValueIterator iterator,
                           void *iterator_cls);



/**
 * This function can be used to add an entry to the HTTP headers of a
 * connection (so that the `MHD_get_connection_values` function will
 * return them -- and the `struct MHD_PostProcessor` will also see
 * them).  This maybe required in certain situations (see Mantis
 * #1399) where (broken) HTTP implementations fail to supply values
 * needed by the post processor (or other parts of the application).
 *
 * This function MUST only be called from within the
 * `MHD_AccessHandlerCallback` (otherwise, access maybe improperly
 * synchronized).  Furthermore, the client must guarantee that the key
 * and value arguments are 0-terminated strings that are NOT freed
 * until the connection is closed.  (The easiest way to do this is by
 * passing only arguments to permanently allocated strings.).
 *
 * Params:
 *  connection = the connection for which a value should be set
 *  kind = kind of the value
 *  key = key for the value
 *  value = the value itself
 * Returns: `MHD_NO` if the operation could not be
 *         performed due to insufficient memory;
 *         `MHD_YES` on success
 * Ingroup: request
 */
MHD_Result MHD_set_connection_value(MHD_Connection *connection,
                          MHD_ValueKind kind,
                          const(char) *key,
                          const(char) *value);



/**
 * Sets the global error handler to a different implementation.
 *
 * @a cb will only be called in the case of typically fatal, serious internal
 * consistency issues or serious system failures like failed lock of mutex.
 *
 * These issues should only arise in the case of serious memory corruption or
 * similar problems with the architecture, there is no safe way to continue
 * even for closing of the application.
 *
 * The default implementation that is used if no panic function is set simply
 * prints an error message and calls `abort()`.
 * Alternative implementations might call `exit()` or other similar functions.
 *
 * Params:
 *  cb = new error handler or NULL to use default handler
 *  cls = passed to @a cb
 * Ingroup: logging
 */
void MHD_set_panic_func(MHD_PanicCallback cb, void *cls);


/**
 * Process escape sequences ('%HH') Updates val in place; the
 * result cannot be larger than the input.
 * The result is still be 0-terminated.
 *
 * Params: val = value to unescape (modified in the process)
 * Returns: length of the resulting val (`strlen(val)` may be
 *  shorter afterwards due to elimination of escape sequences)
 */
size_t MHD_http_unescape(char *val);


/**
 * Get a particular header value.  If multiple
 * values match the kind, return any one of them.
 *
 * Params:
 *  connection = connection to get values from
 *  kind = what kind of value are we looking for
 *  key = the header to look for, NULL to lookup 'trailing' value without a key
 * Returns: NULL if no such item was found
 * Ingroup: request
 */
const(char) *MHD_lookup_connection_value(MHD_Connection *connection,
                             MHD_ValueKind kind,
                             const(char) *key);



/**
 * Queue a response to be transmitted to the client (as soon as
 * possible but after `MHD_AccessHandlerCallback` returns).
 *
 * For any active connection this function must be called
 * only by `MHD_AccessHandlerCallback` callback.
 * For suspended connection this function can be called at any moment. Response
 * will be sent as soon as connection is resumed.
 *
 * If HTTP specifications require use no body in reply, like @a status_code with
 * value 1xx, the response body is automatically not sent even if it is present
 * in the response. No "Content-Length" or "Transfer-Encoding" headers are
 * generated and added.
 *
 * When the response is used to respond HEAD request or used with @a status_code
 * `MHD_HTTP_NOT_MODIFIED`, then response body is not sent, but "Content-Length"
 * header is added automatically based the size of the body in the response.
 * If body size it set to `MHD_SIZE_UNKNOWN` or chunked encoding is enforced
 * then "Transfer-Encoding: chunked" header (for HTTP/1.1 only) is added instead
 * of "Content-Length" header. For example, if response with zero-size body is
 * used for HEAD request, then "Content-Length: 0" is added automatically to
 * reply headers.
 * See_Also: `MHD_RF_HEAD_ONLY_RESPONSE`
 *
 * In situations, where reply body is required, like answer for the GET request
 * with @a status_code `MHD_HTTP_OK`, headers "Content-Length" (for known body
 * size) or "Transfer-Encoding: chunked" (for `MHD_SIZE_UNKNOWN` with HTTP/1.1)
 * are added automatically.
 * In practice, the same response object can be used to respond to both HEAD and
 * GET requests.
 *
 * Params:
 *  connection = the connection identifying the client
 *  status_code = HTTP status code (i.e. `MHD_HTTP_OK`)
 *  response = response to transmit, the NULL is tolerated
 * Returns: `MHD_NO` on error (reply already sent, response is NULL),
 *         `MHD_YES` on success or if message has been queued
 * Ingroup: response
 * See_Also: `MHD_AccessHandlerCallback`
 */
MHD_Result MHD_queue_response(MHD_Connection *connection,
                    uint status_code,
                    MHD_Response *response);


/**
 * Suspend handling of network data for a given connection.
 * This can be used to dequeue a connection from MHD's event loop
 * (not applicable to thread-per-connection!) for a while.
 *
 * If you use this API in conjunction with an "internal" socket polling,
 * you must set the option `MHD_USE_ITC` to ensure that a resumed
 * connection is immediately processed by MHD.
 *
 * Suspended connections continue to count against the total number of
 * connections allowed (per daemon, as well as per IP, if such limits
 * are set).  Suspended connections will NOT time out; timeouts will
 * restart when the connection handling is resumed.  While a
 * connection is suspended, MHD will not detect disconnects by the
 * client.
 *
 * The only safe way to call this function is to call it from the
 * `MHD_AccessHandlerCallback` or `MHD_ContentReaderCallback`.
 *
 * Finally, it is an API violation to call `MHD_stop_daemon` while
 * having suspended connections (this will at least create memory and
 * socket leaks or lead to undefined behavior).  You must explicitly
 * resume all connections before stopping the daemon.
 *
 * Params: connection = the connection to suspend
 *
 * See_Also: `MHD_AccessHandlerCallback`
 */
void MHD_suspend_connection(MHD_Connection *connection);


/**
 * Resume handling of network data for suspended connection.  It is
 * safe to resume a suspended connection at any time.  Calling this
 * function on a connection that was not previously suspended will
 * result in undefined behavior.
 *
 * If you are using this function in "external" sockets polling mode, you must
 * make sure to run `MHD_run()` and `MHD_get_timeout()` afterwards (before
 * again calling `MHD_get_fdset()`), as otherwise the change may not be
 * reflected in the set returned by `MHD_get_fdset()` and you may end up
 * with a connection that is stuck until the next network activity.
 *
 * Params: connection = the connection to resume
 */
void MHD_resume_connection(MHD_Connection *connection);

/**
 * Set special flags and options for a response.
 *
 * Params:
 *  response = the response to modify
 *  flags = to set for the response
 *  ... = `MHD_RO_END` terminates the list of options
 * Returns: `MHD_YES` on success, `MHD_NO` on error
 */
MHD_Result MHD_set_response_options(MHD_Response *response,
                          MHD_ResponseFlags flags,
                          ...);


/**
 * Create a response object.
 * The response object can be extended with header information and then be used
 * any number of times.
 *
 * If response object is used to answer HEAD request then the body of the
 * response is not used, while all headers (including automatic headers) are
 * used.
 *
 * Params:
 *  size = size of the data portion of the response, `MHD_SIZE_UNKNOWN` for unknown
 *  block_size = preferred block size for querying crc (advisory only,
 *                   MHD may still call @a crc using smaller chunks); this
 *                   is essentially the buffer size used for IO, clients
 *                   should pick a value that is appropriate for IO and
 *                   memory performance requirements
 *  crc = callback to use to obtain response data
 *  crc_cls = extra argument to @a crc
 *  crfc = callback to call to free @a crc_cls resources
 * Returns: NULL on error (i.e. invalid arguments, out of memory)
 * Ingroup: response
 */
MHD_Response* MHD_create_response_from_callback(uint64_t size,
                                   size_t block_size,
                                   MHD_ContentReaderCallback crc, void *crc_cls,
                                   MHD_ContentReaderFreeCallback crfc);


/**
 * Create a response object.
 * The response object can be extended with header information and then be used
 * any number of times.
 *
 * If response object is used to answer HEAD request then the body of the
 * response is not used, while all headers (including automatic headers) are
 * used.
 *
 * Params:
 *  size = size of the @a data portion of the response
 *  data = the data itself
 *  must_free = libmicrohttpd should free data when done
 *  must_copy = libmicrohttpd must make a copy of @a data
 *        right away, the data may be released anytime after
 *        this call returns
 * Returns: NULL on error (i.e. invalid arguments, out of memory)
 * Deprecated: use `MHD_create_response_from_buffer` instead
 * Ingroup: response
 */
deprecated("MHD_create_response_from_data() is deprecated, "~
                "use MHD_create_response_from_buffer()")
MHD_Response* MHD_create_response_from_data(size_t size,
                               void *data,
                               int must_free,
                               int must_copy);

/**
 * Create a response object with the content of provided buffer used as
 * the response body.
 *
 * The response object can be extended with header information and then
 * be used any number of times.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * Params:
 *  size = size of the data portion of the response
 *  buffer = size bytes containing the response's data portion
 *  mode = flags for buffer management
 * Returns: NULL on error (i.e. invalid arguments, out of memory)
 * Ingroup: response
 */
MHD_Response* MHD_create_response_from_buffer(size_t size,
                                 void *buffer,
                                 MHD_ResponseMemoryMode mode);


/**
 * Create a response object with the content of provided statically allocated
 * buffer used as the response body.
 *
 * The buffer must be valid for the lifetime of the response. The easiest way
 * to achieve this is to use a statically allocated buffer.
 *
 * The response object can be extended with header information and then
 * be used any number of times.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * Params:
 *  size = the size of the data in @a buffer, can be zero
 *  buffer = the buffer with the data for the response body, can be NULL
 *               if @a size is zero
 * Returns: NULL on error (i.e. invalid arguments, out of memory)
 * Note: Available since `MHD_VERSION` 0x00097506
 * Ingroup: response
 */
MHD_Response* MHD_create_response_from_buffer_static(size_t size,
                                        const(void) *buffer);


/**
 * Create a response object with the content of provided temporal buffer
 * used as the response body.
 *
 * An internal copy of the buffer will be made automatically, so buffer have
 * to be valid only during the call of this function (as a typical example:
 * buffer is a local (non-static) array).
 *
 * The response object can be extended with header information and then
 * be used any number of times.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * Params:
 *  size = the size of the data in @a buffer, can be zero
 *  buffer = the buffer with the data for the response body, can be NULL
 *               if @a size is zero
 * Returns: NULL on error (i.e. invalid arguments, out of memory)
 * Note: Available since `MHD_VERSION` 0x00097507
 * Ingroup: response
 */
MHD_Response* MHD_create_response_from_buffer_copy(size_t size,
                                      const(void) *buffer);




/**
 * Create a response object with the content of provided file used as
 * the response body.
 *
 * The response object can be extended with header information and then
 * be used any number of times.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * Params:
 *  size = size of the data portion of the response
 *  fd = file descriptor referring to a file on disk with the
 *        data; will be closed when response is destroyed;
 *        fd should be in 'blocking' mode
 * Returns: NULL on error (i.e. invalid arguments, out of memory)
 * Ingroup: response
 */
MHD_Response* MHD_create_response_from_fd(size_t size, int fd);


/**
 * Create a response object with the content of provided file used as
 * the response body.
 *
 * The response object can be extended with header information and then
 * be used any number of times.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * Params:
 *  size = size of the data portion of the response;
 *        sizes larger than 2 GiB may be not supported by OS or
 *        MHD build; see ::MHD_FEATURE_LARGE_FILE
 *  fd = file descriptor referring to a file on disk with the
 *        data; will be closed when response is destroyed;
 *        fd should be in 'blocking' mode
 * Returns: NULL on error (i.e. invalid arguments, out of memory)
 * Ingroup: response
 */
MHD_Response* MHD_create_response_from_fd64(uint64_t size, int fd);


/**
 * Create a response object with the content of provided file with
 * specified offset used as the response body.
 *
 * The response object can be extended with header information and then
 * be used any number of times.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * Params:
 *  size = size of the data portion of the response
 *  fd = file descriptor referring to a file on disk with the
 *        data; will be closed when response is destroyed;
 *        fd should be in 'blocking' mode
 *  offset = offset to start reading from in the file;
 *        Be careful! `off_t` may have been compiled to be a
 *        64-bit variable for MHD, in which case your application
 *        also has to be compiled using the same options! Read
 *        the MHD manual for more details.
 * Returns: NULL on error (i.e. invalid arguments, out of memory)
 * Ingroup: response
 */
deprecated("Function MHD_create_response_from_fd_at_offset() is " ~
                "deprecated, use MHD_create_response_from_fd_at_offset64()")
MHD_Response* MHD_create_response_from_fd_at_offset(size_t size,
                                       int fd,
                                       off_t offset);


/**
 * Create a response object with the content of provided file with
 * specified offset used as the response body.
 *
 * The response object can be extended with header information and then
 * be used any number of times.
 *
 * If response object is used to answer HEAD request then the body
 * of the response is not used, while all headers (including automatic
 * headers) are used.
 *
 * Params:
 *  size = size of the data portion of the response;
 *        sizes larger than 2 GiB may be not supported by OS or
 *        MHD build; see ::MHD_FEATURE_LARGE_FILE
 *  fd = file descriptor referring to a file on disk with the
 *        data; will be closed when response is destroyed;
 *        fd should be in 'blocking' mode
 *  offset = offset to start reading from in the file;
 *        reading file beyond 2 GiB may be not supported by OS or
 *        MHD build; see ::MHD_FEATURE_LARGE_FILE
 * Returns: NULL on error (i.e. invalid arguments, out of memory)
 * Ingroup: response
 */
MHD_Response* MHD_create_response_from_fd_at_offset64(uint64_t size,
                                         int fd,
                                         uint64_t offset);


/**
 * Create a response object with empty (zero size) body.
 *
 * The response object can be extended with header information and then be used
 * any number of times.
 *
 * This function is a faster equivalent of `MHD_create_response_from_buffer` call
 * with zero size combined with call of `MHD_set_response_options`.
 *
 * Params: flags = the flags for the new response object
 * Returns: NULL on error (i.e. invalid arguments, out of memory),
 *         the pointer to the created response object otherwise
 * Note: Available since `MHD_VERSION` 0x00097503
 * Ingroup: response
 */
MHD_Response* MHD_create_response_empty(MHD_ResponseFlags flags);


/**
 * This connection-specific callback is provided by MHD to
 * applications (unusual) during the `MHD_UpgradeHandler`.
 * It allows applications to perform 'special' actions on
 * the underlying socket from the upgrade.
 *
 * Params:
 *  urh = the handle identifying the connection to perform
 *            the upgrade @a action on.
 *  action = which action should be performed
 *  ... = arguments to the action (depends on the action).
 * Returns: `MHD_NO` on error, `MHD_YES` on success
 */
MHD_Result MHD_upgrade_action(MHD_UpgradeResponseHandle *urh,
                    MHD_UpgradeAction action,
                    ...);

/**
 * Create a response object that can be used for 101 UPGRADE
 * responses, for example to implement WebSockets.  After sending the
 * response, control over the data stream is given to the callback (which
 * can then, for example, start some bi-directional communication).
 * If the response is queued for multiple connections, the callback
 * will be called for each connection.  The callback
 * will ONLY be called after the response header was successfully passed
 * to the OS; if there are communication errors before, the usual MHD
 * connection error handling code will be performed.
 *
 * Setting the correct HTTP code (i.e. MHD_HTTP_SWITCHING_PROTOCOLS)
 * and setting correct HTTP headers for the upgrade must be done
 * manually (this way, it is possible to implement most existing
 * WebSocket versions using this API; in fact, this API might be useful
 * for any protocol switch, not just WebSockets).  Note that
 * draft-ietf-hybi-thewebsocketprotocol-00 cannot be implemented this
 * way as the header "HTTP/1.1 101 WebSocket Protocol Handshake"
 * cannot be generated; instead, MHD will always produce "HTTP/1.1 101
 * Switching Protocols" (if the response code 101 is used).
 *
 * As usual, the response object can be extended with header
 * information and then be used any number of times (as long as the
 * header information is not connection-specific).
 *
 * Params:
 *  upgrade_handler = function to call with the "upgraded" socket
 *  upgrade_handler_cls = closure for @a upgrade_handler
 * Returns: NULL on error (i.e. invalid arguments, out of memory)
 */
MHD_Response* MHD_create_response_for_upgrade(MHD_UpgradeHandler upgrade_handler,
                                 void *upgrade_handler_cls);


/**
 * Destroy a response object and associated resources.  Note that
 * libmicrohttpd may keep some of the resources around if the response
 * is still in the queue for some clients, so the memory may not
 * necessarily be freed immediately.
 *
 * Params: response = response to destroy
 * Ingroup: response
 */
void MHD_destroy_response(MHD_Response *response);


/**
 * Add a header line to the response.
 *
 * When reply is generated with queued response, some headers are generated
 * automatically. Automatically generated headers are only sent to the client,
 * but not added back to the response object.
 *
 * The list of automatic headers:
 * + "Date" header is added automatically unless already set by
 *   this function
 *   See_Also: `MHD_USE_SUPPRESS_DATE_NO_CLOCK`
 * + "Content-Length" is added automatically when required, attempt to set
 *   it manually by this function is ignored.
 *   See_Also: `MHD_RF_INSANITY_HEADER_CONTENT_LENGTH`
 * + "Transfer-Encoding" with value "chunked" is added automatically,
 *   when chunked transfer encoding is used automatically. Same header with
 *   the same value can be set manually by this function to enforce chunked
 *   encoding, however for HTTP/1.0 clients chunked encoding will not be used
 *   and manually set "Transfer-Encoding" header is automatically removed
 *   for HTTP/1.0 clients
 * + "Connection" may be added automatically with value "Keep-Alive" (only
 *   for HTTP/1.0 clients) or "Close". The header "Connection" with value
 *   "Close" could be set by this function to enforce closure of
 *   the connection after sending this response. "Keep-Alive" cannot be
 *   enforced and will be removed automatically.
 *   See_Also: `MHD_RF_SEND_KEEP_ALIVE_HEADER`
 *
 * Some headers are pre-processed by this function:
 * * "Connection" headers are combined into single header entry, value is
 *   normilised, "Keep-Alive" tokens are removed.
 * * "Transfer-Encoding" header: the only one header is allowed, the only
 *   allowed value is "chunked".
 * * "Date" header: the only one header is allowed, the second added header
 *   replaces the first one.
 * * "Content-Length" application-defined header is not allowed.
 *   See_Also: `MHD_RF_INSANITY_HEADER_CONTENT_LENGTH`
 *
 * Headers are used in order as they were added.
 *
 * Params:
 *  response = the response to add a header to
 *  header = the header name to add, no need to be static, an internal copy
 *               will be created automatically
 *  content = the header value to add, no need to be static, an internal
 *                copy will be created automatically
 * Returns: `MHD_YES` on success,
 *         `MHD_NO` on error (i.e. invalid header or content format),
 *         or out of memory
 * Ingroup: response
 */
MHD_Result MHD_add_response_header(MHD_Response *response,
                         const(char) *header,
                         const(char) *content);


/**
 * Add a footer line to the response.
 *
 * Params:
 *  response = response to remove a header from
 *  footer = the footer to delete
 *  content = value to delete
 * Returns: `MHD_NO` on error (i.e. invalid footer or content format).
 * Ingroup: response
 */
MHD_Result MHD_add_response_footer(MHD_Response *response,
                         const(char) *footer,
                         const(char) *content);


/**
 * Delete a header (or footer) line from the response.
 *
 * For "Connection" headers this function remove all tokens from existing
 * value. Successful result means that at least one token has been removed.
 * If all tokens are removed from "Connection" header, the empty "Connection"
 * header removed.
 *
 * Params:
 *  response = response to remove a header from
 *  header = the header to delete
 *  content = value to delete
 * Returns: `MHD_NO` on error (no such header known)
 * Ingroup: response
 */
MHD_Result MHD_del_response_header(MHD_Response *response,
                         const(char) *header,
                         const(char) *content);


/**
 * Get all of the headers (and footers) added to a response.
 *
 * Params:
 *  response = response to query
 *  iterator = callback to call on each header;
 *        may be NULL (then just count headers)
 *  iterator_cls = extra argument to @a iterator
 * Returns: number of entries iterated over
 * Ingroup: response
 */
int MHD_get_response_headers(MHD_Response *response,
                          MHD_KeyValueIterator iterator,
                          void *iterator_cls);


/**
 * Get a particular header (or footer) from the response.
 *
 * Params:
 *  response = response to query
 *  key = which header to get
 * Returns: NULL if header does not exist
 * Ingroup: response
 */
const(char)* MHD_get_response_header(MHD_Response *response,
                         const(char) *key);


/**
 * Create a `struct MHD_PostProcessor`.
 *
 * A `struct MHD_PostProcessor` can be used to (incrementally) parse
 * the data portion of a POST request.  Note that some buggy browsers
 * fail to set the encoding type.  If you want to support those, you
 * may have to call `MHD_set_connection_value` with the proper encoding
 * type before creating a post processor (if no supported encoding
 * type is set, this function will fail).
 *
 * Params:
 *  connection = the connection on which the POST is
 *        happening (used to determine the POST format)
 *  buffer_size = maximum number of bytes to use for
 *        internal buffering (used only for the parsing,
 *        specifically the parsing of the keys).  A
 *        tiny value (256-1024) should be sufficient.
 *        Do NOT use a value smaller than 256.  For good
 *        performance, use 32 or 64k (i.e. 65536).
 *  iter = iterator to be called with the parsed data,
 *        Must NOT be NULL.
 *  iter_cls = first argument to @a iter
 * Returns: NULL on error (out of memory, unsupported encoding),
 *         otherwise a PP handle
 * Ingroup: request
 */
MHD_PostProcessor* MHD_create_post_processor(MHD_Connection *connection,
                           size_t buffer_size,
                           MHD_PostDataIterator iter, void *iter_cls);


/**
 * Parse and process POST data.  Call this function when POST data is
 * available (usually during an `MHD_AccessHandlerCallback`) with the
 * "upload_data" and "upload_data_size".  Whenever possible, this will
 * then cause calls to the `MHD_PostDataIterator`.
 *
 * Params:
 *  pp = the post processor
 *  post_data = @a post_data_len bytes of POST data
 *  post_data_len = length of @a post_data
 * Returns: `MHD_YES` on success, `MHD_NO` on error
 *         (out-of-memory, iterator aborted, parse error)
 * Ingroup: request
 */
MHD_Result MHD_post_process(MHD_PostProcessor *pp,
                  const(char) *post_data,
                  size_t post_data_len);


/**
 * Release PostProcessor resources.
 *
 * Params: pp = the PostProcessor to destroy
 * Returns: `MHD_YES` if processing completed nicely,
 *         `MHD_NO` if there were spurious characters / formatting
 *                problems; it is common to ignore the return
 *                value of this function
 * Ingroup: request
 */
MHD_Result MHD_destroy_post_processor(MHD_PostProcessor *pp);

/**
 * Get digest size for specified algorithm.
 *
 * The size of the digest specifies the size of the userhash, userdigest
 * and other parameters which size depends on used hash algorithm.
 * Params: algo3 = the algorithm to check
 * Returns: the size of the digest (either `MHD_MD5_DIGEST_SIZE` or
 *         `MHD_SHA256_DIGEST_SIZE`/MHD_SHA512_256_DIGEST_SIZE)
 *         or zero if the input value is not supported or not valid
 * See_Also: `MHD_digest_auth_calc_userdigest()`
 * See_Also: `MHD_digest_auth_calc_userhash()`, `MHD_digest_auth_calc_userhash_hex()`
 * Note: Available since `MHD_VERSION` 0x00097526
 * Ingroup: authentication
 */
size_t MHD_digest_get_hash_size(MHD_DigestAuthAlgo3 algo3);

/**
 * Calculate "userhash", return it as binary data.
 *
 * The "userhash" is the hash of the string "username:realm".
 *
 * The "Userhash" could be used to avoid sending username in cleartext in Digest
 * Authorization client's header.
 *
 * Userhash is not designed to hide the username in local database or files,
 * as username in cleartext is required for `MHD_digest_auth_check3()` function
 * to check the response, but it can be used to hide username in HTTP headers.
 *
 * This function could be used when the new username is added to the username
 * database to save the "userhash" alongside with the username (preferably) or
 * when loading list of the usernames to generate the userhash for every loaded
 * username (this will cause delays at the start with the long lists).
 *
 * Once "userhash" is generated it could be used to identify users for clients
 * with "userhash" support.
 * Avoid repetitive usage of this function for the same username/realm
 * combination as it will cause excessive CPU load; save and re-use the result
 * instead.
 *
 * Params:
 *  algo3 = the algorithm for userhash calculations
 *  username = the username
 *  realm = the realm
 *  userhash_bin = the output buffer for userhash as binary data;
 *                          if this function succeeds, then this buffer has
 *                          `MHD_digest_get_hash_size`(algo3) bytes of userhash
 *                          upon return
 *  bin_buf_size = the size of the @a userhash_bin buffer, must be
 *                     at least `MHD_digest_get_hash_size`(algo3) bytes long
 * Returns: MHD_YES on success,
 *         MHD_NO if @a bin_buf_size is too small or if @a algo3 algorithm is
 *         not supported (or external error has occurred,
 *         see `MHD_FEATURE_EXTERN_HASH`)
 * Note: Available since `MHD_VERSION` 0x00097535
 * Ingroup: authentication
 */
MHD_Result MHD_digest_auth_calc_userhash(MHD_DigestAuthAlgo3 algo3,
                               const(char) *username,
                               const(char) *realm,
                               void *userhash_bin,
                               size_t bin_buf_size);


/**
 * Calculate "userhash", return it as hexadecimal data.
 *
 * The "userhash" is the hash of the string "username:realm".
 *
 * The "Userhash" could be used to avoid sending username in cleartext in Digest
 * Authorization client's header.
 *
 * Userhash is not designed to hide the username in local database or files,
 * as username in cleartext is required for `MHD_digest_auth_check3()` function
 * to check the response, but it can be used to hide username in HTTP headers.
 *
 * This function could be used when the new username is added to the username
 * database to save the "userhash" alongside with the username (preferably) or
 * when loading list of the usernames to generate the userhash for every loaded
 * username (this will cause delays at the start with the long lists).
 *
 * Once "userhash" is generated it could be used to identify users for clients
 * with "userhash" support.
 * Avoid repetitive usage of this function for the same username/realm
 * combination as it will cause excessive CPU load; save and re-use the result
 * instead.
 *
 * Params:
 *  algo3 = the algorithm for userhash calculations
 *  username = the username
 *  realm = the realm
 *  userhash_hex = the output buffer for userhash as hex data;
 *                          if this function succeeds, then this buffer has
 *                          `MHD_digest_get_hash_size`(algo3)*2 chars long
 *                          userhash string
 *  hex_buf_size = the size of the @a userhash_bin buffer, must be
 *                     at least `MHD_digest_get_hash_size`(algo3)*2+1 chars long
 * Returns: MHD_YES on success,
 *         MHD_NO if @a bin_buf_size is too small or if @a algo3 algorithm is
 *         not supported (or external error has occurred,
 *         see `MHD_FEATURE_EXTERN_HASH`).
 * Note: Available since `MHD_VERSION` 0x00097535
 * Ingroup: authentication
 */
MHD_Result MHD_digest_auth_calc_userhash_hex(MHD_DigestAuthAlgo3 algo3,
                                   const(char) *username,
                                   const(char) *realm,
                                   char *userhash_hex,
                                   size_t hex_buf_size);

/**
 * Get information about Digest Authorization client's header.
 *
 * Params: connection = The MHD connection structure
 * Returns: NULL if no valid Digest Authorization header is used in the request;
 *         a pointer to the structure with information if the valid request
 *         header found, free using `MHD_free()`.
 * See_Also: `MHD_digest_auth_get_username3()`
 * Note: Available since `MHD_VERSION` 0x00097519
 * Ingroup: authentication
 */
MHD_DigestAuthInfo* MHD_digest_auth_get_request_info3(MHD_Connection *connection);


/**
 * Get the username from Digest Authorization client's header.
 *
 * Params: connection = The MHD connection structure
 * Returns: NULL if no valid Digest Authorization header is used in the request,
 *         or no username parameter is present in the header, or username is
 *         provided incorrectly by client (see description for
 *         `MHD_DIGEST_AUTH_UNAME_TYPE_INVALID`);
 *         a pointer structure with information if the valid request header
 *         found, free using `MHD_free()`.
 * See_Also: `MHD_digest_auth_get_request_info3()` provides more complete information
 * Note: Available since `MHD_VERSION` 0x00097519
 * Ingroup: authentication
 */
MHD_DigestAuthUsernameInfo* MHD_digest_auth_get_username3(MHD_Connection *connection);

/**
 * Authenticates the authorization header sent by the client.
 *
 * If RFC2069 mode is allowed by setting bit `MHD_DIGEST_AUTH_QOP_NONE` in
 * @a mqop and the client uses this mode, then server generated nonces are
 * used as one-time nonces because nonce-count is not supported in this old RFC.
 * Communication in this mode is very inefficient, especially if the client
 * requests several resources one-by-one as for every request new nonce must be
 * generated and client repeat all requests twice (first time to get a new
 * nonce and second time to perform an authorised request).
 *
 * Params:
 *  connection = the MHD connection structure
 *  realm = the realm to be used for authorization of the client
 *  username = the username needs to be authenticated, must be in clear text
 *                 even if userhash is used by the client
 *  password = the password used in the authentication
 *  nonce_timeout = the nonce validity duration in seconds
 *  max_nc = the maximum allowed nc (Nonce Count) value, if client's nc
 *               exceeds the specified value then MHD_DAUTH_NONCE_STALE is
 *               returned;
 *               zero for no limit
 *  mqop = the QOP to use
 *  malgo3 = digest algorithms allowed to use, fail if algorithm used
 *               by the client is not allowed by this parameter
 * Returns: `MHD_DAUTH_OK` if authenticated,
 *         the error code otherwise
 * Note: Available since `MHD_VERSION` 0x00097528
 * Ingroup: authentication
 */
MHD_DigestAuthResult MHD_digest_auth_check3(MHD_Connection *connection,
                        const(char) *realm,
                        const(char) *username,
                        const(char) *password,
                        uint nonce_timeout,
                        uint32_t max_nc,
                        MHD_DigestAuthMultiQOP mqop,
                        MHD_DigestAuthMultiAlgo3 malgo3);


/**
 * Calculate userdigest, return it as binary data.
 *
 * The "userdigest" is the hash of the "username:realm:password" string.
 *
 * The "userdigest" can be used to avoid storing the password in clear text
 * in database/files
 *
 * This function is designed to improve security of stored credentials,
 * the "userdigest" does not improve security of the authentication process.
 *
 * The results can be used to store username & userdigest pairs instead of
 * username & password pairs. To further improve security, application may
 * store username & userhash & userdigest triplets.
 *
 * Params:
 *  algo3 = the digest algorithm
 *  username = the username
 *  realm = the realm
 *  password = the password, must be zero-terminated
 *  userdigest_bin = the output buffer for userdigest;
 *                            if this function succeeds, then this buffer has
 *                            `MHD_digest_get_hash_size`(algo3) bytes of
 *                            userdigest upon return
 *  userdigest_bin = the size of the @a userdigest_bin buffer, must be
 *                       at least `MHD_digest_get_hash_size`(algo3) bytes long
 * Returns: MHD_YES on success,
 *         MHD_NO if @a userdigest_bin is too small or if @a algo3 algorithm is
 *         not supported (or external error has occurred,
 *         see `MHD_FEATURE_EXTERN_HASH`).
 * See_Also: `MHD_digest_auth_check_digest3()`
 * Note: Available since `MHD_VERSION` 0x00097535
 * Ingroup: authentication
 */
MHD_Result MHD_digest_auth_calc_userdigest(MHD_DigestAuthAlgo3 algo3,
                                 const(char) *username,
                                 const(char) *realm,
                                 const(char) *password,
                                 void *userdigest_bin,
                                 size_t bin_buf_size);


/**
 * Authenticates the authorization header sent by the client by using
 * hash of "username:realm:password".
 *
 * If RFC2069 mode is allowed by setting bit `MHD_DIGEST_AUTH_QOP_NONE` in
 * @a mqop and the client uses this mode, then server generated nonces are
 * used as one-time nonces because nonce-count is not supported in this old RFC.
 * Communication in this mode is very inefficient, especially if the client
 * requests several resources one-by-one as for every request new nonce must be
 * generated and client repeat all requests twice (first time to get a new
 * nonce and second time to perform an authorised request).
 *
 * Params:
 *  connection = the MHD connection structure
 *  realm = the realm to be used for authorization of the client
 *  username = the username needs to be authenticated, must be in clear text
 *                 even if userhash is used by the client
 *  userdigest = the precalculated binary hash of the string
 *                   "username:realm:password",
 *                   see `MHD_digest_auth_calc_userdigest()`
 *  userdigest_size = the size of the @a userdigest in bytes, must match the
 *                        hashing algorithm (see `MHD_MD5_DIGEST_SIZE`,
 *                        `MHD_SHA256_DIGEST_SIZE`, `MHD_SHA512_256_DIGEST_SIZE`,
 *                        `MHD_digest_get_hash_size()`)
 *  nonce_timeout = the period of seconds since nonce generation, when
 *                      the nonce is recognised as valid and not stale.
 *  max_nc = the maximum allowed nc (Nonce Count) value, if client's nc
 *               exceeds the specified value then MHD_DAUTH_NONCE_STALE is
 *               returned;
 *               zero for no limit
 *  mqop = the QOP to use
 *  malgo3 = digest algorithms allowed to use, fail if algorithm used
 *               by the client is not allowed by this parameter;
 *               more than one base algorithms (MD5, SHA-256, SHA-512/256)
 *               cannot be used at the same time for this function
 *               as @a userdigest must match specified algorithm
 * Returns: `MHD_DAUTH_OK` if authenticated,
 *         the error code otherwise
 * See_Also: `MHD_digest_auth_calc_userdigest()`
 * Note: Available since `MHD_VERSION` 0x00097528
 * Ingroup: authentication
 */
MHD_DigestAuthResult MHD_digest_auth_check_digest3(MHD_Connection *connection,
                               const(char) *realm,
                               const(char) *username,
                               const(void) *userdigest,
                               size_t userdigest_size,
                               uint nonce_timeout,
                               uint32_t max_nc,
                               MHD_DigestAuthMultiQOP mqop,
                               MHD_DigestAuthMultiAlgo3 malgo3);


/**
 * Queues a response to request authentication from the client
 *
 * This function modifies provided @a response. The @a response must not be
 * reused and should be destroyed (by `MHD_destroy_response()`) after call of
 * this function.
 *
 * If @a mqop allows both RFC 2069 (MHD_DIGEST_AUTH_QOP_NONE) and QOP with
 * value, then response is formed like if MHD_DIGEST_AUTH_QOP_NONE bit was
 * not set, because such response should be backward-compatible with RFC 2069.
 *
 * If @a mqop allows only MHD_DIGEST_AUTH_MULT_QOP_NONE, then the response is
 * formed in strict accordance with RFC 2069 (no 'qop', no 'userhash', no
 * 'charset'). For better compatibility with clients, it is recommended (but
 * not required) to set @a domain to NULL in this mode.
 *
 * Params:
 *  connection = the MHD connection structure
 *  realm = the realm presented to the client
 *  opaque = the string for opaque value, can be NULL, but NULL is
 *               not recommended for better compatibility with clients;
 *               the recommended format is hex or Base64 encoded string
 *  domain = the optional space-separated list of URIs for which the
 *               same authorisation could be used, URIs can be in form
 *               "path-absolute" (the path for the same host with initial slash)
 *               or in form "absolute-URI" (the full path with protocol), in
 *               any case client may assume that URI is in the same "protection
 *               space" if it starts with any of values specified here;
 *               could be NULL (clients typically assume that the same
 *               credentials could be used for any URI on the same host)
 *  response = the reply to send; should contain the "access denied"
 *                 body; note that this function sets the "WWW Authenticate"
 *                 header and that the caller should not do this;
 *                 the NULL is tolerated
 *  signal_stale = set to `MHD_YES` if the nonce is stale to add 'stale=true'
 *                     to the authentication header, this instructs the client
 *                     to retry immediately with the new nonce and the same
 *                     credentials, without asking user for the new password
 *  qop = the QOP to use
 *  algo = digest algorithm to use, MHD selects; if several algorithms
 *               are allowed then MD5 is preferred (currently, may be changed
 *               in next versions)
 *  userhash_support = if set to non-zero value (`MHD_YES`) then support of
 *                         userhash is indicated, the client may provide
 *                         hash("username:realm") instead of username in
 *                         clear text;
 *                         note that clients are allowed to provide the username
 *                         in cleartext even if this parameter set to non-zero;
 *                         when userhash is used, application must be ready to
 *                         identify users by provided userhash value instead of
 *                         username; see `MHD_digest_auth_calc_userhash()` and
 *                         `MHD_digest_auth_calc_userhash_hex()`
 *  prefer_utf8 = if not set to `MHD_NO`, parameter 'charset=UTF-8' is
 *                    added, indicating for the client that UTF-8 encoding
 *                    is preferred
 * Returns: `MHD_YES` on success, `MHD_NO` otherwise
 * Note: Available since `MHD_VERSION` 0x00097526
 * Ingroup: authentication
 */
MHD_Result MHD_queue_auth_required_response3(MHD_Connection *connection,
                                   const(char) *realm,
                                   const(char) *opaque,
                                   const(char) *domain,
                                   MHD_Response *response,
                                   int signal_stale,
                                   MHD_DigestAuthMultiQOP qop,
                                   MHD_DigestAuthMultiAlgo3 algo,
                                   int userhash_support,
                                   int prefer_utf8);



/**
 * Authenticates the authorization header sent by the client.
 * Uses `MHD_DIGEST_ALG_MD5` (for now, for backwards-compatibility).
 * Note that this MAY change to `MHD_DIGEST_ALG_AUTO` in the future.
 * If you want to be sure you get MD5, use `MHD_digest_auth_check2()`
 * and specify MD5 explicitly.
 *
 * Params:
 *  connection = The MHD connection structure
 *  realm = The realm presented to the client
 *  username = The username needs to be authenticated
 *  password = The password used in the authentication
 *  nonce_timeout = The amount of time for a nonce to be
 *      invalid in seconds
 * Returns: `MHD_YES` if authenticated, `MHD_NO` if not,
 *         `MHD_INVALID_NONCE` if nonce is invalid or stale
 * Deprecated: use MHD_digest_auth_check3()
 * Ingroup: authentication
 */
int MHD_digest_auth_check(MHD_Connection *connection,
                       const(char) *realm,
                       const(char) *username,
                       const(char) *password,
                       uint nonce_timeout);



/**
 * Authenticates the authorization header sent by the client
 * Uses `MHD_DIGEST_ALG_MD5` (required, as @a digest is of fixed
 * size).
 *
 * Params:
 *  connection = The MHD connection structure
 *  realm = The realm presented to the client
 *  username = The username needs to be authenticated
 *  digest = An `unsigned char *' pointer to the binary hash
 *    for the precalculated hash value "username:realm:password";
 *    length must be `MHD_MD5_DIGEST_SIZE` bytes
 *  nonce_timeout = The amount of time for a nonce to be
 *      invalid in seconds
 * Returns: `MHD_YES` if authenticated, `MHD_NO` if not,
 *         `MHD_INVALID_NONCE` if nonce is invalid or stale
 * Note: Available since `MHD_VERSION` 0x00096000
 * Deprecated: use `MHD_digest_auth_check_digest3()`
 * Ingroup: authentication
 */
int MHD_digest_auth_check_digest(MHD_Connection *connection,
                              const(char) *realm,
                              const(char) *username,
                              //const uint8_t digest[MHD_MD5_DIGEST_SIZE],
                              const(uint8_t) *digest,
                              int nonce_timeout);


/**
 * Queues a response to request authentication from the client.
 * For now uses MD5 (for backwards-compatibility). Still, if you
 * need to be sure, use `MHD_queue_auth_fail_response2()`.
 *
 * This function modifies provided @a response. The @a response must not be
 * reused and should be destroyed after call of this function.
 *
 * Params:
 *  connection = The MHD connection structure
 *  realm = the realm presented to the client
 *  opaque = string to user for opaque value
 *  response = reply to send; should contain the "access denied"
 *        body; note that this function will set the "WWW Authenticate"
 *        header and that the caller should not do this; the NULL is tolerated
 *  signal_stale = `MHD_YES` if the nonce is stale to add
 *        'stale=true' to the authentication header
 * Returns: `MHD_YES` on success, `MHD_NO` otherwise
 * Deprecated: use MHD_queue_auth_required_response3()
 * Ingroup: authentication
 */
MHD_Result MHD_queue_auth_fail_response(MHD_Connection *connection,
                              const(char) *realm,
                              const(char) *opaque,
                              MHD_Response *response,
                              int signal_stale);

/**
 * Get the username and password from the Basic Authorisation header
 * sent by the client
 *
 * Params: connection = the MHD connection structure
 * Returns: NULL if no valid Basic Authentication header is present in
 *         current request, or
 *         pointer to structure with username and password, which must be
 *         freed by `MHD_free()`.
 * Note: Available since `MHD_VERSION` 0x00097517
 * Ingroup: authentication
 */
MHD_BasicAuthInfo* MHD_basic_auth_get_username_password3(MHD_Connection *connection);

/**
 * Get the username and password from the basic authorization header sent by the client
 *
 * @param connection The MHD connection structure
 * @param[out] password a pointer for the password, free using `MHD_free()`.
 * Returns: NULL if no username could be found, a pointer
 *      to the username if found, free using `MHD_free()`.
 * Deprecated: use `MHD_basic_auth_get_username_password3()`
 * Ingroup: authentication
 */
deprecated("use `MHD_basic_auth_get_username_password3()`")
char* MHD_basic_auth_get_username_password(MHD_Connection *connection,
                                      char **password);


/**
 * Queues a response to request basic authentication from the client.
 *
 * The given response object is expected to include the payload for
 * the response; the "WWW-Authenticate" header will be added and the
 * response queued with the 'UNAUTHORIZED' status code.
 *
 * See RFC 7617#section-2 for details.
 *
 * The @a response is modified by this function. The modified response object
 * can be used to respond subsequent requests by `MHD_queue_response()`
 * function with status code `MHD_HTTP_UNAUTHORIZED` and must not be used again
 * with MHD_queue_basic_auth_fail_response3() function. The response could
 * be destroyed right after call of this function.
 *
 * Params:
 *  connection = the MHD connection structure
 *  realm = the realm presented to the client
 *  prefer_utf8 = if not set to `MHD_NO`, parameter'charset="UTF-8"' will
 *                    be added, indicating for client that UTF-8 encoding
 *                    is preferred
 *  response = the response object to modify and queue; the NULL
 *                 is tolerated
 * Returns: `MHD_YES` on success, `MHD_NO` otherwise
 * Note: Available since `MHD_VERSION` 0x00097516
 * Ingroup: authentication
 */
MHD_Result MHD_queue_basic_auth_fail_response3(MHD_Connection *connection,
                                     const(char) *realm,
                                     int prefer_utf8,
                                     MHD_Response *response);


/**
 * Queues a response to request basic authentication from the client
 * The given response object is expected to include the payload for
 * the response; the "WWW-Authenticate" header will be added and the
 * response queued with the 'UNAUTHORIZED' status code.
 *
 * Params:
 *  connection = The MHD connection structure
 *  realm = the realm presented to the client
 *  response = response object to modify and queue; the NULL is tolerated
 * Returns: `MHD_YES` on success, `MHD_NO` otherwise
 * Deprecated: use MHD_queue_basic_auth_fail_response3()
 * Ingroup: authentication
 */
MHD_Result MHD_queue_basic_auth_fail_response(MHD_Connection *connection,
                                    const(char) *realm,
                                    MHD_Response *response);


/**
 * Obtain information about the given connection.
 * The returned pointer is invalidated with the next call of this function or
 * when the connection is closed.
 *
 * Params:
 *  connection = what connection to get information about
 *  info_type = what information is desired?
 *  ... = arguments depends on @a info_type.
 * Returns: NULL if this information is not available
 *         (or if the @a info_type is unknown)
 * Ingroup: specialized
 */
const(MHD_ConnectionInfo)* MHD_get_connection_info(MHD_Connection *connection,
                         MHD_ConnectionInfoType info_type,
                         ...);

/**
 * Set a custom option for the given connection, overriding defaults. 
 *
 * Params:
 *  connection = connection to modify
 *  option = option to set
 *  ... = arguments to the option, depending on the option type
 * Returns: `MHD_YES` on success, `MHD_NO` if setting the option failed
 * Ingroup: specialized
 */
MHD_Result MHD_set_connection_option(MHD_Connection *connection,
                           MHD_CONNECTION_OPTION option,
                           ...);

/**
 * Obtain information about the given daemon.
 * The returned pointer is invalidated with the next call of this function or
 * when the daemon is stopped.
 *
 * Params:
 *  daemon = what daemon to get information about
 *  info_type = what information is desired?
 *  ... = arguments depends on @a info_type.
 * Returns: NULL if this information is not available
 *         (or if the @a info_type is unknown)
 * Ingroup: specialized
 */
const(MHD_DaemonInfo)* MHD_get_daemon_info(MHD_Daemon *daemon,
                     MHD_DaemonInfoType info_type,
                     ...);

/**
 * Obtain the version of this library
 *
 * Returns: static version string, e.g. "0.9.9"
 * Ingroup: specialized
 */
const(char)* MHD_get_version();

/**
 * Get information about supported MHD features.
 * Indicate that MHD was compiled with or without support for
 * particular feature. Some features require additional support
 * by kernel. Kernel support is not checked by this function.
 *
 * Params: feature = type of requested information
 * Returns: `MHD_YES` if feature is supported by MHD, `MHD_NO` if
 * feature is not supported or feature is unknown.
 * Ingroup: specialized
 */
MHD_Result MHD_is_feature_supported(MHD_FEATURE feature);


static if (MHD_VERSION >= LibMicroHTTPDSupport.v000966)
{
    /**
     * Get all of the headers from the request.
     *
     * Params:
     *  connection = connection to get values from
     *  kind = types of values to iterate over, can be a bitmask
     *  iterator = callback to call on each header;
     *        may be NULL (then just count headers)
     *  iterator_cls = extra argument to @a iterator
     * Returns: number of entries iterated over,
     *         -1 if connection is NULL.
     * Note: Available since `MHD_VERSION` 0x00096400
     * Ingroup: request
     */
    int MHD_get_connection_values_n(MHD_Connection *connection,
                                MHD_ValueKind kind,
                                MHD_KeyValueIteratorN iterator,
                                void *iterator_cls);

    /**
     * Get a particular header value.  If multiple
     * values match the kind, return any one of them.
     * Note: Since MHD_VERSION 0x00096304
     *
     * Params:
     *  connection = connection to get values from
     *  kind = what kind of value are we looking for
     *  key = the header to look for, NULL to lookup 'trailing' value without a key
     *  key_size = the length of @a key in bytes
     *  value_ptr = the pointer to variable, which will be set to found value,
     *                       will not be updated if key not found,
     *                       could be NULL to just check for presence of @a key
     *  value_size_ptr = the pointer variable, which will set to found value,
     *                            will not be updated if key not found,
     *                            could be NULL
     * Returns: `MHD_YES` if key is found,
     *         `MHD_NO` otherwise.
     * Ingroup: request
     */
    MHD_Result MHD_lookup_connection_value_n(MHD_Connection *connection,
                                MHD_ValueKind kind,
                                const(char) *key,
                                size_t key_size,
                                const(char) **value_ptr,
                                size_t *value_size_ptr);
                                

    /**
     * Create a response object with the content of provided buffer used as
     * the response body.
     *
     * The response object can be extended with header information and then
     * be used any number of times.
     *
     * If response object is used to answer HEAD request then the body
     * of the response is not used, while all headers (including automatic
     * headers) are used.
     *
     * Params:
     *  size = size of the data portion of the response
     *  buffer = size bytes containing the response's data portion
     *  crfc = function to call to free the @a buffer
     * Returns: NULL on error (i.e. invalid arguments, out of memory)
     * Note: Available since `MHD_VERSION` 0x00096000
     * Ingroup: response
     */
    MHD_Response* MHD_create_response_from_buffer_with_free_callback(size_t size,
                                                        void *buffer,
                                                        MHD_ContentReaderFreeCallback crfc);
    
    /**
     * Authenticates the authorization header sent by the client.
     *
     * Params:
     *  connection = The MHD connection structure
     *  realm = The realm presented to the client
     *  username = The username needs to be authenticated
     *  password = The password used in the authentication
     *  nonce_timeout = The amount of time for a nonce to be
     *      invalid in seconds
     *  algo = digest algorithms allowed for verification
     * Returns: `MHD_YES` if authenticated, `MHD_NO` if not,
     *         `MHD_INVALID_NONCE` if nonce is invalid or stale
     * Note: Available since `MHD_VERSION` 0x00096200
     * Deprecated: use MHD_digest_auth_check3()
     * Ingroup: authentication
     */
    int MHD_digest_auth_check2(MHD_Connection *connection,
                            const(char) *realm,
                            const(char) *username,
                            const(char) *password,
                            uint nonce_timeout,
                            MHD_DigestAuthAlgorithm algo);

    /**
     * Authenticates the authorization header sent by the client.
     *
     * Params:
     *  connection = The MHD connection structure
     *  realm = The realm presented to the client
     *  username = The username needs to be authenticated
     *  digest = An `unsigned char *' pointer to the binary MD5 sum
     *      for the precalculated hash value "username:realm:password"
     *      of @a digest_size bytes
     *  digest_size = number of bytes in @a digest (size must match @a algo!)
     *  nonce_timeout = The amount of time for a nonce to be
     *      invalid in seconds
     *  algo = digest algorithms allowed for verification
     * Returns: `MHD_YES` if authenticated, `MHD_NO` if not,
     *         `MHD_INVALID_NONCE` if nonce is invalid or stale
     * Note: Available since `MHD_VERSION` 0x00096200
     * Deprecated: use MHD_digest_auth_check_digest3()
     * Ingroup: authentication
     */
    int MHD_digest_auth_check_digest2(MHD_Connection *connection,
                                const(char) *realm,
                                const(char) *username,
                                const(uint8_t) *digest,
                                size_t digest_size,
                                uint nonce_timeout,
                                MHD_DigestAuthAlgorithm algo);


    /**
     * Queues a response to request authentication from the client
     *
     * This function modifies provided @a response. The @a response must not be
     * reused and should be destroyed after call of this function.
     *
     * Params:
     *  connection = The MHD connection structure
     *  realm = the realm presented to the client
     *  opaque = string to user for opaque value
     *  response = reply to send; should contain the "access denied"
     *        body; note that this function will set the "WWW Authenticate"
     *        header and that the caller should not do this; the NULL is tolerated
     *  signal_stale = `MHD_YES` if the nonce is stale to add
     *        'stale=true' to the authentication header
     *  algo = digest algorithm to use
     * Returns: `MHD_YES` on success, `MHD_NO` otherwise
     * Note: Available since `MHD_VERSION` 0x00096200
     * Deprecated: use MHD_queue_auth_required_response3()
     * Ingroup: authentication
     */
    MHD_Result MHD_queue_auth_fail_response2(MHD_Connection *connection,
                                const(char) *realm,
                                const(char) *opaque,
                                MHD_Response *response,
                                int signal_stale,
                                MHD_DigestAuthAlgorithm algo);
}


static if (MHD_VERSION >= LibMicroHTTPDSupport.v000975)
{
    /**
     * Run websever operation with possible blocking.
     *
     * This function does the following: waits for any network event not more than
     * specified number of milliseconds, processes all incoming and outgoing data,
     * processes new connections, processes any timed-out connection, and does
     * other things required to run webserver.
     * Once all connections are processed, function returns.
     *
     * This function is useful for quick and simple (lazy) webserver implementation
     * if application needs to run a single thread only and does not have any other
     * network activity.
     *
     * This function calls MHD_get_timeout() internally and use returned value as
     * maximum wait time if it less than value of @a millisec parameter.
     *
     * It is expected that the "external" socket polling function is not used in
     * conjunction with this function unless the @a millisec is set to zero.
     *
     * Params:
     *  daemon = the daemon to run
     *  millisec = the maximum time in milliseconds to wait for network and
     *                 other events. Note: there is no guarantee that function
     *                 blocks for the specified amount of time. The real processing
     *                 time can be shorter (if some data or connection timeout
     *                 comes earlier) or longer (if data processing requires more
     *                 time, especially in user callbacks).
     *                 If set to '0' then function does not block and processes
     *                 only already available data (if any).
     *                 If set to '-1' then function waits for events
     *                 indefinitely (blocks until next network activity or
     *                 connection timeout).
     * Returns: `MHD_YES` on success, `MHD_NO` if this
     *         daemon was not started with the right
     *         options for this call or some serious
     *         unrecoverable error occurs.
     * Note: Available since `MHD_VERSION` 0x00097206
     * Ingroup: event
     */
    MHD_Result MHD_run_wait(MHD_Daemon *daemon, int32_t millisec);
    

    /**
     * This function can be used to add an arbitrary entry to connection.
     * This function could add entry with binary zero, which is allowed
     * for `MHD_GET_ARGUMENT_KIND`. For other kind on entries it is
     * recommended to use `MHD_set_connection_value`.
     *
     * This function MUST only be called from within the
     * `MHD_AccessHandlerCallback` (otherwise, access maybe improperly
     * synchronized).  Furthermore, the client must guarantee that the key
     * and value arguments are 0-terminated strings that are NOT freed
     * until the connection is closed.  (The easiest way to do this is by
     * passing only arguments to permanently allocated strings.).
     *
     * Params:
     *  connection = the connection for which a value should be set
     *  kind = kind of the value
     *  key = key for the value, must be zero-terminated
     *  key_size = number of bytes in @a key (excluding 0-terminator)
     *  value = the value itself, must be zero-terminated
     *  value_size = number of bytes in @a value (excluding 0-terminator)
     * Returns: `MHD_NO` if the operation could not be
     *         performed due to insufficient memory;
     *         `MHD_YES` on success
     * Note: Available since `MHD_VERSION` 0x00096400
     * Ingroup: request
     */
    MHD_Result MHD_set_connection_value_n(MHD_Connection *connection,
        MHD_ValueKind kind,
        const(char) *key, size_t key_size,
        const(char) *value, size_t value_size);
    

    /**
     * Create a response object with the content of provided buffer used as
     * the response body.
     *
     * The response object can be extended with header information and then
     * be used any number of times.
     *
     * If response object is used to answer HEAD request then the body
     * of the response is not used, while all headers (including automatic
     * headers) are used.
     *
     * Params:
     *  size = size of the data portion of the response
     *  buffer = size bytes containing the response's data portion
     *  crfc = function to call to cleanup, if set to NULL then callback
     *             is not called
     *  crfc_cls = an argument for @a crfc
     * Returns: NULL on error (i.e. invalid arguments, out of memory)
     * Note: Available since `MHD_VERSION` 0x00097302
     * Note: 'const' qualifier is used for @a buffer since `MHD_VERSION` 0x00097504
     * Ingroup: response
     */
    MHD_Response* MHD_create_response_from_buffer_with_free_callback_cls(size_t size,
                                                            const(void) *buffer,
                                                            MHD_ContentReaderFreeCallback crfc,
                                                            void *crfc_cls);


    /**
     * Create a response object with the response body created by reading
     * the provided pipe.
     *
     * The response object can be extended with header information and
     * then be used ONLY ONCE.
     *
     * If response object is used to answer HEAD request then the body
     * of the response is not used, while all headers (including automatic
     * headers) are used.
     *
     * Params: fd = file descriptor referring to a read-end of a pipe with the
     *        data; will be closed when response is destroyed;
     *        fd should be in 'blocking' mode
     * Returns: NULL on error (i.e. invalid arguments, out of memory)
     * Note: Available since `MHD_VERSION` 0x00097102
     * Ingroup: response
     */
    MHD_Response* MHD_create_response_from_pipe(int fd);


    /**
     * Create a response object with an array of memory buffers
     * used as the response body.
     *
     * The response object can be extended with header information and then
     * be used any number of times.
     *
     * If response object is used to answer HEAD request then the body
     * of the response is not used, while all headers (including automatic
     * headers) are used.
     *
     * Params:
     *  iov = the array for response data buffers, an internal copy of this
     *        will be made
     *  iovcnt = the number of elements in @a iov
     *  free_cb = the callback to clean up any data associated with @a iov when
     *        the response is destroyed.
     *  cls = the argument passed to @a free_cb
     * Returns: NULL on error (i.e. invalid arguments, out of memory)
     * Note: Available since `MHD_VERSION` 0x00097204
     * Ingroup: response
     */
    MHD_Response* MHD_create_response_from_iovec(const(MHD_IoVec) *iov,
                                    uint iovcnt,
                                    MHD_ContentReaderFreeCallback free_cb,
                                    void *cls);
}