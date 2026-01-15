/**
 * Bindings for the libmicrohttpd library. The rest of the doc is left as-is as
 * much as possible.
 *
 * Authors: dd86k <dd@dax.moe>
 * File: microhttpd.h
 * Brief: public interface to libmicrohttpd
 * Original_Authors: Christian Grothoff, Karlson2k (Evgeny Grin), Chris GauthierDickey
 *
 * All symbols defined in this header start with MHD.  MHD is a small
 * HTTP daemon library.  As such, it does not have any API for logging
 * errors (you can only enable or disable logging to stderr).  Also,
 * it may not support all of the HTTP features directly, where
 * applicable, portions of HTTP may have to be handled by clients of
 * the library.
 *
 * The library is supposed to handle everything that it must handle
 * (because the API would not allow clients to do this), such as basic
 * connection management; however, detailed interpretations of headers
 * -- such as range requests -- and HTTP methods are left to clients.
 * The library does understand HEAD and will only send the headers of
 * the response and not the body, even if the client supplied a body.
 * The library also understands headers that control connection
 * management (specifically, "Connection: close" and "Expect: 100
 * continue" are understood and handled automatically).
 *
 * MHD understands POST data and is able to decode certain formats
 * (at the moment only "application/x-www-form-urlencoded" and
 * "multipart/formdata"). Unsupported encodings and large POST
 * submissions may require the application to manually process
 * the stream, which is provided to the main application (and thus can be
 * processed, just not conveniently by MHD).
 *
 * The header file defines various constants used by the HTTP protocol.
 * This does not mean that MHD actually interprets all of these
 * values.  The provided constants are exported as a convenience
 * for users of the library.  MHD does not verify that transmitted
 * HTTP headers are part of the standard specification; users of the
 * library are free to define their own extensions of the HTTP
 * standard and use those with MHD.
 *
 * All functions are guaranteed to be completely reentrant and
 * thread-safe (with the exception of `MHD_set_connection_value`,
 * which must only be used in a particular context).
 *
 *
 * @defgroup event event-loop control
 * MHD API to start and stop the HTTP server and manage the event loop.
 * @defgroup response generation of responses
 * MHD API used to generate responses.
 * @defgroup request handling of requests
 * MHD API used to access information about requests.
 * @defgroup authentication HTTP authentication
 * MHD API related to basic and digest HTTP authentication.
 * @defgroup logging logging
 * MHD API to mange logging and error handling
 * @defgroup specialized misc. specialized functions
 * This group includes functions that do not fit into any particular
 * category and that are rarely used.
 */
module bindbc.libmicrohttpd.header;

/*
     This file is part of libmicrohttpd
     Copyright (C) 2006-2021 Christian Grothoff (and other contributing authors)
     Copyright (C) 2014-2022 Evgeny Grin (Karlson2k)

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

version (Posix)
{
    public import core.sys.posix.unistd;
    public import core.sys.posix.sys.types;
    public import core.sys.posix.sys.socket;
    public import core.sys.posix.sys.select;
}
version (Windows)
{
    public import core.sys.windows.winsock2; // ws2tcpip.h
    public import core.stdc.stdint : intptr_t;
    
    // While core.sys.posix.sys.types sets this as c_long,
    // the libmicrohttpdheaders uses intptr_t
    public alias ssize_t = intptr_t;
    
    // Assumes __USE_FILE_OFFSET64 is set for 64-bit builds
    static if (size_t.sizeof == 8)
        public alias off_t = long;
    else
        public alias off_t = int;
}

public import core.stdc.stdarg;
public import core.stdc.stdint;

alias MHD_UNSIGNED_LONG_LONG = ulong;

/**
 * Operational results from MHD calls.
 */
alias MHD_Result = int;
enum : MHD_Result
{
    /// MHD result code for "NO".
    MHD_NO = 0,

    /// MHD result code for "YES".
    MHD_YES = 1
}

version (UINT64_MAX)
    /// Constant used to indicate unknown size (use when
    /// creating a response).
    enum MHD_SIZE_UNKNOWN = ulong.max;
else
    /// Ditto
    enum MHD_SIZE_UNKNOWN = -1LU;

enum MHD_CONTENT_READER_END_OF_STREAM  = cast(ssize_t) -1;
enum MHD_CONTENT_READER_END_WITH_ERROR = cast(ssize_t) -2;

version (Posix)
{
    enum MHD_POSIX_SOCKETS = 1;
    alias MHD_socket = int;
}
else version (Windows)
{
    enum MHD_WINDOWS_SOCKETS = 1;
    alias MHD_socket = SOCKET;
}

/*
 * @defgroup httpcode HTTP response codes.
 * These are the status codes defined for HTTP responses.
 * See_Also: https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
 * Registry export date: 2021-12-19
 * @{
 */

/// 100 "Continue".            RFC-ietf-httpbis-semantics, Section 15.2.1.
enum MHD_HTTP_CONTINUE            = 100;
/// 101 "Switching Protocols". RFC-ietf-httpbis-semantics, Section 15.2.2.
enum MHD_HTTP_SWITCHING_PROTOCOLS = 101;
/// 102 "Processing".          RFC2518.
enum MHD_HTTP_PROCESSING          = 102;
/// 103 "Early Hints".         RFC8297.
enum MHD_HTTP_EARLY_HINTS         = 103;

/// 200 "OK".                  RFC-ietf-httpbis-semantics, Section 15.3.1.
enum MHD_HTTP_OK                          = 200;
/// 201 "Created".             RFC-ietf-httpbis-semantics, Section 15.3.2.
enum MHD_HTTP_CREATED                     = 201;
/// 202 "Accepted".            RFC-ietf-httpbis-semantics, Section 15.3.3.
enum MHD_HTTP_ACCEPTED                    = 202;
/// 203 "Non-Authoritative Information". RFC-ietf-httpbis-semantics, Section 15.3.4.
enum MHD_HTTP_NON_AUTHORITATIVE_INFORMATION = 203;
/// 204 "No Content".          RFC-ietf-httpbis-semantics, Section 15.3.5.
enum MHD_HTTP_NO_CONTENT                  = 204;
/// 205 "Reset Content".       RFC-ietf-httpbis-semantics, Section 15.3.6.
enum MHD_HTTP_RESET_CONTENT               = 205;
/// 206 "Partial Content".     RFC-ietf-httpbis-semantics, Section 15.3.7.
enum MHD_HTTP_PARTIAL_CONTENT             = 206;
/// 207 "Multi-Status".        RFC4918.
enum MHD_HTTP_MULTI_STATUS                = 207;
/// 208 "Already Reported".    RFC5842.
enum MHD_HTTP_ALREADY_REPORTED            = 208;

/// 226 "IM Used".             RFC3229.
enum MHD_HTTP_IM_USED                     = 226;

/// 300 "Multiple Choices".    RFC-ietf-httpbis-semantics, Section 15.4.1.
enum MHD_HTTP_MULTIPLE_CHOICES          = 300;
/// 301 "Moved Permanently".   RFC-ietf-httpbis-semantics, Section 15.4.2.
enum MHD_HTTP_MOVED_PERMANENTLY         = 301;
/// 302 "Found".               RFC-ietf-httpbis-semantics, Section 15.4.3.
enum MHD_HTTP_FOUND                     = 302;
/// 303 "See Other".           RFC-ietf-httpbis-semantics, Section 15.4.4.
enum MHD_HTTP_SEE_OTHER                 = 303;
/// 304 "Not Modified".        RFC-ietf-httpbis-semantics, Section 15.4.5.
enum MHD_HTTP_NOT_MODIFIED              = 304;
/// 305 "Use Proxy".           RFC-ietf-httpbis-semantics, Section 15.4.6.
enum MHD_HTTP_USE_PROXY                 = 305;
/// 306 "Switch Proxy".        Not used! RFC-ietf-httpbis-semantics, Section 15.4.7.
enum MHD_HTTP_SWITCH_PROXY              = 306;
/// 307 "Temporary Redirect".  RFC-ietf-httpbis-semantics, Section 15.4.8.
enum MHD_HTTP_TEMPORARY_REDIRECT        = 307;
/// 308 "Permanent Redirect".  RFC-ietf-httpbis-semantics, Section 15.4.9.
enum MHD_HTTP_PERMANENT_REDIRECT        = 308;

/// 400 "Bad Request".         RFC-ietf-httpbis-semantics, Section 15.5.1.
enum MHD_HTTP_BAD_REQUEST                 = 400;
/// 401 "Unauthorized".        RFC-ietf-httpbis-semantics, Section 15.5.2.
enum MHD_HTTP_UNAUTHORIZED                = 401;
/// 402 "Payment Required".    RFC-ietf-httpbis-semantics, Section 15.5.3.
enum MHD_HTTP_PAYMENT_REQUIRED            = 402;
/// 403 "Forbidden".           RFC-ietf-httpbis-semantics, Section 15.5.4.
enum MHD_HTTP_FORBIDDEN                   = 403;
/// 404 "Not Found".           RFC-ietf-httpbis-semantics, Section 15.5.5.
enum MHD_HTTP_NOT_FOUND                   = 404;
/// 405 "Method Not Allowed".  RFC-ietf-httpbis-semantics, Section 15.5.6.
enum MHD_HTTP_METHOD_NOT_ALLOWED          = 405;
/// 406 "Not Acceptable".      RFC-ietf-httpbis-semantics, Section 15.5.7.
enum MHD_HTTP_NOT_ACCEPTABLE              = 406;
/// 407 "Proxy Authentication Required". RFC-ietf-httpbis-semantics, Section 15.5.8.
enum MHD_HTTP_PROXY_AUTHENTICATION_REQUIRED = 407;
/// 408 "Request Timeout".     RFC-ietf-httpbis-semantics, Section 15.5.9.
enum MHD_HTTP_REQUEST_TIMEOUT             = 408;
/// 409 "Conflict".            RFC-ietf-httpbis-semantics, Section 15.5.10.
enum MHD_HTTP_CONFLICT                    = 409;
/// 410 "Gone".                RFC-ietf-httpbis-semantics, Section 15.5.11.
enum MHD_HTTP_GONE                        = 410;
/// 411 "Length Required".     RFC-ietf-httpbis-semantics, Section 15.5.12.
enum MHD_HTTP_LENGTH_REQUIRED             = 411;
/// 412 "Precondition Failed". RFC-ietf-httpbis-semantics, Section 15.5.13.
enum MHD_HTTP_PRECONDITION_FAILED         = 412;
/// 413 "Content Too Large".   RFC-ietf-httpbis-semantics, Section 15.5.14.
enum MHD_HTTP_CONTENT_TOO_LARGE           = 413;
/// 414 "URI Too Long".        RFC-ietf-httpbis-semantics, Section 15.5.15.
enum MHD_HTTP_URI_TOO_LONG                = 414;
/// 415 "Unsupported Media Type". RFC-ietf-httpbis-semantics, Section 15.5.16.
enum MHD_HTTP_UNSUPPORTED_MEDIA_TYPE      = 415;
/// 416 "Range Not Satisfiable". RFC-ietf-httpbis-semantics, Section 15.5.17.
enum MHD_HTTP_RANGE_NOT_SATISFIABLE       = 416;
/// 417 "Expectation Failed".  RFC-ietf-httpbis-semantics, Section 15.5.18.
enum MHD_HTTP_EXPECTATION_FAILED          = 417;


/// 421 "Misdirected Request". RFC-ietf-httpbis-semantics, Section 15.5.20.
enum MHD_HTTP_MISDIRECTED_REQUEST         = 421;
/// 422 "Unprocessable Content". RFC-ietf-httpbis-semantics, Section 15.5.21.
enum MHD_HTTP_UNPROCESSABLE_CONTENT       = 422;
/// 423 "Locked".              RFC4918.
enum MHD_HTTP_LOCKED                      = 423;
/// 424 "Failed Dependency".   RFC4918.
enum MHD_HTTP_FAILED_DEPENDENCY           = 424;
/// 425 "Too Early".           RFC8470.
enum MHD_HTTP_TOO_EARLY                   = 425;
/// 426 "Upgrade Required".    RFC-ietf-httpbis-semantics, Section 15.5.22.
enum MHD_HTTP_UPGRADE_REQUIRED            = 426;

/// 428 "Precondition Required". RFC6585.
enum MHD_HTTP_PRECONDITION_REQUIRED       = 428;
/// 429 "Too Many Requests".   RFC6585.
enum MHD_HTTP_TOO_MANY_REQUESTS           = 429;

/// 431 "Request Header Fields Too Large". RFC6585.
enum MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431;

/// 451 "Unavailable For Legal Reasons". RFC7725.
enum MHD_HTTP_UNAVAILABLE_FOR_LEGAL_REASONS   = 451;

/// 500 "Internal Server Error". RFC-ietf-httpbis-semantics, Section 15.6.1.
enum MHD_HTTP_INTERNAL_SERVER_ERROR       = 500;
/// 501 "Not Implemented".     RFC-ietf-httpbis-semantics, Section 15.6.2.
enum MHD_HTTP_NOT_IMPLEMENTED             = 501;
/// 502 "Bad Gateway".         RFC-ietf-httpbis-semantics, Section 15.6.3.
enum MHD_HTTP_BAD_GATEWAY                 = 502;
/// 503 "Service Unavailable". RFC-ietf-httpbis-semantics, Section 15.6.4.
enum MHD_HTTP_SERVICE_UNAVAILABLE         = 503;
/// 504 "Gateway Timeout".     RFC-ietf-httpbis-semantics, Section 15.6.5.
enum MHD_HTTP_GATEWAY_TIMEOUT             = 504;
/// 505 "HTTP Version Not Supported". RFC-ietf-httpbis-semantics, Section 15.6.6.
enum MHD_HTTP_HTTP_VERSION_NOT_SUPPORTED  = 505;
/// 506 "Variant Also Negotiates". RFC2295.
enum MHD_HTTP_VARIANT_ALSO_NEGOTIATES     = 506;
/// 507 "Insufficient Storage". RFC4918.
enum MHD_HTTP_INSUFFICIENT_STORAGE        = 507;
/// 508 "Loop Detected".       RFC5842.
enum MHD_HTTP_LOOP_DETECTED               = 508;

/// 510 "Not Extended".        RFC2774.
enum MHD_HTTP_NOT_EXTENDED                = 510;
/// 511 "Network Authentication Required". RFC6585.
enum MHD_HTTP_NETWORK_AUTHENTICATION_REQUIRED = 511;

/// Not registered non-standard codes
/// 449 "Reply With".          MS IIS extension.
enum MHD_HTTP_RETRY_WITH                  = 449;

/// 450 "Blocked by Windows Parental Controls". MS extension.
enum MHD_HTTP_BLOCKED_BY_WINDOWS_PARENTAL_CONTROLS = 450;

/// 509 "Bandwidth Limit Exceeded". Apache extension.
enum MHD_HTTP_BANDWIDTH_LIMIT_EXCEEDED    = 509;

deprecated("Value MHD_HTTP_METHOD_NOT_ACCEPTABLE is deprecated, use MHD_HTTP_NOT_ACCEPTABLE")
enum MHD_HTTP_METHOD_NOT_ACCEPTABLE = 406;

deprecated("Value MHD_HTTP_REQUEST_ENTITY_TOO_LARGE is deprecated, use MHD_HTTP_CONTENT_TOO_LARGE")
enum MHD_HTTP_REQUEST_ENTITY_TOO_LARGE = 413;

deprecated("Value MHD_HTTP_PAYLOAD_TOO_LARGE is deprecated, use MHD_HTTP_CONTENT_TOO_LARGE")
enum MHD_HTTP_PAYLOAD_TOO_LARGE = 413;

deprecated("Value MHD_HTTP_REQUEST_URI_TOO_LONG is deprecated, use MHD_HTTP_URI_TOO_LONG")
enum MHD_HTTP_REQUEST_URI_TOO_LONG = 414;

deprecated("Value MHD_HTTP_REQUESTED_RANGE_NOT_SATISFIABLE is deprecated, use MHD_HTTP_RANGE_NOT_SATISFIABLE")
enum MHD_HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416;

deprecated("Value MHD_HTTP_UNPROCESSABLE_ENTITY is deprecated, use MHD_HTTP_UNPROCESSABLE_CONTENT")
enum MHD_HTTP_UNPROCESSABLE_ENTITY = 422;

deprecated("Value MHD_HTTP_UNORDERED_COLLECTION is deprecated as it was removed from RFC")
enum MHD_HTTP_UNORDERED_COLLECTION = 425;

deprecated("Value MHD_HTTP_NO_RESPONSE is deprecated as it is nginx internal code for logs only")
enum MHD_HTTP_NO_RESPONSE = 444;

extern (C):

/**
 * Returns the string reason phrase for a response code.
 *
 * If message string is not available for a status code,
 * "Unknown" string will be returned.
 */
//const(char) *MHD_get_reason_phrase_for (uint code);


/**
 * Returns the length of the string reason phrase for a response code.
 *
 * If message string is not available for a status code,
 * 0 is returned.
 */
//size_t MHD_get_reason_phrase_len_for (uint code);

/**
 * Flag to be or-ed with MHD_HTTP status code for
 * SHOUTcast.  This will cause the response to begin
 * with the SHOUTcast "ICY" line instead of "HTTP".
 * Ingroup: specialized
 */
//#define MHD_ICY_FLAG ((uint32_t) (((uint32_t) 1) << 31))
enum MHD_ICY_FLAG = 1u << 31;

/*
 * @defgroup headers HTTP headers
 * These are the standard headers found in HTTP requests and responses.
 * See_Also: https://www.iana.org/assignments/http-fields/http-fields.xhtml
 * Registry export date: 2021-12-19
 * @{
 */

/// Main HTTP headers.
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 12.5.1
enum MHD_HTTP_HEADER_ACCEPT       = "Accept";
/// Deprecated.    RFC-ietf-httpbis-semantics-19, Section 12.5.2
enum MHD_HTTP_HEADER_ACCEPT_CHARSET = "Accept-Charset";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 12.5.3
enum MHD_HTTP_HEADER_ACCEPT_ENCODING = "Accept-Encoding";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 12.5.4
enum MHD_HTTP_HEADER_ACCEPT_LANGUAGE = "Accept-Language";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 14.3
enum MHD_HTTP_HEADER_ACCEPT_RANGES = "Accept-Ranges";
/// Permanent.     RFC-ietf-httpbis-cache-19, Section 5.1
enum MHD_HTTP_HEADER_AGE          = "Age";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.2.1
enum MHD_HTTP_HEADER_ALLOW        = "Allow";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.6.3
enum MHD_HTTP_HEADER_AUTHENTICATION_INFO = "Authentication-Info";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.6.2
enum MHD_HTTP_HEADER_AUTHORIZATION = "Authorization";
/// Permanent.     RFC-ietf-httpbis-cache-19, Section 5.2
enum MHD_HTTP_HEADER_CACHE_CONTROL = "Cache-Control";
/// Permanent.     RFC-ietf-httpbis-cache-header-10
enum MHD_HTTP_HEADER_CACHE_STATUS = "Cache-Status";
/// Permanent.     RFC-ietf-httpbis-messaging-19, Section 9.6
enum MHD_HTTP_HEADER_CLOSE        = "Close";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 7.6.1
enum MHD_HTTP_HEADER_CONNECTION   = "Connection";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.4
enum MHD_HTTP_HEADER_CONTENT_ENCODING = "Content-Encoding";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.5
enum MHD_HTTP_HEADER_CONTENT_LANGUAGE = "Content-Language";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.6
enum MHD_HTTP_HEADER_CONTENT_LENGTH = "Content-Length";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.7
enum MHD_HTTP_HEADER_CONTENT_LOCATION = "Content-Location";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 14.4
enum MHD_HTTP_HEADER_CONTENT_RANGE = "Content-Range";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.3
enum MHD_HTTP_HEADER_CONTENT_TYPE = "Content-Type";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 6.6.1
enum MHD_HTTP_HEADER_DATE         = "Date";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.8.3
enum MHD_HTTP_HEADER_ETAG         = "ETag";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.1.1
enum MHD_HTTP_HEADER_EXPECT       = "Expect";
/// Permanent.     RFC-ietf-httpbis-expect-ct-08
enum MHD_HTTP_HEADER_EXPECT_CT    = "Expect-CT";
/// Permanent.     RFC-ietf-httpbis-cache-19, Section 5.3
enum MHD_HTTP_HEADER_EXPIRES      = "Expires";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.1.2
enum MHD_HTTP_HEADER_FROM         = "From";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 7.2
enum MHD_HTTP_HEADER_HOST         = "Host";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 13.1.1
enum MHD_HTTP_HEADER_IF_MATCH     = "If-Match";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 13.1.3
enum MHD_HTTP_HEADER_IF_MODIFIED_SINCE = "If-Modified-Since";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 13.1.2
enum MHD_HTTP_HEADER_IF_NONE_MATCH = "If-None-Match";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 13.1.5
enum MHD_HTTP_HEADER_IF_RANGE     = "If-Range";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 13.1.4
enum MHD_HTTP_HEADER_IF_UNMODIFIED_SINCE = "If-Unmodified-Since";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 8.8.2
enum MHD_HTTP_HEADER_LAST_MODIFIED = "Last-Modified";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.2.2
enum MHD_HTTP_HEADER_LOCATION     = "Location";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 7.6.2
enum MHD_HTTP_HEADER_MAX_FORWARDS = "Max-Forwards";
/// Permanent.     RFC-ietf-httpbis-messaging-19, Appendix B.1
enum MHD_HTTP_HEADER_MIME_VERSION = "MIME-Version";
/// Permanent.     RFC-ietf-httpbis-cache-19, Section 5.4
enum MHD_HTTP_HEADER_PRAGMA       = "Pragma";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.7.1
enum MHD_HTTP_HEADER_PROXY_AUTHENTICATE = "Proxy-Authenticate";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.7.3
enum MHD_HTTP_HEADER_PROXY_AUTHENTICATION_INFO = "Proxy-Authentication-Info";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.7.2
enum MHD_HTTP_HEADER_PROXY_AUTHORIZATION = "Proxy-Authorization";
/// Permanent.     RFC-ietf-httpbis-proxy-status-08
enum MHD_HTTP_HEADER_PROXY_STATUS = "Proxy-Status";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 14.2
enum MHD_HTTP_HEADER_RANGE        = "Range";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.1.3
enum MHD_HTTP_HEADER_REFERER      = "Referer";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.2.3
enum MHD_HTTP_HEADER_RETRY_AFTER  = "Retry-After";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.2.4
enum MHD_HTTP_HEADER_SERVER       = "Server";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.1.4
enum MHD_HTTP_HEADER_TE           = "TE";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 6.6.2
enum MHD_HTTP_HEADER_TRAILER      = "Trailer";
/// Permanent.     RFC-ietf-httpbis-messaging-19, Section 6.1
enum MHD_HTTP_HEADER_TRANSFER_ENCODING = "Transfer-Encoding";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 7.8
enum MHD_HTTP_HEADER_UPGRADE      = "Upgrade";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 10.1.5
enum MHD_HTTP_HEADER_USER_AGENT   = "User-Agent";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 12.5.5
enum MHD_HTTP_HEADER_VARY         = "Vary";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 7.6.3
enum MHD_HTTP_HEADER_VIA          = "Via";
/// Obsoleted.     RFC-ietf-httpbis-cache-19, Section 5.5
enum MHD_HTTP_HEADER_WARNING      = "Warning";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 11.6.1
enum MHD_HTTP_HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";
/// Permanent.     RFC-ietf-httpbis-semantics-19, Section 12.5.5
enum MHD_HTTP_HEADER_ASTERISK    =  "*";

/// Additional HTTP headers.
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_A_IM         = "A-IM";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_ACCEPT_ADDITIONS = "Accept-Additions";
/// Permanent.     RFC8942, Section 3.1
enum MHD_HTTP_HEADER_ACCEPT_CH    = "Accept-CH";
/// Permanent.     RFC7089
enum MHD_HTTP_HEADER_ACCEPT_DATETIME = "Accept-Datetime";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_ACCEPT_FEATURES = "Accept-Features";
/// Permanent.     https://www.w3.org/TR/ldp/
enum MHD_HTTP_HEADER_ACCEPT_POST  = "Accept-Post";
/// Permanent.     https://fetch.spec.whatwg.org/#http-access-control-allow-credentials
enum MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
/// Permanent.     https://fetch.spec.whatwg.org/#http-access-control-allow-headers
enum MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
/// Permanent.     https://fetch.spec.whatwg.org/#http-access-control-allow-methods
enum MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
/// Permanent.     https://fetch.spec.whatwg.org/#http-access-control-allow-origin
enum MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
/// Permanent.     https://fetch.spec.whatwg.org/#http-access-control-expose-headers
enum MHD_HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers";
/// Permanent.     https://fetch.spec.whatwg.org/#http-access-control-max-age
enum MHD_HTTP_HEADER_ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";
/// Permanent.     https://fetch.spec.whatwg.org/#http-access-control-request-headers
enum MHD_HTTP_HEADER_ACCESS_CONTROL_REQUEST_HEADERS = "Access-Control-Request-Headers";
/// Permanent.     https://fetch.spec.whatwg.org/#http-access-control-request-method
enum MHD_HTTP_HEADER_ACCESS_CONTROL_REQUEST_METHOD = "Access-Control-Request-Method";
/// Permanent.     RFC7639, Section 2
enum MHD_HTTP_HEADER_ALPN         = "ALPN";
/// Permanent.     RFC7838
enum MHD_HTTP_HEADER_ALT_SVC      = "Alt-Svc";
/// Permanent.     RFC7838
enum MHD_HTTP_HEADER_ALT_USED     = "Alt-Used";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_ALTERNATES   = "Alternates";
/// Permanent.     RFC4437
enum MHD_HTTP_HEADER_APPLY_TO_REDIRECT_REF = "Apply-To-Redirect-Ref";
/// Permanent.     RFC8053, Section 4
enum MHD_HTTP_HEADER_AUTHENTICATION_CONTROL = "Authentication-Control";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_C_EXT        = "C-Ext";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_C_MAN        = "C-Man";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_C_OPT        = "C-Opt";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_C_PEP        = "C-PEP";
/// Permanent.     RFC8607, Section 5.1
enum MHD_HTTP_HEADER_CAL_MANAGED_ID = "Cal-Managed-ID";
/// Permanent.     RFC7809, Section 7.1
enum MHD_HTTP_HEADER_CALDAV_TIMEZONES = "CalDAV-Timezones";
/// Permanent.     RFC8586
enum MHD_HTTP_HEADER_CDN_LOOP     = "CDN-Loop";
/// Permanent.     RFC8739, Section 3.3
enum MHD_HTTP_HEADER_CERT_NOT_AFTER = "Cert-Not-After";
/// Permanent.     RFC8739, Section 3.3
enum MHD_HTTP_HEADER_CERT_NOT_BEFORE = "Cert-Not-Before";
/// Permanent.     RFC6266
enum MHD_HTTP_HEADER_CONTENT_DISPOSITION = "Content-Disposition";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_CONTENT_ID   = "Content-ID";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_CONTENT_SCRIPT_TYPE = "Content-Script-Type";
/// Permanent.     https://www.w3.org/TR/CSP/#csp-header
enum MHD_HTTP_HEADER_CONTENT_SECURITY_POLICY = "Content-Security-Policy";
/// Permanent.     https://www.w3.org/TR/CSP/#cspro-header
enum MHD_HTTP_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY = "Content-Security-Policy-Report-Only";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_CONTENT_STYLE_TYPE = "Content-Style-Type";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_CONTENT_VERSION = "Content-Version";
/// Permanent.     RFC6265
enum MHD_HTTP_HEADER_COOKIE       = "Cookie";
/// Permanent.     https://html.spec.whatwg.org/multipage/origin.html#cross-origin-embedder-policy
enum MHD_HTTP_HEADER_CROSS_ORIGIN_EMBEDDER_POLICY = "Cross-Origin-Embedder-Policy";
/// Permanent.     https://html.spec.whatwg.org/multipage/origin.html#cross-origin-embedder-policy-report-only
enum MHD_HTTP_HEADER_CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY = "Cross-Origin-Embedder-Policy-Report-Only";
/// Permanent.     https://html.spec.whatwg.org/multipage/origin.html#cross-origin-opener-policy-2
enum MHD_HTTP_HEADER_CROSS_ORIGIN_OPENER_POLICY = "Cross-Origin-Opener-Policy";
/// Permanent.     https://html.spec.whatwg.org/multipage/origin.html#cross-origin-opener-policy-report-only
enum MHD_HTTP_HEADER_CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY = "Cross-Origin-Opener-Policy-Report-Only";
/// Permanent.     https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header
enum MHD_HTTP_HEADER_CROSS_ORIGIN_RESOURCE_POLICY = "Cross-Origin-Resource-Policy";
/// Permanent.     RFC5323
enum MHD_HTTP_HEADER_DASL         = "DASL";
/// Permanent.     RFC4918
enum MHD_HTTP_HEADER_DAV          = "DAV";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_DEFAULT_STYLE = "Default-Style";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_DELTA_BASE   = "Delta-Base";
/// Permanent.     RFC4918
enum MHD_HTTP_HEADER_DEPTH        = "Depth";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_DERIVED_FROM = "Derived-From";
/// Permanent.     RFC4918
enum MHD_HTTP_HEADER_DESTINATION  = "Destination";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_DIFFERENTIAL_ID = "Differential-ID";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_DIGEST       = "Digest";
/// Permanent.     RFC8470
enum MHD_HTTP_HEADER_EARLY_DATA   = "Early-Data";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_EXT          = "Ext";
/// Permanent.     RFC7239
enum MHD_HTTP_HEADER_FORWARDED    = "Forwarded";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_GETPROFILE   = "GetProfile";
/// Permanent.     RFC7486, Section 6.1.1
enum MHD_HTTP_HEADER_HOBAREG      = "Hobareg";
/// Permanent.     RFC7540, Section 3.2.1
enum MHD_HTTP_HEADER_HTTP2_SETTINGS = "HTTP2-Settings";
/// Permanent.     RFC4918
enum MHD_HTTP_HEADER_IF           = "If";
/// Permanent.     RFC6638
enum MHD_HTTP_HEADER_IF_SCHEDULE_TAG_MATCH = "If-Schedule-Tag-Match";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_IM           = "IM";
/// Permanent.     RFC8473
enum MHD_HTTP_HEADER_INCLUDE_REFERRED_TOKEN_BINDING_ID = "Include-Referred-Token-Binding-ID";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_KEEP_ALIVE   = "Keep-Alive";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_LABEL        = "Label";
/// Permanent.     https://html.spec.whatwg.org/multipage/server-sent-events.html#last-event-id
enum MHD_HTTP_HEADER_LAST_EVENT_ID = "Last-Event-ID";
/// Permanent.     RFC8288
enum MHD_HTTP_HEADER_LINK         = "Link";
/// Permanent.     RFC4918
enum MHD_HTTP_HEADER_LOCK_TOKEN   = "Lock-Token";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_MAN          = "Man";
/// Permanent.     RFC7089
enum MHD_HTTP_HEADER_MEMENTO_DATETIME = "Memento-Datetime";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_METER        = "Meter";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_NEGOTIATE    = "Negotiate";
/// Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign
enum MHD_HTTP_HEADER_ODATA_ENTITYID = "OData-EntityId";
/// Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign
enum MHD_HTTP_HEADER_ODATA_ISOLATION = "OData-Isolation";
/// Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign
enum MHD_HTTP_HEADER_ODATA_MAXVERSION = "OData-MaxVersion";
/// Permanent.     OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign
enum MHD_HTTP_HEADER_ODATA_VERSION = "OData-Version";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_OPT          = "Opt";
/// Permanent.     RFC8053, Section 3
enum MHD_HTTP_HEADER_OPTIONAL_WWW_AUTHENTICATE = "Optional-WWW-Authenticate";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_ORDERING_TYPE = "Ordering-Type";
/// Permanent.     RFC6454
enum MHD_HTTP_HEADER_ORIGIN       = "Origin";
/// Permanent.     https://html.spec.whatwg.org/multipage/origin.html#origin-agent-cluster
enum MHD_HTTP_HEADER_ORIGIN_AGENT_CLUSTER = "Origin-Agent-Cluster";
/// Permanent.     RFC8613, Section 11.1
enum MHD_HTTP_HEADER_OSCORE       = "OSCORE";
/// Permanent.     OASIS Project Specification 01; OASIS; Chet_Ensign
enum MHD_HTTP_HEADER_OSLC_CORE_VERSION = "OSLC-Core-Version";
/// Permanent.     RFC4918
enum MHD_HTTP_HEADER_OVERWRITE    = "Overwrite";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_P3P          = "P3P";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_PEP          = "PEP";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_PEP_INFO     = "Pep-Info";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_PICS_LABEL   = "PICS-Label";
/// Permanent.     https://html.spec.whatwg.org/multipage/links.html#ping-from
enum MHD_HTTP_HEADER_PING_FROM    = "Ping-From";
/// Permanent.     https://html.spec.whatwg.org/multipage/links.html#ping-to
enum MHD_HTTP_HEADER_PING_TO      = "Ping-To";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_POSITION     = "Position";
/// Permanent.     RFC7240
enum MHD_HTTP_HEADER_PREFER       = "Prefer";
/// Permanent.     RFC7240
enum MHD_HTTP_HEADER_PREFERENCE_APPLIED = "Preference-Applied";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_PROFILEOBJECT = "ProfileObject";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_PROTOCOL     = "Protocol";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_PROTOCOL_REQUEST = "Protocol-Request";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_PROXY_FEATURES = "Proxy-Features";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_PROXY_INSTRUCTION = "Proxy-Instruction";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_PUBLIC       = "Public";
/// Permanent.     RFC7469
enum MHD_HTTP_HEADER_PUBLIC_KEY_PINS = "Public-Key-Pins";
/// Permanent.     RFC7469
enum MHD_HTTP_HEADER_PUBLIC_KEY_PINS_REPORT_ONLY = "Public-Key-Pins-Report-Only";
/// Permanent.     RFC4437
enum MHD_HTTP_HEADER_REDIRECT_REF = "Redirect-Ref";
/// Permanent.     https://html.spec.whatwg.org/multipage/browsing-the-web.html#refresh
enum MHD_HTTP_HEADER_REFRESH      = "Refresh";
/// Permanent.     RFC8555, Section 6.5.1
enum MHD_HTTP_HEADER_REPLAY_NONCE = "Replay-Nonce";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_SAFE         = "Safe";
/// Permanent.     RFC6638
enum MHD_HTTP_HEADER_SCHEDULE_REPLY = "Schedule-Reply";
/// Permanent.     RFC6638
enum MHD_HTTP_HEADER_SCHEDULE_TAG = "Schedule-Tag";
/// Permanent.     RFC8473
enum MHD_HTTP_HEADER_SEC_TOKEN_BINDING = "Sec-Token-Binding";
/// Permanent.     RFC6455
enum MHD_HTTP_HEADER_SEC_WEBSOCKET_ACCEPT = "Sec-WebSocket-Accept";
/// Permanent.     RFC6455
enum MHD_HTTP_HEADER_SEC_WEBSOCKET_EXTENSIONS = "Sec-WebSocket-Extensions";
/// Permanent.     RFC6455
enum MHD_HTTP_HEADER_SEC_WEBSOCKET_KEY = "Sec-WebSocket-Key";
/// Permanent.     RFC6455
enum MHD_HTTP_HEADER_SEC_WEBSOCKET_PROTOCOL = "Sec-WebSocket-Protocol";
/// Permanent.     RFC6455
enum MHD_HTTP_HEADER_SEC_WEBSOCKET_VERSION = "Sec-WebSocket-Version";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_SECURITY_SCHEME = "Security-Scheme";
/// Permanent.     https://www.w3.org/TR/server-timing/
enum MHD_HTTP_HEADER_SERVER_TIMING = "Server-Timing";
/// Permanent.     RFC6265
enum MHD_HTTP_HEADER_SET_COOKIE   = "Set-Cookie";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_SETPROFILE   = "SetProfile";
/// Permanent.     RFC5023
enum MHD_HTTP_HEADER_SLUG         = "SLUG";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_SOAPACTION   = "SoapAction";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_STATUS_URI   = "Status-URI";
/// Permanent.     RFC6797
enum MHD_HTTP_HEADER_STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security";
/// Permanent.     RFC8594
enum MHD_HTTP_HEADER_SUNSET       = "Sunset";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_SURROGATE_CAPABILITY = "Surrogate-Capability";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_SURROGATE_CONTROL = "Surrogate-Control";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_TCN          = "TCN";
/// Permanent.     RFC4918
enum MHD_HTTP_HEADER_TIMEOUT      = "Timeout";
/// Permanent.     RFC8030, Section 5.4
enum MHD_HTTP_HEADER_TOPIC        = "Topic";
/// Permanent.     RFC8030, Section 5.2
enum MHD_HTTP_HEADER_TTL          = "TTL";
/// Permanent.     RFC8030, Section 5.3
enum MHD_HTTP_HEADER_URGENCY      = "Urgency";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_URI          = "URI";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_VARIANT_VARY = "Variant-Vary";
/// Permanent.     RFC4229
enum MHD_HTTP_HEADER_WANT_DIGEST  = "Want-Digest";
/// Permanent.     https://fetch.spec.whatwg.org/#x-content-type-options-header
enum MHD_HTTP_HEADER_X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options";
/// Permanent.     https://html.spec.whatwg.org/multipage/browsing-the-web.html#x-frame-options
enum MHD_HTTP_HEADER_X_FRAME_OPTIONS = "X-Frame-Options";
/// Provisional.   RFC5789
enum MHD_HTTP_HEADER_ACCEPT_PATCH = "Accept-Patch";
/// Provisional.   https://github.com/ampproject/amphtml/blob/master/spec/amp-cache-transform.md
enum MHD_HTTP_HEADER_AMP_CACHE_TRANSFORM = "AMP-Cache-Transform";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_COMPLIANCE   = "Compliance";
/// Provisional.   https://docs.oasis-open-projects.org/oslc-op/config/v1.0/psd01/config-resources.html#configcontext
enum MHD_HTTP_HEADER_CONFIGURATION_CONTEXT = "Configuration-Context";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_COST         = "Cost";
/// Provisional.   RFC6017
enum MHD_HTTP_HEADER_EDIINT_FEATURES = "EDIINT-Features";
/// Provisional.   OData Version 4.01 Part 1: Protocol; OASIS; Chet_Ensign
enum MHD_HTTP_HEADER_ISOLATION    = "Isolation";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_MESSAGE_ID   = "Message-ID";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_NON_COMPLIANCE = "Non-Compliance";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_OPTIONAL     = "Optional";
/// Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign
enum MHD_HTTP_HEADER_REPEATABILITY_CLIENT_ID = "Repeatability-Client-ID";
/// Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign
enum MHD_HTTP_HEADER_REPEATABILITY_FIRST_SENT = "Repeatability-First-Sent";
/// Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign
enum MHD_HTTP_HEADER_REPEATABILITY_REQUEST_ID = "Repeatability-Request-ID";
/// Provisional.   Repeatable Requests Version 1.0; OASIS; Chet_Ensign
enum MHD_HTTP_HEADER_REPEATABILITY_RESULT = "Repeatability-Result";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_RESOLUTION_HINT = "Resolution-Hint";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_RESOLVER_LOCATION = "Resolver-Location";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_SUBOK        = "SubOK";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_SUBST        = "Subst";
/// Provisional.   https://www.w3.org/TR/resource-timing-1/#timing-allow-origin
enum MHD_HTTP_HEADER_TIMING_ALLOW_ORIGIN = "Timing-Allow-Origin";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_TITLE        = "Title";
/// Provisional.   https://www.w3.org/TR/trace-context/#traceparent-field
enum MHD_HTTP_HEADER_TRACEPARENT  = "Traceparent";
/// Provisional.   https://www.w3.org/TR/trace-context/#tracestate-field
enum MHD_HTTP_HEADER_TRACESTATE   = "Tracestate";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_UA_COLOR     = "UA-Color";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_UA_MEDIA     = "UA-Media";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_UA_PIXELS    = "UA-Pixels";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_UA_RESOLUTION = "UA-Resolution";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_UA_WINDOWPIXELS = "UA-Windowpixels";
/// Provisional.   RFC4229
enum MHD_HTTP_HEADER_VERSION      = "Version";
/// Provisional.   W3C Mobile Web Best Practices Working Group
enum MHD_HTTP_HEADER_X_DEVICE_ACCEPT = "X-Device-Accept";
/// Provisional.   W3C Mobile Web Best Practices Working Group
enum MHD_HTTP_HEADER_X_DEVICE_ACCEPT_CHARSET = "X-Device-Accept-Charset";
/// Provisional.   W3C Mobile Web Best Practices Working Group
enum MHD_HTTP_HEADER_X_DEVICE_ACCEPT_ENCODING = "X-Device-Accept-Encoding";
/// Provisional.   W3C Mobile Web Best Practices Working Group
enum MHD_HTTP_HEADER_X_DEVICE_ACCEPT_LANGUAGE = "X-Device-Accept-Language";
/// Provisional.   W3C Mobile Web Best Practices Working Group
enum MHD_HTTP_HEADER_X_DEVICE_USER_AGENT = "X-Device-User-Agent";
/// Deprecated.    RFC4229
enum MHD_HTTP_HEADER_C_PEP_INFO   = "C-PEP-Info";
/// Deprecated.    RFC4229
enum MHD_HTTP_HEADER_PROTOCOL_INFO = "Protocol-Info";
/// Deprecated.    RFC4229
enum MHD_HTTP_HEADER_PROTOCOL_QUERY = "Protocol-Query";
/// Obsoleted.     https://www.w3.org/TR/2007/WD-access-control-20071126/#access-control0
enum MHD_HTTP_HEADER_ACCESS_CONTROL = "Access-Control";
/// Obsoleted.     RFC2068; RFC2616
enum MHD_HTTP_HEADER_CONTENT_BASE = "Content-Base";
/// Obsoleted.     RFC2616, Section 14.15; RFC7231, Appendix B
enum MHD_HTTP_HEADER_CONTENT_MD5  = "Content-MD5";
/// Obsoleted.     RFC2965; RFC6265
enum MHD_HTTP_HEADER_COOKIE2      = "Cookie2";
/// Obsoleted.     https://www.w3.org/TR/2007/WD-access-control-20071126/#method-check
enum MHD_HTTP_HEADER_METHOD_CHECK = "Method-Check";
/// Obsoleted.     https://www.w3.org/TR/2007/WD-access-control-20071126/#method-check-expires
enum MHD_HTTP_HEADER_METHOD_CHECK_EXPIRES = "Method-Check-Expires";
/// Obsoleted.     https://www.w3.org/TR/2007/WD-access-control-20071126/#referer-root
enum MHD_HTTP_HEADER_REFERER_ROOT = "Referer-Root";
/// Obsoleted.     RFC2965; RFC6265
enum MHD_HTTP_HEADER_SET_COOKIE2  = "Set-Cookie2";

/*
 * @defgroup versions HTTP versions
 * These strings should be used to match against the first line of the
 * HTTP header.
 * @{
 */
enum MHD_HTTP_VERSION_1_0 = "HTTP/1.0";
enum MHD_HTTP_VERSION_1_1 = "HTTP/1.1";

/*
 * @defgroup methods HTTP methods
 * HTTP methods (as strings).
 * See_Also: http://www.iana.org/assignments/http-methods/http-methods.xml
 * Registry export date: 2021-12-19
 * @{
 */

/// Main HTTP methods.
/// Not safe. Not idempotent. RFC-ietf-httpbis-semantics, Section 9.3.6.
enum MHD_HTTP_METHOD_CONNECT  = "CONNECT";
/// Not safe. Idempotent.     RFC-ietf-httpbis-semantics, Section 9.3.5.
enum MHD_HTTP_METHOD_DELETE   = "DELETE";
/// Safe.     Idempotent.     RFC-ietf-httpbis-semantics, Section 9.3.1.
enum MHD_HTTP_METHOD_GET      = "GET";
/// Safe.     Idempotent.     RFC-ietf-httpbis-semantics, Section 9.3.2.
enum MHD_HTTP_METHOD_HEAD     = "HEAD";
/// Safe.     Idempotent.     RFC-ietf-httpbis-semantics, Section 9.3.7.
enum MHD_HTTP_METHOD_OPTIONS  = "OPTIONS";
/// Not safe. Not idempotent. RFC-ietf-httpbis-semantics, Section 9.3.3.
enum MHD_HTTP_METHOD_POST     = "POST";
/// Not safe. Idempotent.     RFC-ietf-httpbis-semantics, Section 9.3.4.
enum MHD_HTTP_METHOD_PUT      = "PUT";
/// Safe.     Idempotent.     RFC-ietf-httpbis-semantics, Section 9.3.8.
enum MHD_HTTP_METHOD_TRACE    = "TRACE";
/// Not safe. Not idempotent. RFC-ietf-httpbis-semantics, Section 18.2.
enum MHD_HTTP_METHOD_ASTERISK=  "*";

/// Additional HTTP methods.
/// Not safe. Idempotent.     RFC3744, Section 8.1.
enum MHD_HTTP_METHOD_ACL            = "ACL";
/// Not safe. Idempotent.     RFC3253, Section 12.6.
enum MHD_HTTP_METHOD_BASELINE_CONTROL = "BASELINE-CONTROL";
/// Not safe. Idempotent.     RFC5842, Section 4.
enum MHD_HTTP_METHOD_BIND           = "BIND";
/// Not safe. Idempotent.     RFC3253, Section 4.4, Section 9.4.
enum MHD_HTTP_METHOD_CHECKIN        = "CHECKIN";
/// Not safe. Idempotent.     RFC3253, Section 4.3, Section 8.8.
enum MHD_HTTP_METHOD_CHECKOUT       = "CHECKOUT";
/// Not safe. Idempotent.     RFC4918, Section 9.8.
enum MHD_HTTP_METHOD_COPY           = "COPY";
/// Not safe. Idempotent.     RFC3253, Section 8.2.
enum MHD_HTTP_METHOD_LABEL          = "LABEL";
/// Not safe. Idempotent.     RFC2068, Section 19.6.1.2.
enum MHD_HTTP_METHOD_LINK           = "LINK";
/// Not safe. Not idempotent. RFC4918, Section 9.10.
enum MHD_HTTP_METHOD_LOCK           = "LOCK";
/// Not safe. Idempotent.     RFC3253, Section 11.2.
enum MHD_HTTP_METHOD_MERGE          = "MERGE";
/// Not safe. Idempotent.     RFC3253, Section 13.5.
enum MHD_HTTP_METHOD_MKACTIVITY     = "MKACTIVITY";
/// Not safe. Idempotent.     RFC4791, Section 5.3.1; RFC8144, Section 2.3.
enum MHD_HTTP_METHOD_MKCALENDAR     = "MKCALENDAR";
/// Not safe. Idempotent.     RFC4918, Section 9.3; RFC5689, Section 3; RFC8144, Section 2.3.
enum MHD_HTTP_METHOD_MKCOL          = "MKCOL";
/// Not safe. Idempotent.     RFC4437, Section 6.
enum MHD_HTTP_METHOD_MKREDIRECTREF  = "MKREDIRECTREF";
/// Not safe. Idempotent.     RFC3253, Section 6.3.
enum MHD_HTTP_METHOD_MKWORKSPACE    = "MKWORKSPACE";
/// Not safe. Idempotent.     RFC4918, Section 9.9.
enum MHD_HTTP_METHOD_MOVE           = "MOVE";
/// Not safe. Idempotent.     RFC3648, Section 7.
enum MHD_HTTP_METHOD_ORDERPATCH     = "ORDERPATCH";
/// Not safe. Not idempotent. RFC5789, Section 2.
enum MHD_HTTP_METHOD_PATCH          = "PATCH";
/// Safe.     Idempotent.     RFC7540, Section 3.5.
enum MHD_HTTP_METHOD_PRI            = "PRI";
/// Safe.     Idempotent.     RFC4918, Section 9.1; RFC8144, Section 2.1.
enum MHD_HTTP_METHOD_PROPFIND       = "PROPFIND";
/// Not safe. Idempotent.     RFC4918, Section 9.2; RFC8144, Section 2.2.
enum MHD_HTTP_METHOD_PROPPATCH      = "PROPPATCH";
/// Not safe. Idempotent.     RFC5842, Section 6.
enum MHD_HTTP_METHOD_REBIND         = "REBIND";
/// Safe.     Idempotent.     RFC3253, Section 3.6; RFC8144, Section 2.1.
enum MHD_HTTP_METHOD_REPORT         = "REPORT";
/// Safe.     Idempotent.     RFC5323, Section 2.
enum MHD_HTTP_METHOD_SEARCH         = "SEARCH";
/// Not safe. Idempotent.     RFC5842, Section 5.
enum MHD_HTTP_METHOD_UNBIND         = "UNBIND";
/// Not safe. Idempotent.     RFC3253, Section 4.5.
enum MHD_HTTP_METHOD_UNCHECKOUT     = "UNCHECKOUT";
/// Not safe. Idempotent.     RFC2068, Section 19.6.1.3.
enum MHD_HTTP_METHOD_UNLINK         = "UNLINK";
/// Not safe. Idempotent.     RFC4918, Section 9.11.
enum MHD_HTTP_METHOD_UNLOCK         = "UNLOCK";
/// Not safe. Idempotent.     RFC3253, Section 7.1.
enum MHD_HTTP_METHOD_UPDATE         = "UPDATE";
/// Not safe. Idempotent.     RFC4437, Section 7.
enum MHD_HTTP_METHOD_UPDATEREDIRECTREF = "UPDATEREDIRECTREF";
/// Not safe. Idempotent.     RFC3253, Section 3.5.
enum MHD_HTTP_METHOD_VERSION_CONTROL = "VERSION-CONTROL";

/*
 * @defgroup postenc HTTP POST encodings
 * See also: http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4
 * @{
 */
enum MHD_HTTP_POST_ENCODING_FORM_URLENCODED = "application/x-www-form-urlencoded";
enum MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA = "multipart/form-data";

/**
 * @brief Handle for the daemon (listening on a socket for HTTP traffic).
 * Ingroup: event
 */
struct MHD_Daemon;

/**
 * @brief Handle for a connection / HTTP request.
 *
 * With HTTP/1.1, multiple requests can be run over the same
 * connection.  However, MHD will only show one request per TCP
 * connection to the client at any given time.
 * Ingroup: request
 */
struct MHD_Connection;

/**
 * @brief Handle for a response.
 * Ingroup: response
 */
struct MHD_Response;

/**
 * @brief Handle for POST processing.
 * Ingroup: response
 */
struct MHD_PostProcessor;


/*
 * @brief Flags for the `struct MHD_Daemon`.
 *
 * Note that MHD will run automatically in background thread(s) only
 * if `MHD_USE_INTERNAL_POLLING_THREAD` is used. Otherwise caller (application)
 * must use `MHD_run()` or `MHD_run_from_select()` to have MHD processed
 * network connections and data.
 *
 * Starting the daemon may also fail if a particular option is not
 * implemented or not supported on the target platform (i.e. no
 * support for TLS, epoll or IPv6).
 */
alias MHD_FLAG = int;
enum : MHD_FLAG
{
  /**
   * No options selected.
   */
  MHD_NO_FLAG = 0,

  /**
   * Print errors messages to custom error logger or to `stderr` if
   * custom error logger is not set.
   * See_Also: ::MHD_OPTION_EXTERNAL_LOGGER
   */
  MHD_USE_ERROR_LOG = 1,

  /**
   * Run in debug mode.  If this flag is used, the library should
   * print error messages and warnings to `stderr`.
   */
  MHD_USE_DEBUG = 1,

  /**
   * Run in HTTPS mode.  The modern protocol is called TLS.
   */
  MHD_USE_TLS = 2,
  
  /**
   * Run using one thread per connection.
   * Must be used only with `MHD_USE_INTERNAL_POLLING_THREAD`.
   *
   * If `MHD_USE_ITC` is also not used, closed and expired connections may only
   * be cleaned up internally when a new connection is received.
   * Consider adding of `MHD_USE_ITC` flag to have faster internal cleanups
   * at very minor increase in system resources usage.
   */
  MHD_USE_THREAD_PER_CONNECTION = 4,

  /**
   * Run using an internal thread (or thread pool) for sockets sending
   * and receiving and data processing. Without this flag MHD will not
   * run automatically in background thread(s).
   * If this flag is set, `MHD_run()` and `MHD_run_from_select()` couldn't
   * be used.
   * This flag is set explicitly by `MHD_USE_POLL_INTERNAL_THREAD` and
   * by `MHD_USE_EPOLL_INTERNAL_THREAD`.
   * When this flag is not set, MHD run in "external" polling mode.
   */
  MHD_USE_INTERNAL_POLLING_THREAD = 8,

  //deprecated("Value MHD_USE_SELECT_INTERNALLY is deprecated, use MHD_USE_INTERNAL_POLLING_THREAD instead")
  MHD_USE_SELECT_INTERNALLY = 8,

  /**
   * Run using the IPv6 protocol (otherwise, MHD will just support
   * IPv4).  If you want MHD to support IPv4 and IPv6 using a single
   * socket, pass `MHD_USE_DUAL_STACK`, otherwise, if you only pass
   * this option, MHD will try to bind to IPv6-only (resulting in
   * no IPv4 support).
   */
  MHD_USE_IPv6 = 16,
  
  /**
   * Use `poll()` instead of `select()` for polling sockets.
   * This allows sockets with `fd >= FD_SETSIZE`.
   * This option is not compatible with an "external" polling mode
   * (as there is no API to get the file descriptors for the external
   * poll() from MHD) and must also not be used in combination
   * with `MHD_USE_EPOLL`.
   * See_Also: ::MHD_FEATURE_POLL, `MHD_USE_POLL_INTERNAL_THREAD`
   */
  MHD_USE_POLL = 64,

  /**
   * Run using an internal thread (or thread pool) doing `poll()`.
   * See_Also: ::MHD_FEATURE_POLL, `MHD_USE_POLL`, `MHD_USE_INTERNAL_POLLING_THREAD`
   */
  MHD_USE_POLL_INTERNAL_THREAD = MHD_USE_POLL | MHD_USE_INTERNAL_POLLING_THREAD,
  
  /**
   * Suppress (automatically) adding the 'Date:' header to HTTP responses.
   * This option should ONLY be used on systems that do not have a clock
   * and that DO provide other mechanisms for cache control.  See also
   * RFC 2616, section 14.18 (exception 3).
   */
  MHD_USE_SUPPRESS_DATE_NO_CLOCK = 128,
  
  /**
   * Run without a listen socket.  This option only makes sense if
   * `MHD_add_connection` is to be used exclusively to connect HTTP
   * clients to the HTTP server.  This option is incompatible with
   * using a thread pool; if it is used, `MHD_OPTION_THREAD_POOL_SIZE`
   * is ignored.
   */
  MHD_USE_NO_LISTEN_SOCKET = 256,

  /**
   * Use `epoll()` instead of `select()` or `poll()` for the event loop.
   * This option is only available on some systems; using the option on
   * systems without epoll will cause `MHD_start_daemon` to fail.  Using
   * this option is not supported with `MHD_USE_THREAD_PER_CONNECTION`.
   * See_Also: ::MHD_FEATURE_EPOLL
   */
  MHD_USE_EPOLL = 512,
  
  /**
   * Run using an internal thread (or thread pool) doing `epoll` polling.
   * This option is only available on certain platforms; using the option on
   * platform without `epoll` support will cause `MHD_start_daemon` to fail.
   * See_Also: ::MHD_FEATURE_EPOLL, `MHD_USE_EPOLL`, `MHD_USE_INTERNAL_POLLING_THREAD`
   */
  MHD_USE_EPOLL_INTERNAL_THREAD = MHD_USE_EPOLL | MHD_USE_INTERNAL_POLLING_THREAD,
  
  /**
   * Use inter-thread communication channel.
   * `MHD_USE_ITC` can be used with `MHD_USE_INTERNAL_POLLING_THREAD`
   * and is ignored with any "external" sockets polling.
   * It's required for use of `MHD_quiesce_daemon`
   * or `MHD_add_connection`.
   * This option is enforced by `MHD_ALLOW_SUSPEND_RESUME` or
   * `MHD_USE_NO_LISTEN_SOCKET`.
   * `MHD_USE_ITC` is always used automatically on platforms
   * where select()/poll()/other ignore shutdown of listen
   * socket.
   */
  MHD_USE_ITC = 1024,
  
  /**
   * Use a single socket for IPv4 and IPv6.
   */
  MHD_USE_DUAL_STACK = MHD_USE_IPv6 | 2048,

  /**
   * Enable `turbo`.  Disables certain calls to `shutdown()`,
   * enables aggressive non-blocking optimistic reads and
   * other potentially unsafe optimizations.
   * Most effects only happen with `MHD_USE_EPOLL`.
   */
  MHD_USE_TURBO = 4096,
  
  /**
   * Enable suspend/resume functions, which also implies setting up
   * ITC to signal resume.
   */
  MHD_ALLOW_SUSPEND_RESUME = 8192 | MHD_USE_ITC,
  
  /**
   * Enable TCP_FASTOPEN option.  This option is only available on Linux with a
   * kernel >= 3.6.  On other systems, using this option cases `MHD_start_daemon`
   * to fail.
   */
  MHD_USE_TCP_FASTOPEN = 16384,

  /**
   * You need to set this option if you want to use HTTP "Upgrade".
   * "Upgrade" may require usage of additional internal resources,
   * which we do not want to use unless necessary.
   */
  MHD_ALLOW_UPGRADE = 32768,

  /**
   * Automatically use best available polling function.
   * Choice of polling function is also depend on other daemon options.
   * If `MHD_USE_INTERNAL_POLLING_THREAD` is specified then epoll, poll() or
   * select() will be used (listed in decreasing preference order, first
   * function available on system will be used).
   * If `MHD_USE_THREAD_PER_CONNECTION` is specified then poll() or select()
   * will be used.
   * If those flags are not specified then epoll or select() will be
   * used (as the only suitable for MHD_get_fdset())
   */
  MHD_USE_AUTO = 65536,

  /**
   * Run using an internal thread (or thread pool) with best available on
   * system polling function.
   * This is combination of `MHD_USE_AUTO` and `MHD_USE_INTERNAL_POLLING_THREAD`
   * flags.
   */
  MHD_USE_AUTO_INTERNAL_THREAD = MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD,

  /**
   * Flag set to enable post-handshake client authentication
   * (only useful in combination with `MHD_USE_TLS`).
   */
  MHD_USE_POST_HANDSHAKE_AUTH_SUPPORT = 1u << 17,

  /**
   * Flag set to enable TLS 1.3 early data.  This has
   * security implications, be VERY careful when using this.
   */
  MHD_USE_INSECURE_TLS_EARLY_DATA = 1u << 18
}
deprecated("Value MHD_USE_SUSPEND_RESUME is deprecated, use MHD_ALLOW_SUSPEND_RESUME instead")
enum MHD_FLAG MHD_USE_SUSPEND_RESUME = 8192 | MHD_USE_ITC;
deprecated("Value MHD_USE_EPOLL_TURBO is deprecated, use MHD_USE_TURBO")
enum MHD_FLAG MHD_USE_EPOLL_TURBO = 4096;
deprecated("Value MHD_USE_PIPE_FOR_SHUTDOWN is deprecated, use MHD_USE_ITC")
enum MHD_FLAG MHD_USE_PIPE_FOR_SHUTDOWN = 1024;
deprecated("Value MHD_USE_EPOLL_INTERNALLY is deprecated, use MHD_USE_EPOLL_INTERNAL_THREAD")
enum MHD_FLAG MHD_USE_EPOLL_INTERNALLY = MHD_USE_EPOLL | MHD_USE_INTERNAL_POLLING_THREAD;
deprecated("Value MHD_USE_EPOLL_INTERNALLY_LINUX_ONLY is deprecated, use MHD_USE_EPOLL_INTERNAL_THREAD")
enum MHD_FLAG MHD_USE_EPOLL_INTERNALLY_LINUX_ONLY = MHD_USE_EPOLL | MHD_USE_INTERNAL_POLLING_THREAD;
deprecated("Value MHD_USE_EPOLL_LINUX_ONLY is deprecated, use MHD_USE_EPOLL")
enum MHD_FLAG MHD_USE_EPOLL_LINUX_ONLY = 512;
deprecated("Value MHD_SUPPRESS_DATE_NO_CLOCK is deprecated, use MHD_USE_SUPPRESS_DATE_NO_CLOCK instead")
enum MHD_FLAG MHD_SUPPRESS_DATE_NO_CLOCK = 128;
deprecated("Value MHD_USE_POLL_INTERNALLY is deprecated, use MHD_USE_POLL_INTERNAL_THREAD instead")
enum MHD_FLAG MHD_USE_POLL_INTERNALLY = MHD_USE_POLL | MHD_USE_INTERNAL_POLLING_THREAD;
deprecated("Flag MHD_USE_PEDANTIC_CHECKS is deprecated, use option MHD_OPTION_STRICT_FOR_CLIENT instead")
enum MHD_FLAG MHD_USE_PEDANTIC_CHECKS = 32;
deprecated("Value MHD_USE_SSL is deprecated, use MHD_USE_TLS")
enum MHD_FLAG MHD_USE_SSL = 2;

/**
 * Type of a callback function used for logging by MHD.
 *
 * Param: cls = closure
 * Param: fm = format string (`printf()`-style)
 * Param: ap = arguments to @a fm
 * Ingroup: logging
 */
alias MHD_LogCallback = void function(void *cls, const(char) *fm, va_list ap);
//typedef void (*MHD_LogCallback)(void *cls, const char *fm, va_list ap);

/**
 * Function called to lookup the pre shared key (@a psk) for a given
 * HTTP connection based on the @a username.
 *
 * Param: cls = closure
 * Param: connection = the HTTPS connection
 * Param: username = the user name claimed by the other side
 * Param: psk = to be set to the pre-shared-key; should be allocated with malloc(),
 *        will be freed by MHD
 * Param: psk_size = to be set to the number of bytes in @a psk
 * 
 * Returns: 0 on success, -1 on errors
 */
alias MHD_PskServerCredentialsCallback = int function(
    void *cls, const(MHD_Connection) *connection,
    const(char) *username, void **psk, size_t *psk_size);
//typedef int (*MHD_PskServerCredentialsCallback)(
//    void *cls, const struct MHD_Connection *connection,
//    const char *username, void **psk, size_t *psk_size);

/**
 * Values for `MHD_OPTION_DIGEST_AUTH_NONCE_BIND_TYPE`.
 *
 * These values can limit the scope of validity of MHD-generated nonces.
 * Values can be combined with bitwise OR.
 * Any value, except `MHD_DAUTH_BIND_NONCE_NONE`, enforce function
 * `MHD_digest_auth_check3()` (and similar functions) to check nonce by
 * re-generating it again with the same parameters, which is CPU-intensive
 * operation.
 * Note: Available since `MHD_VERSION` 0x00097531
 */
alias MHD_DAuthBindNonce = int;
enum : MHD_DAuthBindNonce
{
  /**
   * Generated nonces are valid for any request from any client until expired.
   * This is default and recommended value.
   * `MHD_digest_auth_check3()` (and similar functions) would check only whether
   * the nonce value that is used by client has been generated by MHD and not
   * expired yet.
   * It is recommended because RFC 7616 allows clients to use the same nonce
   * for any request in the same "protection space".
   * CPU is loaded less when this value is used when checking client's
   * authorisation requests.
   * This mode gives MHD maximum flexibility for nonces generation and can
   * prevent possible nonce collisions (and corresponding log warning messages)
   * when clients' requests are intensive.
   * This value cannot be combined with other values.
   */
  MHD_DAUTH_BIND_NONCE_NONE = 0,

  /**
   * Generated nonces are valid only for the same realm.
   */
  MHD_DAUTH_BIND_NONCE_REALM = 1 << 0,

  /**
   * Generated nonces are valid only for the same URI (excluding parameters
   * after '?' in URI) and request method (GET, POST etc).
   * Not recommended unless "protection space" is limited to a single URI as
   * RFC 7616 allows clients to re-use server-generated nonces for any URI
   * in the same "protection space" which is by default consists of all server
   * URIs.
   * This was default (and only supported) nonce bind type
   * before `MHD_VERSION` 0x00097518
   */
  MHD_DAUTH_BIND_NONCE_URI = 1 << 1,

  /**
   * Generated nonces are valid only for the same URI including URI parameters
   * and request method (GET, POST etc).
   * This value implies `MHD_DAUTH_BIND_NONCE_URI`.
   * Not recommended for that same reasons as `MHD_DAUTH_BIND_NONCE_URI`.
   */
  MHD_DAUTH_BIND_NONCE_URI_PARAMS = 1 << 2,

  /**
   * Generated nonces are valid only for the single client's IP.
   * While it looks like security improvement, in practice the same client may
   * jump from one IP to another (mobile or Wi-Fi handover, DHCP re-assignment,
   * Multi-NAT, different proxy chain and other reasons), while IP address
   * spoofing could be used relatively easily.
   */
  MHD_DAUTH_BIND_NONCE_CLIENT_IP = 1 << 3
}

/**
 * @brief MHD options.
 *
 * Passed in the varargs portion of `MHD_start_daemon`.
 */
alias MHD_OPTION = int;
enum : MHD_OPTION
{

  /**
   * No more options / last option.  This is used
   * to terminate the VARARGs list.
   */
  MHD_OPTION_END = 0,

  /**
   * Maximum memory size per connection (followed by a `size_t`).
   * Default is 32 kb (`MHD_POOL_SIZE_DEFAULT`).
   * Values above 128k are unlikely to result in much benefit, as half
   * of the memory will be typically used for IO, and TCP buffers are
   * unlikely to support window sizes above 64k on most systems.
   */
  MHD_OPTION_CONNECTION_MEMORY_LIMIT = 1,

  /**
   * Maximum number of concurrent connections to
   * accept (followed by an `unsigned int`).
   */
  MHD_OPTION_CONNECTION_LIMIT = 2,

  /**
   * After how many seconds of inactivity should a
   * connection automatically be timed out? (followed
   * by an `unsigned int`; use zero for no timeout).
   * Values larger than (UINT64_MAX / 2000 - 1) will
   * be clipped to this number.
   */
  MHD_OPTION_CONNECTION_TIMEOUT = 3,

  /**
   * Register a function that should be called whenever a request has
   * been completed (this can be used for application-specific clean
   * up).  Requests that have never been presented to the application
   * (via `MHD_AccessHandlerCallback`) will not result in
   * notifications.
   *
   * This option should be followed by TWO pointers.  First a pointer
   * to a function of type `MHD_RequestCompletedCallback` and second a
   * pointer to a closure to pass to the request completed callback.
   * The second pointer may be NULL.
   */
  MHD_OPTION_NOTIFY_COMPLETED = 4,

  /**
   * Limit on the number of (concurrent) connections made to the
   * server from the same IP address.  Can be used to prevent one
   * IP from taking over all of the allowed connections.  If the
   * same IP tries to establish more than the specified number of
   * connections, they will be immediately rejected.  The option
   * should be followed by an `unsigned int`.  The default is
   * zero, which means no limit on the number of connections
   * from the same IP address.
   */
  MHD_OPTION_PER_IP_CONNECTION_LIMIT = 5,

  /**
   * Bind daemon to the supplied `struct sockaddr`. This option should
   * be followed by a `struct sockaddr *`.  If `MHD_USE_IPv6` is
   * specified, the `struct sockaddr*` should point to a `struct
   * sockaddr_in6`, otherwise to a `struct sockaddr_in`.
   */
  MHD_OPTION_SOCK_ADDR = 6,

  /**
   * Specify a function that should be called before parsing the URI from
   * the client.  The specified callback function can be used for processing
   * the URI (including the options) before it is parsed.  The URI after
   * parsing will no longer contain the options, which maybe inconvenient for
   * logging.  This option should be followed by two arguments, the first
   * one must be of the form
   *
   *     void * my_logger(void *cls, const char *uri, struct MHD_Connection *con)
   *
   * where the return value will be passed as
   * (`* req_cls`) in calls to the `MHD_AccessHandlerCallback`
   * when this request is processed later; returning a
   * value of NULL has no special significance (however,
   * note that if you return non-NULL, you can no longer
   * rely on the first call to the access handler having
   * `NULL == *req_cls` on entry;)
   * "cls" will be set to the second argument following
   * `MHD_OPTION_URI_LOG_CALLBACK`.  Finally, uri will
   * be the 0-terminated URI of the request.
   *
   * Note that during the time of this call, most of the connection's
   * state is not initialized (as we have not yet parsed the headers).
   * However, information about the connecting client (IP, socket)
   * is available.
   *
   * The specified function is called only once per request, therefore some
   * programmers may use it to instantiate their own request objects, freeing
   * them in the notifier `MHD_OPTION_NOTIFY_COMPLETED`.
   */
  MHD_OPTION_URI_LOG_CALLBACK = 7,

  /**
   * Memory pointer for the private key (key.pem) to be used by the
   * HTTPS daemon.  This option should be followed by a
   * `const char *` argument.
   * This should be used in conjunction with `MHD_OPTION_HTTPS_MEM_CERT`.
   */
  MHD_OPTION_HTTPS_MEM_KEY = 8,

  /**
   * Memory pointer for the certificate (cert.pem) to be used by the
   * HTTPS daemon.  This option should be followed by a
   * `const char *` argument.
   * This should be used in conjunction with `MHD_OPTION_HTTPS_MEM_KEY`.
   */
  MHD_OPTION_HTTPS_MEM_CERT = 9,

  /**
   * Daemon credentials type.
   * Followed by an argument of type
   * `gnutls_credentials_type_t`.
   */
  MHD_OPTION_HTTPS_CRED_TYPE = 10,

  /**
   * Memory pointer to a `const char *` specifying the GnuTLS priorities string.
   * If this options is not specified, then MHD will try the following strings:
   * * "@LIBMICROHTTPD" (application-specific system-wide configuration)
   * * "@SYSTEM"        (system-wide configuration)
   * * default GnuTLS priorities string
   * * "NORMAL"
   * The first configuration accepted by GnuTLS will be used.
   * For more details see GnuTLS documentation for "Application-specific
   * priority strings".
   */
  MHD_OPTION_HTTPS_PRIORITIES = 11,

  /**
   * Pass a listen socket for MHD to use (systemd-style).  If this
   * option is used, MHD will not open its own listen socket(s). The
   * argument passed must be of type `MHD_socket` and refer to an
   * existing socket that has been bound to a port and is listening.
   */
  MHD_OPTION_LISTEN_SOCKET = 12,

  /**
   * Use the given function for logging error messages.  This option
   * must be followed by two arguments; the first must be a pointer to
   * a function of type `MHD_LogCallback` and the second a pointer
   * `void *` which will be passed as the first argument to the log
   * callback.
   * Should be specified as the first option, otherwise some messages
   * may be printed by standard MHD logger during daemon startup.
   *
   * Note that MHD will not generate any log messages
   * if it was compiled without the "--enable-messages"
   * flag being set.
   */
  MHD_OPTION_EXTERNAL_LOGGER = 13,

  /**
   * Number (`unsigned int`) of threads in thread pool. Enable
   * thread pooling by setting this value to to something
   * greater than 1. Currently, thread mode must be
   * `MHD_USE_INTERNAL_POLLING_THREAD` if thread pooling is enabled
   * (`MHD_start_daemon` returns NULL for an unsupported thread
   * mode).
   */
  MHD_OPTION_THREAD_POOL_SIZE = 14,

  /**
   * Additional options given in an array of `struct MHD_OptionItem`.
   * The array must be terminated with an entry `{MHD_OPTION_END, 0, NULL}`.
   * An example for code using `MHD_OPTION_ARRAY` is:
   * ---
   *     struct MHD_OptionItem ops[] = {
   *       { MHD_OPTION_CONNECTION_LIMIT, 100, NULL },
   *       { MHD_OPTION_CONNECTION_TIMEOUT, 10, NULL },
   *       { MHD_OPTION_END, 0, NULL }
   *     };
   *     d = MHD_start_daemon (0, 8080, NULL, NULL, dh, NULL,
   *                           MHD_OPTION_ARRAY, ops,
   *                           MHD_OPTION_END);
   * ---
   * For options that expect a single pointer argument, the
   * second member of the `struct MHD_OptionItem` is ignored.
   * For options that expect two pointer arguments, the first
   * argument must be cast to `intptr_t`.
   */
  MHD_OPTION_ARRAY = 15,

  /**
   * Specify a function that should be called for unescaping escape
   * sequences in URIs and URI arguments.  Note that this function
   * will NOT be used by the `struct MHD_PostProcessor`.  If this
   * option is not specified, the default method will be used which
   * decodes escape sequences of the form "%HH".  This option should
   * be followed by two arguments, the first one must be of the form
   * ---
   *     size_t my_unescaper(void *cls,
   *                         struct MHD_Connection *c,
   *                         char *s)
   * ---
   * where the return value must be the length of the value left in
   * "s" (without the 0-terminator) and "s" should be updated.  Note
   * that the unescape function must not lengthen "s" (the result must
   * be shorter than the input and must still be 0-terminated).
   * However, it may also include binary zeros before the
   * 0-termination.  "cls" will be set to the second argument
   * following `MHD_OPTION_UNESCAPE_CALLBACK`.
   */
  MHD_OPTION_UNESCAPE_CALLBACK = 16,

  /**
   * Memory pointer for the random values to be used by the Digest
   * Auth module. This option should be followed by two arguments.
   * First an integer of type `size_t` which specifies the size
   * of the buffer pointed to by the second argument in bytes.
   * The recommended size is between 8 and 32. If size is four or less
   * then security could be lowered. Sizes more then 32 (or, probably
   * more than 16 - debatable) will not increase security.
   * Note that the application must ensure that the buffer of the
   * second argument remains allocated and unmodified while the
   * daemon is running.
   * See_Also: `MHD_OPTION_DIGEST_AUTH_RANDOM_COPY`
   */
  MHD_OPTION_DIGEST_AUTH_RANDOM = 17,

  /**
   * Size of the internal array holding the map of the nonce and
   * the nonce counter. This option should be followed by an `unsigend int`
   * argument.
   * The map size is 4 by default, which is enough to communicate with
   * a single client at any given moment of time, but not enough to
   * handle several clients simultaneously.
   * If Digest Auth is not used, this option can be set to zero to minimise
   * memory allocation.
   */
  MHD_OPTION_NONCE_NC_SIZE = 18,

  /**
   * Desired size of the stack for threads created by MHD. Followed
   * by an argument of type `size_t`.  Use 0 for system default.
   */
  MHD_OPTION_THREAD_STACK_SIZE = 19,

  /**
   * Memory pointer for the certificate (ca.pem) to be used by the
   * HTTPS daemon for client authentication.
   * This option should be followed by a `const char *` argument.
   */
  MHD_OPTION_HTTPS_MEM_TRUST = 20,

  /**
   * Increment to use for growing the read buffer (followed by a
   * `size_t`). Must fit within `MHD_OPTION_CONNECTION_MEMORY_LIMIT`.
   */
  MHD_OPTION_CONNECTION_MEMORY_INCREMENT = 21,

  /**
   * Use a callback to determine which X.509 certificate should be
   * used for a given HTTPS connection.  This option should be
   * followed by a argument of type `gnutls_certificate_retrieve_function2 *`.
   * This option provides an
   * alternative to `MHD_OPTION_HTTPS_MEM_KEY`,
   * `MHD_OPTION_HTTPS_MEM_CERT`.  You must use this version if
   * multiple domains are to be hosted at the same IP address using
   * TLS's Server Name Indication (SNI) extension.  In this case,
   * the callback is expected to select the correct certificate
   * based on the SNI information provided.  The callback is expected
   * to access the SNI data using `gnutls_server_name_get()`.
   * Using this option requires GnuTLS 3.0 or higher.
   */
  MHD_OPTION_HTTPS_CERT_CALLBACK = 22,

  /**
   * When using `MHD_USE_TCP_FASTOPEN`, this option changes the default TCP
   * fastopen queue length of 50.  Note that having a larger queue size can
   * cause resource exhaustion attack as the TCP stack has to now allocate
   * resources for the SYN packet along with its DATA.  This option should be
   * followed by an `unsigned int` argument.
   */
  MHD_OPTION_TCP_FASTOPEN_QUEUE_SIZE = 23,

  /**
   * Memory pointer for the Diffie-Hellman parameters (dh.pem) to be used by the
   * HTTPS daemon for key exchange.
   * This option must be followed by a `const char *` argument.
   */
  MHD_OPTION_HTTPS_MEM_DHPARAMS = 24,

  /**
   * If present and set to true, allow reusing address:port socket
   * (by using SO_REUSEPORT on most platform, or platform-specific ways).
   * If present and set to false, disallow reusing address:port socket
   * (does nothing on most platform, but uses SO_EXCLUSIVEADDRUSE on Windows).
   * This option must be followed by a `unsigned int` argument.
   */
  MHD_OPTION_LISTENING_ADDRESS_REUSE = 25,

  /**
   * Memory pointer for a password that decrypts the private key (key.pem)
   * to be used by the HTTPS daemon. This option should be followed by a
   * `const char *` argument.
   * This should be used in conjunction with `MHD_OPTION_HTTPS_MEM_KEY`.
   * See_Also: ::MHD_FEATURE_HTTPS_KEY_PASSWORD
   */
  MHD_OPTION_HTTPS_KEY_PASSWORD = 26,

  /**
   * Register a function that should be called whenever a connection is
   * started or closed.
   *
   * This option should be followed by TWO pointers.  First a pointer
   * to a function of type `MHD_NotifyConnectionCallback` and second a
   * pointer to a closure to pass to the request completed callback.
   * The second pointer may be NULL.
   */
  MHD_OPTION_NOTIFY_CONNECTION = 27,

  /**
   * Allow to change maximum length of the queue of pending connections on
   * listen socket. If not present than default platform-specific SOMAXCONN
   * value is used. This option should be followed by an `unsigned int`
   * argument.
   */
  MHD_OPTION_LISTEN_BACKLOG_SIZE = 28,

  /**
   * If set to 1 - be strict about the protocol.  Use -1 to be
   * as tolerant as possible.
   *
   * Specifically, at the moment, at 1 this flag
   * causes MHD to reject HTTP 1.1 connections without a "Host" header,
   * and to disallow spaces in the URL or (at -1) in HTTP header key strings.
   *
   * These are required by some versions of the standard, but of
   * course in violation of the "be as liberal as possible in what you
   * accept" norm.  It is recommended to set this to 1 if you are
   * testing clients against MHD, and 0 in production.  This option
   * should be followed by an `int` argument.
   */
  MHD_OPTION_STRICT_FOR_CLIENT = 29,

  /**
   * This should be a pointer to callback of type
   * gnutls_psk_server_credentials_function that will be given to
   * gnutls_psk_set_server_credentials_function. It is used to
   * retrieve the shared key for a given username.
   */
  MHD_OPTION_GNUTLS_PSK_CRED_HANDLER = 30,

  /**
   * Use a callback to determine which X.509 certificate should be
   * used for a given HTTPS connection.  This option should be
   * followed by a argument of type `gnutls_certificate_retrieve_function3 *`.
   * This option provides an
   * alternative/extension to `MHD_OPTION_HTTPS_CERT_CALLBACK`.
   * You must use this version if you want to use OCSP stapling.
   * Using this option requires GnuTLS 3.6.3 or higher.
   */
  MHD_OPTION_HTTPS_CERT_CALLBACK2 = 31,

  /**
   * Allows the application to disable certain sanity precautions
   * in MHD. With these, the client can break the HTTP protocol,
   * so this should never be used in production. The options are,
   * however, useful for testing HTTP clients against "broken"
   * server implementations.
   * This argument must be followed by an "unsigned int", corresponding
   * to an `enum MHD_DisableSanityCheck`.
   */
  MHD_OPTION_SERVER_INSANITY = 32,

  /**
   * If followed by value '1' informs MHD that SIGPIPE is suppressed or
   * handled by application. Allows MHD to use network functions that could
   * generate SIGPIPE, like `sendfile()`.
   * Valid only for daemons without `MHD_USE_INTERNAL_POLLING_THREAD` as
   * MHD automatically suppresses SIGPIPE for threads started by MHD.
   * This option should be followed by an `int` argument.
   * Note: Available since `MHD_VERSION` 0x00097205
   */
  MHD_OPTION_SIGPIPE_HANDLED_BY_APP = 33,

  /**
   * If followed by 'int' with value '1' disables usage of ALPN for TLS
   * connections even if supported by TLS library.
   * Valid only for daemons with `MHD_USE_TLS`.
   * This option should be followed by an `int` argument.
   * Note: Available since `MHD_VERSION` 0x00097207
   */
  MHD_OPTION_TLS_NO_ALPN = 34,

  /**
   * Memory pointer for the random values to be used by the Digest
   * Auth module. This option should be followed by two arguments.
   * First an integer of type `size_t` which specifies the size
   * of the buffer pointed to by the second argument in bytes.
   * The recommended size is between 8 and 32. If size is four or less
   * then security could be lowered. Sizes more then 32 (or, probably
   * more than 16 - debatable) will not increase security.
   * An internal copy of the buffer will be made, the data do not
   * need to be static.
   * See_Also: `MHD_OPTION_DIGEST_AUTH_RANDOM`
   * Note: Available since `MHD_VERSION` 0x00097529
   */
  MHD_OPTION_DIGEST_AUTH_RANDOM_COPY = 35,

  /**
   * Allow to controls the scope of validity of MHD-generated nonces.
   * This regulates how "nonces" are generated and how "nonces" are checked by
   * `MHD_digest_auth_check3()` and similar functions.
   * This option should be followed by an 'unsigned int` argument with value
   * formed as bitwise OR combination of `MHD_DAuthBindNonce` values.
   * When not specified, default value `MHD_DAUTH_BIND_NONCE_NONE` is used.
   * Note: Available since `MHD_VERSION` 0x00097531
   */
  MHD_OPTION_DIGEST_AUTH_NONCE_BIND_TYPE = 36,

  /**
   * Memory pointer to a `const char *` specifying the GnuTLS priorities to be
   * appended to default priorities.
   * This allow some specific options to be enabled/disabled, while leaving
   * the rest of the settings to their defaults.
   * The string does not have to start with a colon ':' character.
   * See `MHD_OPTION_HTTPS_PRIORITIES` description for details of automatic
   * default priorities.
   * Note: Available since `MHD_VERSION` 0x00097542
   */
  MHD_OPTION_HTTPS_PRIORITIES_APPEND = 37
}


/**
 * Bitfield for the `MHD_OPTION_SERVER_INSANITY` specifying
 * which santiy checks should be disabled.
 */
alias MHD_DisableSanityCheck = int;
enum : MHD_DisableSanityCheck
{
  /**
   * All sanity checks are enabled.
   */
  MHD_DSC_SANE = 0

}


/**
 * Entry in an `MHD_OPTION_ARRAY`.
 */
struct MHD_OptionItem
{
  /**
   * Which option is being given.  Use `MHD_OPTION_END`
   * to terminate the array.
   */
  MHD_OPTION option;

  /**
   * Option value (for integer arguments, and for options requiring
   * two pointer arguments); should be 0 for options that take no
   * arguments or only a single pointer argument.
   */
  intptr_t value;

  /**
   * Pointer option value (use NULL for options taking no arguments
   * or only an integer option).
   */
  void *ptr_value;

}


/**
 * The `enum MHD_ValueKind` specifies the source of
 * the key-value pairs in the HTTP protocol.
 */
alias MHD_ValueKind = int;
  /**
   * Response header
   * @deprecated
   */
deprecated("Value MHD_RESPONSE_HEADER_KIND is deprecated and not used")
enum MHD_RESPONSE_HEADER_KIND = 0;
enum : MHD_ValueKind
{
  /**
   * HTTP header (request/response).
   */
  MHD_HEADER_KIND = 1,

  /**
   * Cookies.  Note that the original HTTP header containing
   * the cookie(s) will still be available and intact.
   */
  MHD_COOKIE_KIND = 2,

  /**
   * POST data.  This is available only if a content encoding
   * supported by MHD is used (currently only URL encoding),
   * and only if the posted content fits within the available
   * memory pool.  Note that in that case, the upload data
   * given to the `MHD_AccessHandlerCallback` will be
   * empty (since it has already been processed).
   */
  MHD_POSTDATA_KIND = 4,

  /**
   * GET (URI) arguments.
   */
  MHD_GET_ARGUMENT_KIND = 8,

  /**
   * HTTP footer (only for HTTP 1.1 chunked encodings).
   */
  MHD_FOOTER_KIND = 16
}


/**
 * The `enum MHD_RequestTerminationCode` specifies reasons
 * why a request has been terminated (or completed).
 * Ingroup: request
 */
alias MHD_RequestTerminationCode = int;
enum : MHD_RequestTerminationCode
{

  /**
   * We finished sending the response.
   * Ingroup: request
   */
  MHD_REQUEST_TERMINATED_COMPLETED_OK = 0,

  /**
   * Error handling the connection (resources
   * exhausted, application error accepting request,
   * decrypt error (for HTTPS), connection died when
   * sending the response etc.)
   * Ingroup: request
   */
  MHD_REQUEST_TERMINATED_WITH_ERROR = 1,

  /**
   * No activity on the connection for the number
   * of seconds specified using
   * `MHD_OPTION_CONNECTION_TIMEOUT`.
   * Ingroup: request
   */
  MHD_REQUEST_TERMINATED_TIMEOUT_REACHED = 2,

  /**
   * We had to close the session since MHD was being
   * shut down.
   * Ingroup: request
   */
  MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN = 3,

  /**
   * We tried to read additional data, but the connection became broken or
   * the other side hard closed the connection.
   * This error is similar to `MHD_REQUEST_TERMINATED_WITH_ERROR`, but
   * specific to the case where the connection died before request completely
   * received.
   * Ingroup: request
   */
  MHD_REQUEST_TERMINATED_READ_ERROR = 4,

  /**
   * The client terminated the connection by closing the socket
   * for writing (TCP half-closed) while still sending request.
   * Ingroup: request
   */
  MHD_REQUEST_TERMINATED_CLIENT_ABORT = 5

}


/**
 * The `enum MHD_ConnectionNotificationCode` specifies types
 * of connection notifications.
 * Ingroup: request
 */
alias MHD_ConnectionNotificationCode = int;
enum : MHD_ConnectionNotificationCode
{

  /**
   * A new connection has been started.
   * Ingroup: request
   */
  MHD_CONNECTION_NOTIFY_STARTED = 0,

  /**
   * A connection is closed.
   * Ingroup: request
   */
  MHD_CONNECTION_NOTIFY_CLOSED = 1

}


/**
 * Information about a connection.
 */
union MHD_ConnectionInfo
{

  /**
   * Cipher algorithm used, of type "enum gnutls_cipher_algorithm".
   */
  int /* enum gnutls_cipher_algorithm */ cipher_algoritm;

  /**
   * Protocol used, of type "enum gnutls_protocol".
   */
  int /* enum gnutls_protocol */ protocol;

  /**
   * The suspended status of a connection.
   */
  int /* MHD_YES or MHD_NO */ suspended;

  /**
   * Amount of second that connection could spend in idle state
   * before automatically disconnected.
   * Zero for no timeout (unlimited idle time).
   */
  uint connection_timeout;

  /**
   * HTTP status queued with the response, for `MHD_CONNECTION_INFO_HTTP_STATUS`.
   */
  uint http_status;

  /**
   * Connect socket
   */
  MHD_socket connect_fd;

  /**
   * Size of the client's HTTP header.
   */
  size_t header_size;

  /**
   * GNUtls session handle, of type "gnutls_session_t".
   */
  void * /* gnutls_session_t */ tls_session;

  /**
   * GNUtls client certificate handle, of type "gnutls_x509_crt_t".
   */
  void * /* gnutls_x509_crt_t */ client_cert;

  /**
   * Address information for the client.
   */
  sockaddr *client_addr;

  /**
   * Which daemon manages this connection (useful in case there are many
   * daemons running).
   */
  MHD_Daemon *daemon;

  /**
   * Socket-specific client context.  Points to the same address as
   * the "socket_context" of the `MHD_NotifyConnectionCallback`.
   */
  void *socket_context;
}


/**
 * I/O vector type. Provided for use with `MHD_create_response_from_iovec()`.
 * Note: Available since `MHD_VERSION` 0x00097204
 */
struct MHD_IoVec
{
  /**
   * The pointer to the memory region for I/O.
   */
  const(void) *iov_base;

  /**
   * The size in bytes of the memory region for I/O.
   */
  size_t iov_len;
}


/**
 * Values of this enum are used to specify what
 * information about a connection is desired.
 * Ingroup: request
 */
alias MHD_ConnectionInfoType = int;
enum : MHD_ConnectionInfoType
{
  /**
   * What cipher algorithm is being used.
   * Takes no extra arguments.
   * Ingroup: request
   */
  MHD_CONNECTION_INFO_CIPHER_ALGO,

  /**
   *
   * Takes no extra arguments.
   * Ingroup: request
   */
  MHD_CONNECTION_INFO_PROTOCOL,

  /**
   * Obtain IP address of the client.  Takes no extra arguments.
   * Returns essentially a `struct sockaddr **` (since the API returns
   * a `union MHD_ConnectionInfo *` and that union contains a `struct
   * sockaddr *`).
   * Ingroup: request
   */
  MHD_CONNECTION_INFO_CLIENT_ADDRESS,

  /**
   * Get the gnuTLS session handle.
   * Ingroup: request
   */
  MHD_CONNECTION_INFO_GNUTLS_SESSION,

  /**
   * Get the gnuTLS client certificate handle.  Dysfunctional (never
   * implemented, deprecated).  Use `MHD_CONNECTION_INFO_GNUTLS_SESSION`
   * to get the `gnutls_session_t` and then call
   * gnutls_certificate_get_peers().
   */
  MHD_CONNECTION_INFO_GNUTLS_CLIENT_CERT,

  /**
   * Get the `struct MHD_Daemon *` responsible for managing this connection.
   * Ingroup: request
   */
  MHD_CONNECTION_INFO_DAEMON,

  /**
   * Request the file descriptor for the connection socket.
   * MHD sockets are always in non-blocking mode.
   * No extra arguments should be passed.
   * Ingroup: request
   */
  MHD_CONNECTION_INFO_CONNECTION_FD,

  /**
   * Returns the client-specific pointer to a `void *` that was (possibly)
   * set during a `MHD_NotifyConnectionCallback` when the socket was
   * first accepted.
   * Note that this is NOT the same as the "req_cls" argument of
   * the `MHD_AccessHandlerCallback`. The "req_cls" is fresh for each
   * HTTP request, while the "socket_context" is fresh for each socket.
   */
  MHD_CONNECTION_INFO_SOCKET_CONTEXT,

  /**
   * Check whether the connection is suspended.
   * Ingroup: request
   */
  MHD_CONNECTION_INFO_CONNECTION_SUSPENDED,

  /**
   * Get connection timeout
   * Ingroup: request
   */
  MHD_CONNECTION_INFO_CONNECTION_TIMEOUT,

  /**
   * Return length of the client's HTTP request header.
   * Ingroup: request
   */
  MHD_CONNECTION_INFO_REQUEST_HEADER_SIZE,

  /**
   * Return HTTP status queued with the response. NULL
   * if no HTTP response has been queued yet.
   */
  MHD_CONNECTION_INFO_HTTP_STATUS

}


/**
 * Values of this enum are used to specify what
 * information about a daemon is desired.
 */
alias MHD_DaemonInfoType = int;
enum : MHD_DaemonInfoType
{
  /**
   * No longer supported (will return NULL).
   */
  MHD_DAEMON_INFO_KEY_SIZE,

  /**
   * No longer supported (will return NULL).
   */
  MHD_DAEMON_INFO_MAC_KEY_SIZE,

  /**
   * Request the file descriptor for the listening socket.
   * No extra arguments should be passed.
   */
  MHD_DAEMON_INFO_LISTEN_FD,

  /**
   * Request the file descriptor for the "external" sockets polling
   * when 'epoll' mode is used.
   * No extra arguments should be passed.
   *
   * Waiting on epoll FD must not block longer than value
   * returned by `MHD_get_timeout()` otherwise connections
   * will "hung" with unprocessed data in network buffers
   * and timed-out connections will not be closed.
   *
   * See_Also: `MHD_get_timeout()`, `MHD_run()`
   */
  MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY,
  MHD_DAEMON_INFO_EPOLL_FD = MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY,

  /**
   * Request the number of current connections handled by the daemon.
   * No extra arguments should be passed.
   * Note: when using MHD in "external" polling mode, this type of request
   * could be used only when `MHD_run()`/`MHD_run_from_select` is not
   * working in other thread at the same time.
   */
  MHD_DAEMON_INFO_CURRENT_CONNECTIONS,

  /**
   * Request the daemon flags.
   * No extra arguments should be passed.
   * Note: flags may differ from original 'flags' specified for
   * daemon, especially if `MHD_USE_AUTO` was set.
   */
  MHD_DAEMON_INFO_FLAGS,

  /**
   * Request the port number of daemon's listen socket.
   * No extra arguments should be passed.
   * Note: if port '0' was specified for `MHD_start_daemon()`, returned
   * value will be real port number.
   */
  MHD_DAEMON_INFO_BIND_PORT
}


/**
 * Callback for serious error condition. The default action is to print
 * an error message and `abort()`.
 * 
 * Param: cls = user specified value
 * Param: file = where the error occurred, may be NULL if MHD was built without
 *             messages support
 * Param: line = where the error occurred
 * Param: reason = error detail, may be NULL
 * Ingroup: logging
 */
alias MHD_PanicCallback = void function(
    void *cls, const(char) *file, uint line, const(char) *reason);
/*typedef void
(*MHD_PanicCallback) (void *cls,
                      const char *file,
                      unsigned int line,
                      const char *reason);*/

/**
 * Allow or deny a client to connect.
 *
 * Param: cls = closure
 * Param: addr = address information from the client
 * Param: addrlen = length of @a addr
 * Returns: `MHD_YES` if connection is allowed, `MHD_NO` if not
 */
alias MHD_AcceptPolicyCallback = MHD_Result function(
    void *cls, const(sockaddr) *addr, socklen_t addrlen);
/*typedef enum MHD_Result (*MHD_AcceptPolicyCallback)(void *cls,
                            const struct sockaddr *addr, socklen_t addrlen);*/


/**
 * A client has requested the given @a url using the given @a method
 * (`MHD_HTTP_METHOD_GET`, `MHD_HTTP_METHOD_PUT`, `MHD_HTTP_METHOD_DELETE`,
 * `MHD_HTTP_METHOD_POST`, etc).
 *
 * The callback must call MHD function MHD_queue_response() to provide content
 * to give back to the client and return an HTTP status code (i.e.
 * `MHD_HTTP_OK`, `MHD_HTTP_NOT_FOUND`, etc.). The response can be created
 * in this callback or prepared in advance.
 * Alternatively, callback may call MHD_suspend_connection() to temporarily
 * suspend data processing for this connection.
 *
 * As soon as response is provided this callback will not be called anymore
 * for the current request.
 *
 * For each HTTP request this callback is called several times:
 * * after request headers are fully received and decoded,
 * * for each received part of request body (optional, if request has body),
 * * when request is fully received.
 *
 * If response is provided before request is fully received, the rest
 * of the request is discarded and connection is automatically closed
 * after sending response.
 *
 * If the request is fully received, but response hasn't been provided and
 * connection is not suspended, the callback can be called again immediately.
 *
 * The response cannot be queued when this callback is called to process
 * the client upload data (when @a upload_data is not NULL).
 *
 * Param: cls         = argument given together with the function
 *                pointer when the handler was registered with MHD
 * Param: connection  = the connection handle
 * Param: url         = the requested url
 * Param: method      = the HTTP method used (`MHD_HTTP_METHOD_GET`, `MHD_HTTP_METHOD_PUT`, etc.)
 * Param: version     = the HTTP version string (i.e. `MHD_HTTP_VERSION_1_1`)
 * Param: upload_data = the data being uploaded (excluding HEADERS,
 *                for a POST that fits into memory and that is encoded
 *                with a supported encoding, the POST data will NOT be
 *                given in upload_data and is instead available as
 *                part of `MHD_get_connection_values`; very large POST
 *                data *will* be made available incrementally in
 *                @a upload_data)
 * Param: upload_data_size = set initially to the size of the
 *                     @a upload_data provided; the method must update this
 *                     value to the number of bytes NOT processed;
 * Param: req_cls = pointer that the callback can set to some
 *            address and that will be preserved by MHD for future
 *            calls for this request; since the access handler may
 *            be called many times (i.e., for a PUT/POST operation
 *            with plenty of upload data) this allows the application
 *            to easily associate some request-specific state.
 *            If necessary, this state can be cleaned up in the
 *            global `MHD_RequestCompletedCallback` (which
 *            can be set with the `MHD_OPTION_NOTIFY_COMPLETED`).
 *            Initially, `*req_cls` will be NULL.
 * Returns: `MHD_YES` if the connection was handled successfully,
 *          `MHD_NO` if the socket must be closed due to a serious
 *          error while handling the request
 *
 * See_Also: `MHD_queue_response()`
 */
alias MHD_AccessHandlerCallback = MHD_Result function(
    void *cls,
    MHD_Connection *connection,
    const(char) *url,
    const(char) *method,
    const(char) *version_,
    const(char) *upload_data,
    size_t *upload_data_size,
    void **req_cls);
/*typedef enum MHD_Result
(*MHD_AccessHandlerCallback)(void *cls,
                             struct MHD_Connection *connection,
                             const char *url,
                             const char *method,
                             const char *version,
                             const char *upload_data,
                             size_t *upload_data_size,
                             void **req_cls);/


/**
 * Signature of the callback used by MHD to notify the
 * application about completed requests.
 *
 * Param: cls = client-defined closure
 * Param: connection = connection handle
 * Param: req_cls = value as set by the last call to
 *        the `MHD_AccessHandlerCallback`
 * Param: toe = reason for request termination
 * See_Also: `MHD_OPTION_NOTIFY_COMPLETED`
 * Ingroup: request
 */
alias MHD_RequestCompletedCallback = void function(
    void *cls,
    MHD_Connection *connection,
    void **req_cls,
    MHD_RequestTerminationCode toe);
/*typedef void (*MHD_RequestCompletedCallback) (void *cls,
                                 struct MHD_Connection *connection,
                                 void **req_cls,
                                 enum MHD_RequestTerminationCode toe);*/


/**
 * Signature of the callback used by MHD to notify the
 * application about started/stopped connections
 *
 * Param: cls = client-defined closure
 * Param: connection = connection handle
 * Param: socket_context = socket-specific pointer where the
 *                  client can associate some state specific
 *                  to the TCP connection; note that this is
 *                  different from the "req_cls" which is per
 *                  HTTP request.  The client can initialize
 *                  during `MHD_CONNECTION_NOTIFY_STARTED` and
 *                  cleanup during `MHD_CONNECTION_NOTIFY_CLOSED`
 *                  and access in the meantime using
 *                  `MHD_CONNECTION_INFO_SOCKET_CONTEXT`.
 * Param: toe = reason for connection notification
 * See_Also: `MHD_OPTION_NOTIFY_CONNECTION`
 * Ingroup: request
 */
alias MHD_NotifyConnectionCallback = void function(
    void *cls,
    MHD_Connection *connection,
    void **socket_context,
    MHD_ConnectionNotificationCode toe);
/*typedef void (*MHD_NotifyConnectionCallback) (void *cls,
                                 struct MHD_Connection *connection,
                                 void **socket_context,
                                 enum MHD_ConnectionNotificationCode toe);*/


/**
 * Iterator over key-value pairs.  This iterator
 * can be used to iterate over all of the cookies,
 * headers, or POST-data fields of a request, and
 * also to iterate over the headers that have been
 * added to a response.
 *
 * Param: cls = closure
 * Param: kind = kind of the header we are looking at
 * Param: key = key for the value, can be an empty string
 * Param: value = corresponding value, can be NULL
 * Return: `MHD_YES` to continue iterating,
 *         `MHD_NO` to abort the iteration
 * Ingroup: request
 */
alias MHD_KeyValueIterator = MHD_Result function(
    void *cls,
    MHD_ValueKind kind,
    const(char) *key,
    const(char) *value);
/*typedef enum MHD_Result (*MHD_KeyValueIterator)(void *cls,
                        enum MHD_ValueKind kind,
                        const char *key,
                        const char *value);*/


/**
 * Iterator over key-value pairs with size parameters.
 * This iterator can be used to iterate over all of
 * the cookies, headers, or POST-data fields of a
 * request, and also to iterate over the headers that
 * have been added to a response.
 * 
 * Note: Available since `MHD_VERSION` 0x00096303
 *
 * Param: cls = closure
 * Param: kind = kind of the header we are looking at
 * Param: key = key for the value, can be an empty string
 * Param: value = corresponding value, can be NULL
 * Param: value_size = number of bytes in @a value;
 *                   for C-strings, the length excludes the 0-terminator
 * Returns: `MHD_YES` to continue iterating,
 *         `MHD_NO` to abort the iteration
 * Ingroup: request
 */
alias MHD_KeyValueIteratorN = MHD_Result function(
    void *cls,
    MHD_ValueKind kind,
    const(char) *key,
    size_t key_size,
    const(char) *value,
    size_t value_size);
/*typedef enum MHD_Result (*MHD_KeyValueIteratorN)(void *cls,
                         enum MHD_ValueKind kind,
                         const char *key,
                         size_t key_size,
                         const char *value,
                         size_t value_size);*/


/**
 * Callback used by libmicrohttpd in order to obtain content.
 *
 * The callback is to copy at most @a max bytes of content into @a buf.
 * The total number of bytes that has been placed into @a buf should be
 * returned.
 *
 * Note that returning zero will cause libmicrohttpd to try again.
 * Thus, returning zero should only be used in conjunction
 * with `MHD_suspend_connection()` to avoid busy waiting.
 *
 * Param: cls = extra argument to the callback
 * Param: pos = position in the datastream to access;
 *        note that if a `struct MHD_Response` object is re-used,
 *        it is possible for the same content reader to
 *        be queried multiple times for the same data;
 *        however, if a `struct MHD_Response` is not re-used,
 *        libmicrohttpd guarantees that "pos" will be
 *        the sum of all non-negative return values
 *        obtained from the content reader so far.
 * Param: buf = where to copy the data
 * Param: max = maximum number of bytes to copy to @a buf (size of @a buf)
 * Returns: number of bytes written to @a buf;
 *  0 is legal unless MHD is started in "internal" sockets polling mode
 *    (since this would cause busy-waiting); 0 in "external" sockets
 *    polling mode will cause this function to be called again once
 *    any `MHD_run*()` function is called;
 *  `MHD_CONTENT_READER_END_OF_STREAM` (-1) for the regular
 *    end of transmission with chunked encoding, MHD will then
 *    terminate the chunk and send any HTTP footers that might be
 *    present; without chunked encoding and given an unknown
 *    response size, MHD will simply close the connection; note
 *    that while returning `MHD_CONTENT_READER_END_OF_STREAM` is not technically
 *    legal if a response size was specified, MHD accepts this
 *    and treats it just as `MHD_CONTENT_READER_END_WITH_ERROR`;
 *  `MHD_CONTENT_READER_END_WITH_ERROR` (-2) to indicate a server
 *    error generating the response; this will cause MHD to simply
 *    close the connection immediately.  If a response size was
 *    given or if chunked encoding is in use, this will indicate
 *    an error to the client.  Note, however, that if the client
 *    does not know a response size and chunked encoding is not in
 *    use, then clients will not be able to tell the difference between
 *    `MHD_CONTENT_READER_END_WITH_ERROR` and `MHD_CONTENT_READER_END_OF_STREAM`.
 *    This is not a limitation of MHD but rather of the HTTP protocol.
 */
alias MHD_ContentReaderCallback = ssize_t function(
    void *cls,
    uint64_t pos,
    char *buf,
    size_t max);
/*typedef ssize_t (*MHD_ContentReaderCallback) (void *cls,
                              uint64_t pos,
                              char *buf,
                              size_t max);*/


/**
 * This method is called by libmicrohttpd if we
 * are done with a content reader.  It should
 * be used to free resources associated with the
 * content reader.
 *
 * Param: cls = closure
 * Ingroup: response
 */
alias MHD_ContentReaderFreeCallback = void function(void *cls);
//typedef void (*MHD_ContentReaderFreeCallback) (void *cls);


/**
 * Iterator over key-value pairs where the value
 * may be made available in increments and/or may
 * not be zero-terminated.  Used for processing
 * POST data.
 *
 * Param: cls = user-specified closure
 * Param: kind = type of the value, always `MHD_POSTDATA_KIND` when called from MHD
 * Param: key = 0-terminated key for the value
 * Param: filename = name of the uploaded file, NULL if not known
 * Param: content_type = mime-type of the data, NULL if not known
 * Param: transfer_encoding = encoding of the data, NULL if not known
 * Param: data = pointer to @a size bytes of data at the
 *              specified offset
 * Param: off = offset of data in the overall value
 * Param: size = number of bytes in @a data available
 * Returns: `MHD_YES` to continue iterating,
 *          `MHD_NO` to abort the iteration
 */
alias MHD_PostDataIterator = MHD_Result function(
    void *cls,
    MHD_ValueKind kind,
    const(char) *key,
    const(char) *filename,
    const(char) *content_type,
    const(char) *transfer_encoding,
    const(char) *data,
    uint64_t off,
    size_t size);
/*typedef enum MHD_Result (*MHD_PostDataIterator)(void *cls,
                        enum MHD_ValueKind kind,
                        const char *key,
                        const char *filename,
                        const char *content_type,
                        const char *transfer_encoding,
                        const char *data,
                        uint64_t off,
                        size_t size);*/


/// **************** Response manipulation functions *****************


/**
 * Flags for special handling of responses.
 */
alias MHD_ResponseFlags = int;
enum : MHD_ResponseFlags
{
  /**
   * Default: no special flags.
   * Note: Available since `MHD_VERSION` 0x00093701
   */
  MHD_RF_NONE = 0,

  /**
   * Only respond in conservative (dumb) HTTP/1.0-compatible mode.
   * Response still use HTTP/1.1 version in header, but always close
   * the connection after sending the response and do not use chunked
   * encoding for the response.
   * You can also set the `MHD_RF_HTTP_1_0_SERVER` flag to force
   * HTTP/1.0 version in the response.
   * Responses are still compatible with HTTP/1.1.
   * This option can be used to communicate with some broken client, which
   * does not implement HTTP/1.1 features, but advertises HTTP/1.1 support.
   * Note: Available since `MHD_VERSION` 0x00097308
   */
  MHD_RF_HTTP_1_0_COMPATIBLE_STRICT = 1,
  /**
   * The same as `MHD_RF_HTTP_1_0_COMPATIBLE_STRICT`
   * Note: Available since `MHD_VERSION` 0x00093701
   */
  MHD_RF_HTTP_VERSION_1_0_ONLY = 1,

  /**
   * Only respond in HTTP 1.0-mode.
   * Contrary to the `MHD_RF_HTTP_1_0_COMPATIBLE_STRICT` flag, the response's
   * HTTP version will always be set to 1.0 and keep-alive connections
   * will be used if explicitly requested by the client.
   * The "Connection:" header will be added for both "close" and "keep-alive"
   * connections.
   * Chunked encoding will not be used for the response.
   * Due to backward compatibility, responses still can be used with
   * HTTP/1.1 clients.
   * This option can be used to emulate HTTP/1.0 server (for response part
   * only as chunked encoding in requests (if any) is processed by MHD).
   * Note: Available since `MHD_VERSION` 0x00097308
   */
  MHD_RF_HTTP_1_0_SERVER = 1 << 1,
  /**
   * The same as `MHD_RF_HTTP_1_0_SERVER`
   * Note: Available since `MHD_VERSION` 0x00096000
   */
  MHD_RF_HTTP_VERSION_1_0_RESPONSE = 1 << 1,

  /**
   * Disable sanity check preventing clients from manually
   * setting the HTTP content length option.
   * Allow to set several "Content-Length" headers. These headers will
   * be used even with replies without body.
   * Note: Available since `MHD_VERSION` 0x00096702
   */
  MHD_RF_INSANITY_HEADER_CONTENT_LENGTH = 1 << 2,

  /**
   * Enable sending of "Connection: keep-alive" header even for
   * HTTP/1.1 clients when "Keep-Alive" connection is used.
   * Disabled by default for HTTP/1.1 clients as per RFC.
   * Note: Available since `MHD_VERSION` 0x00097310
   */
  MHD_RF_SEND_KEEP_ALIVE_HEADER = 1 << 3,

  /**
   * Enable special processing of the response as body-less (with undefined
   * body size). No automatic "Content-Length" or "Transfer-Encoding: chunked"
   * headers are added when the response is used with `MHD_HTTP_NOT_MODIFIED`
   * code or to respond to HEAD request.
   * The flag also allow to set arbitrary "Content-Length" by
   * MHD_add_response_header() function.
   * This flag value can be used only with responses created without body
   * (zero-size body).
   * Responses with this flag enabled cannot be used in situations where
   * reply body must be sent to the client.
   * This flag is primarily intended to be used when automatic "Content-Length"
   * header is undesirable in response to HEAD requests.
   * Note: Available since `MHD_VERSION` 0x00097502
   */
  MHD_RF_HEAD_ONLY_RESPONSE = 1 << 4
}


/**
 * MHD options (for future extensions).
 */
alias MHD_ResponseOptions = int;
enum : MHD_ResponseFlags
{
  /**
   * End of the list of options.
   */
  MHD_RO_END = 0
}



/**
 * Specification for how MHD should treat the memory buffer
 * given for the response.
 * Ingroup: response
 */
alias MHD_ResponseMemoryMode = int;
enum : MHD_ResponseMemoryMode
{

  /**
   * Buffer is a persistent (static/global) buffer that won't change
   * for at least the lifetime of the response, MHD should just use
   * it, not free it, not copy it, just keep an alias to it.
   * Ingroup: response
   */
  MHD_RESPMEM_PERSISTENT,

  /**
   * Buffer is heap-allocated with `malloc()` (or equivalent) and
   * should be freed by MHD after processing the response has
   * concluded (response reference counter reaches zero).
   * The more portable way to automatically free the buffer is function
   * MHD_create_response_from_buffer_with_free_callback() with '&free' as
   * crfc parameter as it does not require to use the same runtime library.
   * @warning It is critical to make sure that the same C-runtime library
   *          is used by both application and MHD (especially
   *          important for W32).
   * Ingroup: response
   */
  MHD_RESPMEM_MUST_FREE,

  /**
   * Buffer is in transient memory, but not on the heap (for example,
   * on the stack or non-`malloc()` allocated) and only valid during the
   * call to `MHD_create_response_from_buffer`.  MHD must make its
   * own private copy of the data for processing.
   * Ingroup: response
   */
  MHD_RESPMEM_MUST_COPY

}



/**
 * Enumeration for actions MHD should perform on the underlying socket
 * of the upgrade.  This API is not finalized, and in particular
 * the final set of actions is yet to be decided. This is just an
 * idea for what we might want.
 */
alias MHD_UpgradeAction = int;
enum : MHD_UpgradeAction
{

  /**
   * Close the socket, the application is done with it.
   *
   * Takes no extra arguments.
   */
  MHD_UPGRADE_ACTION_CLOSE = 0,

  /**
   * Enable CORKing on the underlying socket.
   */
  MHD_UPGRADE_ACTION_CORK_ON = 1,

  /**
   * Disable CORKing on the underlying socket.
   */
  MHD_UPGRADE_ACTION_CORK_OFF = 2

}


/**
 * Handle given to the application to manage special
 * actions relating to MHD responses that "upgrade"
 * the HTTP protocol (i.e. to WebSockets).
 */
struct MHD_UpgradeResponseHandle;



/**
 * Function called after a protocol "upgrade" response was sent
 * successfully and the socket should now be controlled by some
 * protocol other than HTTP.
 *
 * Any data already received on the socket will be made available in
 * @e extra_in.  This can happen if the application sent extra data
 * before MHD send the upgrade response.  The application should
 * treat data from @a extra_in as if it had read it from the socket.
 *
 * Note that the application must not close() @a sock directly,
 * but instead use `MHD_upgrade_action()` for special operations
 * on @a sock.
 *
 * Data forwarding to "upgraded" @a sock will be started as soon
 * as this function return.
 *
 * Except when in 'thread-per-connection' mode, implementations
 * of this function should never block (as it will still be called
 * from within the main event loop).
 *
 * Param: cls = closure, whatever was given to `MHD_create_response_for_upgrade()`.
 * Param: connection = original HTTP connection handle,
 *                   giving the function a last chance
 *                   to inspect the original HTTP request
 * Param: req_cls = last value left in `req_cls` of the `MHD_AccessHandlerCallback`
 * Param: extra_in = if we happened to have read bytes after the
 *                 HTTP header already (because the client sent
 *                 more than the HTTP header of the request before
 *                 we sent the upgrade response),
 *                 these are the extra bytes already read from @a sock
 *                 by MHD.  The application should treat these as if
 *                 it had read them from @a sock.
 * Param: extra_in_size = number of bytes in @a extra_in
 * Param: sock = socket to use for bi-directional communication
 *        with the client.  For HTTPS, this may not be a socket
 *        that is directly connected to the client and thus certain
 *        operations (TCP-specific setsockopt(), getsockopt(), etc.)
 *        may not work as expected (as the socket could be from a
 *        socketpair() or a TCP-loopback).  The application is expected
 *        to perform read()/recv() and write()/send() calls on the socket.
 *        The application may also call shutdown(), but must not call
 *        close() directly.
 * Param: urh = argument for `MHD_upgrade_action()`s on this @a connection.
 *        Applications must eventually use this callback to (indirectly)
 *        perform the close() action on the @a sock.
 */
alias MHD_UpgradeHandler = void function(void *cls,
                      MHD_Connection *connection,
                      void *req_cls,
                      const(char) *extra_in,
                      size_t extra_in_size,
                      MHD_socket sock,
                      MHD_UpgradeResponseHandle *urh);
/*typedef void (*MHD_UpgradeHandler)(void *cls,
                      struct MHD_Connection *connection,
                      void *req_cls,
                      const char *extra_in,
                      size_t extra_in_size,
                      MHD_socket sock,
                      struct MHD_UpgradeResponseHandle *urh);*/


/// ********************** PostProcessor functions **********************


/// ********************* Digest Authentication functions ***************


/**
 * Length of the binary output of the MD5 hash function.
 * See_Also: `MHD_digest_get_hash_size()`
 * Ingroup: authentication
 */
enum MHD_MD5_DIGEST_SIZE = 16;

/**
 * Length of the binary output of the SHA-256 hash function.
 * See_Also: `MHD_digest_get_hash_size()`
 * Ingroup: authentication
 */
enum MHD_SHA256_DIGEST_SIZE = 32;

/**
 * Length of the binary output of the SHA-512/256 hash function.
 * Warning: While this value is the same as the `MHD_SHA256_DIGEST_SIZE`,
 *          the calculated digests for SHA-256 and SHA-512/256 are different.
 * See_Also: `MHD_digest_get_hash_size()`
 * Note: Available since `MHD_VERSION` 0x00097538
 * Ingroup: authentication
 */
enum MHD_SHA512_256_DIGEST_SIZE = 32;

/**
 * Base type of hash calculation.
 * Used as part of `MHD_DigestAuthAlgo3` values.
 *
 * @warning Not used directly by MHD API.
 * Note: Available since `MHD_VERSION` 0x00097520
 */
alias MHD_DigestBaseAlgo = int;
enum : MHD_DigestBaseAlgo
{
  /**
   * Invalid hash algorithm value
   */
  MHD_DIGEST_BASE_ALGO_INVALID = 0,

  /**
   * MD5 hash algorithm.
   * As specified by RFC1321
   */
  MHD_DIGEST_BASE_ALGO_MD5 = (1 << 0),

  /**
   * SHA-256 hash algorithm.
   * As specified by FIPS PUB 180-4
   */
  MHD_DIGEST_BASE_ALGO_SHA256 = (1 << 1),

  /**
   * SHA-512/256 hash algorithm.
   * As specified by FIPS PUB 180-4
   */
  MHD_DIGEST_BASE_ALGO_SHA512_256 = (1 << 2)
}

/**
 * The flag indicating non-session algorithm types,
 * like 'MD5', 'SHA-256' or 'SHA-512-256'.
 * Note: Available since `MHD_VERSION` 0x00097519
 */
enum MHD_DIGEST_AUTH_ALGO3_NON_SESSION =    (1 << 6);

/**
 * The flag indicating session algorithm types,
 * like 'MD5-sess', 'SHA-256-sess' or 'SHA-512-256-sess'.
 * Note: Available since `MHD_VERSION` 0x00097519
 */
enum MHD_DIGEST_AUTH_ALGO3_SESSION =        (1 << 7);

/**
 * Digest algorithm identification
 * @warning Do not be confused with `MHD_DigestAuthAlgorithm`,
 *          which uses other values!
 * Note: Available since `MHD_VERSION` 0x00097523
 */
alias MHD_DigestAuthAlgo3 = int;
enum : MHD_DigestAuthAlgo3
{
  /**
   * Unknown or wrong algorithm type.
   * Used in struct MHD_DigestAuthInfo to indicate client value that
   * cannot by identified.
   */
  MHD_DIGEST_AUTH_ALGO3_INVALID = 0,

  /**
   * The 'MD5' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_ALGO3_MD5 =
    MHD_DIGEST_BASE_ALGO_MD5 | MHD_DIGEST_AUTH_ALGO3_NON_SESSION,

  /**
   * The 'MD5-sess' algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO3_MD5_SESSION =
    MHD_DIGEST_BASE_ALGO_MD5 | MHD_DIGEST_AUTH_ALGO3_SESSION,

  /**
   * The 'SHA-256' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_ALGO3_SHA256 =
    MHD_DIGEST_BASE_ALGO_SHA256 | MHD_DIGEST_AUTH_ALGO3_NON_SESSION,

  /**
   * The 'SHA-256-sess' algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION =
    MHD_DIGEST_BASE_ALGO_SHA256 | MHD_DIGEST_AUTH_ALGO3_SESSION,

  /**
   * The 'SHA-512-256' (SHA-512/256) algorithm.
   */
  MHD_DIGEST_AUTH_ALGO3_SHA512_256 =
    MHD_DIGEST_BASE_ALGO_SHA512_256 | MHD_DIGEST_AUTH_ALGO3_NON_SESSION,

  /**
   * The 'SHA-512-256-sess' (SHA-512/256 session) algorithm.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION =
    MHD_DIGEST_BASE_ALGO_SHA512_256 | MHD_DIGEST_AUTH_ALGO3_SESSION,
}


/**
 * Digest algorithm identification, allow multiple selection.
 *
 * `MHD_DigestAuthAlgo3` always can be casted to `MHD_DigestAuthMultiAlgo3`, but
 * not vice versa.
 *
 * Note: Available since `MHD_VERSION` 0x00097523
 */
enum MHD_DigestAuthMultiAlgo3
{
  /**
   * Unknown or wrong algorithm type.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_INVALID = MHD_DIGEST_AUTH_ALGO3_INVALID,

  /**
   * The 'MD5' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5 = MHD_DIGEST_AUTH_ALGO3_MD5,

  /**
   * The 'MD5-sess' algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5_SESSION = MHD_DIGEST_AUTH_ALGO3_MD5_SESSION,

  /**
   * The 'SHA-256' algorithm, non-session version.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256 = MHD_DIGEST_AUTH_ALGO3_SHA256,

  /**
   * The 'SHA-256-sess' algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256_SESSION =
    MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION,

  /**
   * The 'SHA-512-256' (SHA-512/256) algorithm.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256 = MHD_DIGEST_AUTH_ALGO3_SHA512_256,

  /**
   * The 'SHA-512-256-sess' (SHA-512/256 session) algorithm.
   * Not supported by MHD for authentication.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256_SESSION =
    MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION,

  /**
   * Any non-session algorithm, MHD will choose.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_ANY_NON_SESSION =
    (0x3F) | MHD_DIGEST_AUTH_ALGO3_NON_SESSION,

  /**
   * Any session algorithm, MHD will choose.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_ANY_SESSION =
    (0x3F) | MHD_DIGEST_AUTH_ALGO3_SESSION,

  /**
   * The 'MD5' algorithm, session or non-session.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_MD5 | MHD_DIGEST_AUTH_MULT_ALGO3_MD5_SESSION,

  /**
   * The 'SHA-256' algorithm, session or non-session.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_SHA256
    | MHD_DIGEST_AUTH_MULT_ALGO3_SHA256_SESSION,

  /**
   * The 'SHA-512/256' algorithm, session or non-session.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256
    | MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256_SESSION,

  /**
   * Any algorithm, MHD will choose.
   */
  MHD_DIGEST_AUTH_MULT_ALGO3_ANY =
    (0x3F) | MHD_DIGEST_AUTH_ALGO3_NON_SESSION | MHD_DIGEST_AUTH_ALGO3_SESSION
}



/**
 * The type of username used by client in Digest Authorization header
 *
 * Values are sorted so simplified checks could be used.
 * For example:
 * * (value <= MHD_DIGEST_AUTH_UNAME_TYPE_INVALID) is true if no valid username
 *   is provided by the client
 * * (value >= MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH) is true if username is
 *   provided in any form
 * * (value >= MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD) is true if username is
 *   provided in clear text (not userhash matching is needed)
 *
 * Note: Available since `MHD_VERSION` 0x00097537
 */
alias MHD_DigestAuthUsernameType = int;
enum : MHD_DigestAuthUsernameType
{
  /**
   * No username parameter in in Digest Authorization header.
   * This should be treated as an error.
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_MISSING = 0,

  /**
   * The 'username' parameter is used to specify the username.
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD = (1 << 2),

  /**
   * The username is specified by 'username*' parameter with
   * the extended notation (see RFC 5987 #section-3.2.1).
   * The only difference between standard and extended types is
   * the way how username value is encoded in the header.
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_EXTENDED = (1 << 3),

  /**
   * The username provided in form of 'userhash' as
   * specified by RFC 7616 #section-3.4.4.
   * See_Also: `MHD_digest_auth_calc_userhash_hex()`, `MHD_digest_auth_calc_userhash()`
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH = (1 << 1),

  /**
   * The invalid combination of username parameters are used by client.
   * Either:
   * * both 'username' and 'username*' are used
   * * 'username*' is used with 'userhash=true'
   * * 'username*' used with invalid extended notation
   * * 'username' is not hexadecimal digits, while 'userhash' set to 'true'
   */
  MHD_DIGEST_AUTH_UNAME_TYPE_INVALID = (1 << 0)
}

/**
 * The QOP ('quality of protection') types.
 * Note: Available since `MHD_VERSION` 0x00097519
 */
alias MHD_DigestAuthQOP = int;
enum : MHD_DigestAuthQOP
{
  /**
   * Invalid/unknown QOP.
   * Used in struct MHD_DigestAuthInfo to indicate client value that
   * cannot by identified.
   */
  MHD_DIGEST_AUTH_QOP_INVALID = 0,

  /**
   * No QOP parameter.
   * As described in old RFC 2069 original specification.
   * This mode is not allowed by latest RFCs and should be used only to
   * communicate with clients that do not support more modern modes (with QOP
   * parameter).
   * This mode is less secure than other modes and inefficient.
   */
  MHD_DIGEST_AUTH_QOP_NONE = 1 << 0,

  /**
   * The 'auth' QOP type.
   */
  MHD_DIGEST_AUTH_QOP_AUTH = 1 << 1,

  /**
   * The 'auth-int' QOP type.
   * Not supported by MHD for authentication.
   */
  MHD_DIGEST_AUTH_QOP_AUTH_INT = 1 << 2
}

/**
 * The QOP ('quality of protection') types, multiple selection.
 *
 * `MHD_DigestAuthQOP` always can be casted to `MHD_DigestAuthMultiQOP`, but
 * not vice versa.
 *
 * Note: Available since `MHD_VERSION` 0x00097530
 */
alias MHD_DigestAuthMultiQOP = int;
enum : MHD_DigestAuthMultiQOP
{
  /**
   * Invalid/unknown QOP.
   */
  MHD_DIGEST_AUTH_MULT_QOP_INVALID = MHD_DIGEST_AUTH_QOP_INVALID,

  /**
   * No QOP parameter.
   * As described in old RFC 2069 original specification.
   * This mode is not allowed by latest RFCs and should be used only to
   * communicate with clients that do not support more modern modes (with QOP
   * parameter).
   * This mode is less secure than other modes and inefficient.
   */
  MHD_DIGEST_AUTH_MULT_QOP_NONE = MHD_DIGEST_AUTH_QOP_NONE,

  /**
   * The 'auth' QOP type.
   */
  MHD_DIGEST_AUTH_MULT_QOP_AUTH = MHD_DIGEST_AUTH_QOP_AUTH,

  /**
   * The 'auth-int' QOP type.
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_QOP_AUTH_INT = MHD_DIGEST_AUTH_QOP_AUTH_INT,

  /**
   * The 'auth' QOP type OR the old RFC2069 (no QOP) type.
   * In other words: any types except 'auth-int'.
   * RFC2069-compatible mode is allowed, thus this value should be used only
   * when it is really necessary.
   */
  MHD_DIGEST_AUTH_MULT_QOP_ANY_NON_INT =
    MHD_DIGEST_AUTH_QOP_NONE | MHD_DIGEST_AUTH_QOP_AUTH,

  /**
   * Any 'auth' QOP type ('auth' or 'auth-int').
   * Not supported by MHD.
   * Reserved value.
   */
  MHD_DIGEST_AUTH_MULT_QOP_AUTH_ANY =
    MHD_DIGEST_AUTH_QOP_AUTH | MHD_DIGEST_AUTH_QOP_AUTH_INT
}

/**
 * The invalid value of 'nc' parameter in client Digest Authorization header.
 * Note: Available since `MHD_VERSION` 0x00097519
 */
enum MHD_DIGEST_AUTH_INVALID_NC_VALUE =        (0);

/**
 * Information from Digest Authorization client's header.
 *
 * All buffers pointed by any struct members are freed when `MHD_free()` is
 * called for pointer to this structure.
 *
 * Application may modify buffers as needed until `MHD_free()` is called for
 * pointer to this structure
 * Note: Available since `MHD_VERSION` 0x00097537
 */
struct MHD_DigestAuthInfo
{
  /**
   * The algorithm as defined by client.
   * Set automatically to MD5 if not specified by client.
   * @warning Do not be confused with `MHD_DigestAuthAlgorithm`,
   *          which uses other values!
   */
  MHD_DigestAuthAlgo3 algo3;

  /**
   * The type of username used by client.
   */
  MHD_DigestAuthUsernameType uname_type;

  /**
   * The username string.
   * Used only if username type is standard or extended, always NULL otherwise.
   * If extended notation is used, this string is pct-decoded string
   * with charset and language tag removed (i.e. it is original username
   * extracted from the extended notation).
   * When userhash is used by the client, this member is NULL and
   * @a userhash_hex is set.
   */
  char *username;

  /**
   * The length of the @a username.
   * When the @a username is NULL, this member is always zero.
   */
  size_t username_len;

  /**
   * The userhash string.
   * Valid only if username type is userhash.
   * This is unqoted string without decoding of the hexadecimal
   * digits (as provided by the client).
   * See_Also: `MHD_digest_auth_calc_userhash_hex()`
   */
  char *userhash_hex;

  /**
   * The length of the @a userhash_hex in characters.
   * The valid size should be `MHD_digest_get_hash_size`(algo3) * 2 characters.
   * When the @a userhash_hex is NULL, this member is always zero.
   */
  size_t userhash_hex_len;

  /**
   * The userhash decoded to binary form.
   * Used only if username type is userhash, always NULL otherwise.
   * When not NULL, this points to binary sequence @a userhash_hex_len /2 bytes
   * long.
   * The valid size should be `MHD_digest_get_hash_size`(algo3) bytes.
   * @warning This is binary data, no zero termination.
   * @warning To avoid buffer overruns, always check the size of the data before
   *          use, because @a userhash_bin can point even to zero-sized
   *          data.
   * See_Also: `MHD_digest_auth_calc_userhash()`
   */
  uint8_t *userhash_bin;

  /**
   * The 'opaque' parameter value, as specified by client.
   * NULL if not specified by client.
   */
  char *opaque;

  /**
   * The length of the @a opaque.
   * When the @a opaque is NULL, this member is always zero.
   */
  size_t opaque_len;

  /**
   * The 'realm' parameter value, as specified by client.
   * NULL if not specified by client.
   */
  char *realm;

  /**
   * The length of the @a realm.
   * When the @a realm is NULL, this member is always zero.
   */
  size_t realm_len;

  /**
   * The 'qop' parameter value.
   */
  MHD_DigestAuthQOP qop;

  /**
   * The length of the 'cnonce' parameter value, including possible
   * backslash-escape characters.
   * 'cnonce' is used in hash calculation, which is CPU-intensive procedure.
   * An application may want to reject too large cnonces to limit the CPU load.
   * A few kilobytes is a reasonable limit, typically cnonce is just 32-160
   * characters long.
   */
  size_t cnonce_len;

  /**
   * The nc parameter value.
   * Can be used by application to limit the number of nonce re-uses. If @a nc
   * is higher than application wants to allow, then auth required response with
   * 'stale=true' could be used to force client to retry with the fresh 'nonce'.
   * If not specified by client or does not have hexadecimal digits only, the
   * value is `MHD_DIGEST_AUTH_INVALID_NC_VALUE`.
   */
  uint32_t nc;
}


/**
 * Information from Digest Authorization client's header.
 *
 * All buffers pointed by any struct members are freed when `MHD_free()` is
 * called for pointer to this structure.
 *
 * Application may modify buffers as needed until `MHD_free()` is called for
 * pointer to this structure
 * Note: Available since `MHD_VERSION` 0x00097537
 */
struct MHD_DigestAuthUsernameInfo
{
  /**
   * The algorithm as defined by client.
   * Set automatically to MD5 if not specified by client.
   * @warning Do not be confused with `MHD_DigestAuthAlgorithm`,
   *          which uses other values!
   */
  MHD_DigestAuthAlgo3 algo3;

  /**
   * The type of username used by client.
   * The 'invalid' and 'missing' types are not used in this structure,
   * instead NULL is returned by `MHD_digest_auth_get_username3()`.
   */
  MHD_DigestAuthUsernameType uname_type;

  /**
   * The username string.
   * Used only if username type is standard or extended, always NULL otherwise.
   * If extended notation is used, this string is pct-decoded string
   * with charset and language tag removed (i.e. it is original username
   * extracted from the extended notation).
   * When userhash is used by the client, this member is NULL and
   * @a userhash_hex is set.
   */
  char *username;

  /**
   * The length of the @a username.
   * When the @a username is NULL, this member is always zero.
   */
  size_t username_len;

  /**
   * The userhash string.
   * Valid only if username type is userhash.
   * This is unqoted string without decoding of the hexadecimal
   * digits (as provided by the client).
   * See_Also: `MHD_digest_auth_calc_userhash_hex()`
   */
  char *userhash_hex;

  /**
   * The length of the @a userhash_hex in characters.
   * The valid size should be `MHD_digest_get_hash_size`(algo3) * 2 characters.
   * When the @a userhash_hex is NULL, this member is always zero.
   */
  size_t userhash_hex_len;

  /**
   * The userhash decoded to binary form.
   * Used only if username type is userhash, always NULL otherwise.
   * When not NULL, this points to binary sequence @a userhash_hex_len /2 bytes
   * long.
   * The valid size should be `MHD_digest_get_hash_size`(algo3) bytes.
   * @warning This is binary data, no zero termination.
   * @warning To avoid buffer overruns, always check the size of the data before
   *          use, because @a userhash_bin can point even to zero-sized
   *          data.
   * See_Also: `MHD_digest_auth_calc_userhash()`
   */
  uint8_t *userhash_bin;
}


/**
 * The result of digest authentication of the client.
 *
 * All error values are zero or negative.
 *
 * Note: Available since `MHD_VERSION` 0x00097531
 */
alias MHD_DigestAuthResult = int;
enum : MHD_DigestAuthResult
{
  /**
   * Authentication OK.
   */
  MHD_DAUTH_OK = 1,

  /**
   * General error, like "out of memory".
   */
  MHD_DAUTH_ERROR = 0,

  /**
   * No "Authorization" header or wrong format of the header.
   * Also may be returned if required parameters in client Authorisation header
   * are missing or broken (in invalid format).
   */
  MHD_DAUTH_WRONG_HEADER = -1,

  /**
   * Wrong 'username'.
   */
  MHD_DAUTH_WRONG_USERNAME = -2,

  /**
   * Wrong 'realm'.
   */
  MHD_DAUTH_WRONG_REALM = -3,

  /**
   * Wrong 'URI' (or URI parameters).
   */
  MHD_DAUTH_WRONG_URI = -4,

  /**
   * Wrong 'qop'.
   */
  MHD_DAUTH_WRONG_QOP = -5,

  /**
   * Wrong 'algorithm'.
   */
  MHD_DAUTH_WRONG_ALGO = -6,

  /**
   * Too large (>64 KiB) Authorization parameter value.
   */
  MHD_DAUTH_TOO_LARGE = -15,

  /* The different form of naming is intentionally used for the results below,
   * as they are more important */

  /**
   * The 'nonce' is too old. Suggest the client to retry with the same
   * username and password to get the fresh 'nonce'.
   * The validity of the 'nonce' may be not checked.
   */
  MHD_DAUTH_NONCE_STALE = -17,

  /**
   * The 'nonce' was generated by MHD for other conditions.
   * This value is only returned if `MHD_OPTION_DIGEST_AUTH_NONCE_BIND_TYPE`
   * is set to anything other than `MHD_DAUTH_BIND_NONCE_NONE`.
   * The interpretation of this code could be different. For example, if
   * `MHD_DAUTH_BIND_NONCE_URI` is set and client just used the same 'nonce' for
   * another URI, the code could be handled as `MHD_DAUTH_NONCE_STALE` as
   * it is allowed to re-use nonces for other URIs in the same "protection
   * space". However, if only `MHD_DAUTH_BIND_NONCE_CLIENT_IP` bit is set and
   * it is know that clients have fixed IP addresses, this return code could
   * be handled like `MHD_DAUTH_NONCE_WRONG`.
   */
  MHD_DAUTH_NONCE_OTHER_COND = -18,

  /**
   * The 'nonce' is wrong. May indicate an attack attempt.
   */
  MHD_DAUTH_NONCE_WRONG = -33,

  /**
   * The 'response' is wrong. May indicate an attack attempt.
   */
  MHD_DAUTH_RESPONSE_WRONG = -34,
}


/**
 * Constant to indicate that the nonce of the provided
 * authentication code was wrong.
 * Also MHD digest auth internal code for an invalid nonce.
 * Used as return code by `MHD_digest_auth_check()`, `MHD_digest_auth_check2()`,
 * `MHD_digest_auth_check_digest()`, `MHD_digest_auth_check_digest2()`.
 * Ingroup: authentication
 */
enum MHD_INVALID_NONCE = -1;


/**
 * Get the username from the authorization header sent by the client
 *
 * This function supports username in standard and extended notations.
 * "userhash" is not supported by this function.
 *
 * Params: connection = The MHD connection structure
 * Returns: NULL if no username could be found, username provided as
 *         "userhash", extended notation broken or memory allocation error
 *         occurs;
 *         a pointer to the username if found, free using `MHD_free()`.
 * Warning: Returned value must be freed by `MHD_free()`.
 * See_Also: `MHD_digest_auth_get_username3()`
 * Ingroup: authentication
 */
char* MHD_digest_auth_get_username(MHD_Connection *connection);


/**
 * Which digest algorithm should MHD use for HTTP digest authentication?
 * Used as parameter for `MHD_digest_auth_check2()`,
 * `MHD_digest_auth_check_digest2()`, `MHD_queue_auth_fail_response2()`.
 */
alias MHD_DigestAuthAlgorithm = int;
enum : MHD_DigestAuthAlgorithm
{

  /**
   * MHD should pick (currently defaults to MD5).
   */
  MHD_DIGEST_ALG_AUTO = 0,

  /**
   * Force use of MD5.
   */
  MHD_DIGEST_ALG_MD5,

  /**
   * Force use of SHA-256.
   */
  MHD_DIGEST_ALG_SHA256

}


/// ********************* Basic Authentication functions ***************


/**
 * Information decoded from Basic Authentication client's header.
 *
 * The username and the password are technically allowed to have binary zeros,
 * username_len and password_len could be used to detect such situations.
 *
 * The buffers pointed by username and password members are freed
 * when `MHD_free()` is called for pointer to this structure.
 *
 * Application may modify buffers as needed until `MHD_free()` is called for
 * pointer to this structure
 */
struct MHD_BasicAuthInfo
{
  /**
   * The username, cannot be NULL
   */
  char *username;

  /**
   * The length of the @a username, not including zero-termination
   */
  size_t username_len;

  /**
   * The password, may be NULL if password is not encoded by the client
   */
  char *password;

  /**
   * The length of the @a password, not including zero-termination;
   * when the @a password is NULL, the length is always zero.
   */
  size_t password_len;
}

/// ********************** generic query functions **********************


/**
 * MHD connection options.  Given to `MHD_set_connection_option` to
 * set custom options for a particular connection.
 */
alias MHD_CONNECTION_OPTION = int;
enum : MHD_CONNECTION_OPTION
{

  /**
   * Set a custom timeout for the given connection.  Specified
   * as the number of seconds, given as an `unsigned int`.  Use
   * zero for no timeout.
   * If timeout was set to zero (or unset) before, setup of new value by
   * MHD_set_connection_option() will reset timeout timer.
   * Values larger than (UINT64_MAX / 2000 - 1) will
   * be clipped to this number.
   */
  MHD_CONNECTION_OPTION_TIMEOUT

}


/**
 * Information about an MHD daemon.
 */
union MHD_DaemonInfo
{
  /**
   * Size of the key, no longer supported.
   * @deprecated
   */
  size_t key_size;

  /**
   * Size of the mac key, no longer supported.
   * @deprecated
   */
  size_t mac_key_size;

  /**
   * Socket, returned for `MHD_DAEMON_INFO_LISTEN_FD`.
   */
  MHD_socket listen_fd;

  /**
   * Bind port number, returned for `MHD_DAEMON_INFO_BIND_PORT`.
   */
  uint16_t port;

  /**
   * epoll FD, returned for `MHD_DAEMON_INFO_EPOLL_FD`.
   */
  int epoll_fd;

  /**
   * Number of active connections, for `MHD_DAEMON_INFO_CURRENT_CONNECTIONS`.
   */
  uint num_connections;

  /**
   * Combination of `MHD_FLAG` values, for `MHD_DAEMON_INFO_FLAGS`.
   * This value is actually a bitfield.
   * Note: flags may differ from original 'flags' specified for
   * daemon, especially if `MHD_USE_AUTO` was set.
   */
  MHD_FLAG flags;
}

/**
 * Types of information about MHD features,
 * used by `MHD_is_feature_supported()`.
 */
alias MHD_FEATURE = int;
enum : MHD_FEATURE
{
  /**
   * Get whether messages are supported. If supported then in debug
   * mode messages can be printed to stderr or to external logger.
   */
  MHD_FEATURE_MESSAGES = 1,

  /**
   * Get whether HTTPS is supported.  If supported then flag
   * `MHD_USE_TLS` and options `MHD_OPTION_HTTPS_MEM_KEY`,
   * `MHD_OPTION_HTTPS_MEM_CERT`, `MHD_OPTION_HTTPS_MEM_TRUST`,
   * `MHD_OPTION_HTTPS_MEM_DHPARAMS`, `MHD_OPTION_HTTPS_CRED_TYPE`,
   * `MHD_OPTION_HTTPS_PRIORITIES` can be used.
   */
  MHD_FEATURE_TLS = 2,
  MHD_FEATURE_SSL = 2,

  /**
   * Get whether option `MHD_OPTION_HTTPS_CERT_CALLBACK` is
   * supported.
   */
  MHD_FEATURE_HTTPS_CERT_CALLBACK = 3,

  /**
   * Get whether IPv6 is supported. If supported then flag
   * `MHD_USE_IPv6` can be used.
   */
  MHD_FEATURE_IPv6 = 4,

  /**
   * Get whether IPv6 without IPv4 is supported. If not supported
   * then IPv4 is always enabled in IPv6 sockets and
   * flag `MHD_USE_DUAL_STACK` if always used when `MHD_USE_IPv6` is
   * specified.
   */
  MHD_FEATURE_IPv6_ONLY = 5,

  /**
   * Get whether `poll()` is supported. If supported then flag
   * `MHD_USE_POLL` can be used.
   */
  MHD_FEATURE_POLL = 6,

  /**
   * Get whether `epoll()` is supported. If supported then Flags
   * `MHD_USE_EPOLL` and
   * `MHD_USE_EPOLL_INTERNAL_THREAD` can be used.
   */
  MHD_FEATURE_EPOLL = 7,

  /**
   * Get whether shutdown on listen socket to signal other
   * threads is supported. If not supported flag
   * `MHD_USE_ITC` is automatically forced.
   */
  MHD_FEATURE_SHUTDOWN_LISTEN_SOCKET = 8,

  /**
   * Get whether socketpair is used internally instead of pipe to
   * signal other threads.
   */
  MHD_FEATURE_SOCKETPAIR = 9,

  /**
   * Get whether TCP Fast Open is supported. If supported then
   * flag `MHD_USE_TCP_FASTOPEN` and option
   * `MHD_OPTION_TCP_FASTOPEN_QUEUE_SIZE` can be used.
   */
  MHD_FEATURE_TCP_FASTOPEN = 10,

  /**
   * Get whether HTTP Basic authorization is supported. If supported
   * then functions `MHD_basic_auth_get_username_password` and
   * `MHD_queue_basic_auth_fail_response` can be used.
   */
  MHD_FEATURE_BASIC_AUTH = 11,

  /**
   * Get whether HTTP Digest authorization is supported. If
   * supported then options `MHD_OPTION_DIGEST_AUTH_RANDOM`,
   * `MHD_OPTION_NONCE_NC_SIZE` and
   * `MHD_digest_auth_check()` can be used.
   */
  MHD_FEATURE_DIGEST_AUTH = 12,

  /**
   * Get whether postprocessor is supported. If supported then
   * functions `MHD_create_post_processor()`, `MHD_post_process()` and
   * `MHD_destroy_post_processor()` can
   * be used.
   */
  MHD_FEATURE_POSTPROCESSOR = 13,

  /**
  * Get whether password encrypted private key for HTTPS daemon is
  * supported. If supported then option
  * ::MHD_OPTION_HTTPS_KEY_PASSWORD can be used.
  */
  MHD_FEATURE_HTTPS_KEY_PASSWORD = 14,

  /**
   * Get whether reading files beyond 2 GiB boundary is supported.
   * If supported then `MHD_create_response_from_fd()`,
   * `MHD_create_response_from_fd64` `MHD_create_response_from_fd_at_offset()`
   * and `MHD_create_response_from_fd_at_offset64()` can be used with sizes and
   * offsets larger than 2 GiB. If not supported value of size+offset is
   * limited to 2 GiB.
   */
  MHD_FEATURE_LARGE_FILE = 15,

  /**
   * Get whether MHD set names on generated threads.
   */
  MHD_FEATURE_THREAD_NAMES = 16,
  MHD_THREAD_NAMES = 16,

  /**
   * Get whether HTTP "Upgrade" is supported.
   * If supported then `MHD_ALLOW_UPGRADE`, `MHD_upgrade_action()` and
   * `MHD_create_response_for_upgrade()` can be used.
   */
  MHD_FEATURE_UPGRADE = 17,

  /**
   * Get whether it's safe to use same FD for multiple calls of
   * `MHD_create_response_from_fd()` and whether it's safe to use single
   * response generated by `MHD_create_response_from_fd()` with multiple
   * connections at same time.
   * If `MHD_is_feature_supported()` return `MHD_NO` for this feature then
   * usage of responses with same file FD in multiple parallel threads may
   * results in incorrect data sent to remote client.
   * It's always safe to use same file FD in multiple responses if MHD
   * is run in any single thread mode.
   */
  MHD_FEATURE_RESPONSES_SHARED_FD = 18,

  /**
   * Get whether MHD support automatic detection of bind port number.
   * See_Also: `MHD_DAEMON_INFO_BIND_PORT`
   */
  MHD_FEATURE_AUTODETECT_BIND_PORT = 19,

  /**
   * Get whether MHD supports automatic SIGPIPE suppression.
   * If SIGPIPE suppression is not supported, application must handle
   * SIGPIPE signal by itself.
   */
  MHD_FEATURE_AUTOSUPPRESS_SIGPIPE = 20,

  /**
   * Get whether MHD use system's sendfile() function to send
   * file-FD based responses over non-TLS connections.
   * Note: Since v0.9.56
   */
  MHD_FEATURE_SENDFILE = 21,

  /**
   * Get whether MHD supports threads.
   */
  MHD_FEATURE_THREADS = 22,

  /**
   * Get whether option `MHD_OPTION_HTTPS_CERT_CALLBACK2` is
   * supported.
   */
  MHD_FEATURE_HTTPS_CERT_CALLBACK2 = 23,

  /**
   * Get whether automatic parsing of HTTP Cookie header is supported.
   * If disabled, no MHD_COOKIE_KIND will be generated by MHD.
   * MHD versions before 0x00097514 always support cookie parsing.
   * Note: Available since `MHD_VERSION` 0x00097514
   */
  MHD_FEATURE_HTTPS_COOKIE_PARSING = 24,

  /**
   * Get whether the early version the Digest Authorization (RFC 2069) is
   * supported (digest authorisation without QOP parameter).
   * Since `MHD_VERSION` 0x00097530 it is always supported if Digest Auth
   * module is built.
   * Note: Available since `MHD_VERSION` 0x00097527
   */
  MHD_FEATURE_DIGEST_AUTH_RFC2069 = 25,

  /**
   * Get whether the MD5-based hashing algorithms are supported for Digest
   * Authorization.
   * Currently it is always supported if Digest Auth module is built
   * unless manually disabled in a custom build.
   * Note: Available since `MHD_VERSION` 0x00097527
   */
  MHD_FEATURE_DIGEST_AUTH_MD5 = 26,

  /**
   * Get whether the SHA-256-based hashing algorithms are supported for Digest
   * Authorization.
   * It it always supported since `MHD_VERSION` 0x00096200 if Digest Auth
   * module is built unless manually disabled in a custom build.
   * Note: Available since `MHD_VERSION` 0x00097527
   */
  MHD_FEATURE_DIGEST_AUTH_SHA256 = 27,

  /**
   * Get whether the SHA-512/256-based hashing algorithms are supported
   * for Digest Authorization.
   * It it always supported since `MHD_VERSION` 0x00097539 if Digest Auth
   * module is built unless manually disabled in a custom build.
   * Note: Available since `MHD_VERSION` 0x00097536
   */
  MHD_FEATURE_DIGEST_AUTH_SHA512_256 = 28,

  /**
   * Get whether QOP with value 'auth-int' (authentication with integrity
   * protection) is supported for Digest Authorization.
   * Currently it is always not supported.
   * Note: Available since `MHD_VERSION` 0x00097536
   */
  MHD_FEATURE_DIGEST_AUTH_AUTH_INT = 29,

  /**
   * Get whether 'session' algorithms (like 'MD5-sess') are supported for Digest
   * Authorization.
   * Currently it is always not supported.
   * Note: Available since `MHD_VERSION` 0x00097536
   */
  MHD_FEATURE_DIGEST_AUTH_ALGO_SESSION = 30,

  /**
   * Get whether 'userhash' is supported for Digest Authorization.
   * It is always supported since `MHD_VERSION` 0x00097526 if Digest Auth
   * module is built.
   * Note: Available since `MHD_VERSION` 0x00097536
   */
  MHD_FEATURE_DIGEST_AUTH_USERHASH = 31,

  /**
   * Get whether any of hashing algorithms is implemented by external
   * function (like TLS library) and may fail due to external conditions,
   * like "out-of-memory".
   *
   * If result is `MHD_YES` then functions which use hash calculations
   * like `MHD_digest_auth_calc_userhash()`, `MHD_digest_auth_check3()` and others
   * potentially may fail even with valid input because of out-of-memory error
   * or crypto accelerator device failure, however in practice such fails are
   * unlikely.
   * Note: Available since `MHD_VERSION` 0x00097540
   */
  MHD_FEATURE_EXTERN_HASH = 32
}