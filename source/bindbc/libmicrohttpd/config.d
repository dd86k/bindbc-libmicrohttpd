module bindbc.libmicrohttpd.config;

/// 
enum LibMicroHTTPDSupport
{
    /// No libmicrohttpd libraries were found.
    noLibrary,
    /// An older version of the library was found compared
    /// to the one configured.
    badLibrary,
    /// Version 0.9.59, c. Ubuntu 18.04, baseline
    v000959 = 0x00095900,
    /// Version 0.9.66, c. Ubuntu 20.04
    v000966 = 0x00096600,
    /// Version 0.9.75, c. Ubuntu 22.04
    v000975 = 0x00097500,
    /// Latest versions supported by this library
    latest = v000975,
}

version (LibMicroHTTPD_v000975)
{
    /// Current version of the library in packed BCD form.
    /// Note: Version number components are coded as Simple Binary-Coded Decimal
    /// (also called Natural BCD or BCD 8421). While they are hexadecimal numbers,
    /// they are parsed as decimal numbers.
    /// Example: 0x01093001 = 1.9.30-1.
    enum MHD_VERSION = LibMicroHTTPDSupport.v000975;
}
else version (LibMicroHTTPD_v000966)
{
    /// Ditto
    enum MHD_VERSION = LibMicroHTTPDSupport.v000966;
}
else
{
    /// Ditto
    enum MHD_VERSION = LibMicroHTTPDSupport.v000959;
}