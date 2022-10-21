module bindbc.libmicrohttpd;

public import bindbc.libmicrohttpd.header;

version(BindBC_Static)
	version = BindLibMicroHTTPD_Static;

version(BindBC_LibMicroHTTPD_Static)
	enum staticBinding = true;
else
	enum staticBinding = false;

static if (staticBinding)
	public import bindbc.libmicrohttpd.staticcfg;
else
	public import bindbc.libmicrohttpd.dynamiccfg;