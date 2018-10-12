##! Log writer for sending logs to TCP.

module LogTCP;

export {
	## TCP connection details. Retry will cause the
	## writer to not throw an error when a connection fails
	## and simply keep retrying. TLS negotiates TLS with the
	## TCP server. Cert is an optional path to a trusted CA
	## or server certificate.
	##
	## This value can be overridden on a per-filter basis in a
	## filter's "config" table.
	const host: string = "" &redef;
	const tcpport: int = 1337 &redef;
	const retry: bool = F &redef;
	const tls: bool = F &redef;
	const cert: string = "" &redef;
}
