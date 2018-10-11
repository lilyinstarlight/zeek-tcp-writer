##! Log writer for sending logs to TCP.

module LogTCP;

export {
	## TCP address and port of the subscriber.
	##
	## This value can be overridden on a per-filter basis in a
	## filter's "config" table.
	const host: string = "" &redef;
	const tcpport: int = 1337 &redef;
	const tls: bool = T &redef;
	const cert: string = "" &redef;
}
