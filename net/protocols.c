#include <sys/socket.h>
#include "config.h"
#include "net.h"
#include "compat.h"

const struct protoptr net_protocols[TRINITY_AF_MAX] = {
	[AF_UNIX] = { .proto = &proto_unix },
	[AF_INET] = { .proto = &proto_ipv4 },
	[AF_AX25] = { .proto = &proto_ax25 },
	[AF_IPX] = { .proto = &proto_ipx },
#ifdef USE_APPLETALK
	[AF_APPLETALK] = { .proto = &proto_appletalk },
#endif
	[AF_X25] = { .proto = &proto_x25 },
#ifdef USE_IPV6
	[AF_INET6] = { .proto = &proto_inet6 },
#endif
	[AF_DECnet] = { .proto = &proto_decnet },
	[AF_PACKET] = { .proto = &proto_packet },
	[AF_ECONET] = { .proto = &proto_econet },
#ifdef USE_RDS
	[AF_RDS] = { .proto = &proto_rds },
#endif
	[AF_IRDA] = { .proto = &proto_irda },
	[AF_LLC] = { .proto = &proto_llc },
	[AF_CAN] = { .proto = &proto_can },
	[AF_TIPC] = { .proto = &proto_tipc },
	[AF_BLUETOOTH] = { .proto = &proto_bluetooth },
	[AF_PHONET] = { .proto = &proto_phonet },
#ifdef USE_CAIF
	[AF_CAIF] = { .proto = &proto_caif },
#endif
	[AF_NFC] = { .proto = &proto_nfc },
#ifdef USE_NETROM
	[AF_NETROM] = { .proto = &proto_netrom },
#endif
	[AF_NETLINK] = { .proto = &proto_netlink },
#ifdef USE_ROSE
	[AF_ROSE] = { .proto = &proto_rose },
#endif
	[AF_ATMPVC] = { .proto = &proto_atmpvc },
	[AF_ATMSVC] = { .proto = &proto_atmsvc },
	[AF_NETBEUI] = { .proto = &proto_netbeui },
	[AF_PPPOX] = { .proto = &proto_pppol2tp },
	[AF_IUCV] = { .proto = &proto_iucv },
	[AF_RXRPC] = { .proto = &proto_rxrpc },
#ifdef USE_IF_ALG
	[AF_ALG] = { .proto = &proto_alg },
#endif
	[AF_KCM] = { .proto = &proto_kcm },
};
