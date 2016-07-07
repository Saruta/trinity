#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <netipx/ipx.h>
#include "net.h"
#include "random.h"
#include "utils.h"

static void ipx_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ipx *ipx;
	unsigned int i;

	ipx = zmalloc(sizeof(struct sockaddr_ipx));

	ipx->sipx_family = AF_IPX;
	ipx->sipx_port = rnd();
	ipx->sipx_network = rnd();
	for (i = 0; i < 6; i++)
		ipx->sipx_node[i] = rnd();
	ipx->sipx_type = rnd();
	ipx->sipx_zero = RAND_BOOL();
	*addr = (struct sockaddr *) ipx;
	*addrlen = sizeof(struct sockaddr_ipx);
}

static void ipx_rand_socket(struct socket_triplet *st)
{
	st->protocol = rnd() % PROTO_MAX;
	st->type = SOCK_DGRAM;
}

static void ipx_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_IPX;
	so->optname = IPX_TYPE;
}

const struct netproto proto_ipx = {
	.name = "ipx",
	.socket = ipx_rand_socket,
	.setsockopt = ipx_setsockopt,
	.gen_sockaddr = ipx_gen_sockaddr,
};
