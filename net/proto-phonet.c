#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/phonet.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"
#include "compat.h"

static void phonet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_pn *pn;

	pn = zmalloc(sizeof(struct sockaddr_pn));

	pn->spn_family = AF_PHONET;
	pn->spn_obj = rnd();
	pn->spn_dev = rnd();
	pn->spn_resource = rnd();
	*addr = (struct sockaddr *) pn;
	*addrlen = sizeof(struct sockaddr_pn);
}

static void phonet_rand_socket(struct socket_triplet *st)
{
	st->protocol = 0;
	if (RAND_BOOL())
		st->type = SOCK_DGRAM;
	else
		st->type = SOCK_SEQPACKET;
}

#define SOL_PNPIPE 275

static void phonet_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_PNPIPE;
}

const struct netproto proto_phonet = {
	.name = "phonet",
	.socket = phonet_rand_socket,
	.setsockopt = phonet_setsockopt,
	.gen_sockaddr = phonet_gen_sockaddr,
};
