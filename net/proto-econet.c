#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <neteconet/ec.h>
#include <stdlib.h>
#include "net.h"
#include "random.h"
#include "utils.h"

static void econet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ec *ec;

	ec = zmalloc(sizeof(struct sockaddr_ec));

	ec->sec_family = AF_ECONET;
	ec->port = rnd();
	ec->cb = rnd();
	ec->type = rnd();
	ec->addr.station = rnd();
	ec->addr.net = rnd();
	ec->cookie = rnd();
	*addr = (struct sockaddr *) ec;
	*addrlen = sizeof(struct sockaddr_ec);
}

const struct netproto proto_econet = {
	.name = "econet",
	.gen_sockaddr = econet_gen_sockaddr,
};
