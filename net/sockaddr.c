#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "arch.h"	// page_size
#include "net.h"
#include "params.h"	// do_specific_domain
#include "random.h"
#include "utils.h"	// ARRAY_SIZE

void generate_sockaddr(struct sockaddr **addr, socklen_t *addrlen, int pf)
{
	const struct netproto *proto;

	/* If we want sockets of a specific type, we'll want sockaddrs that match. */
	if (do_specific_domain == TRUE)
		pf = specific_domain;

	/* If we got no hint passed down, pick a random proto. */
	if (pf == -1)
		pf = rnd() % TRINITY_AF_MAX;

	proto = net_protocols[pf].proto;
	if (proto != NULL) {
		if (proto->gen_sockaddr != NULL) {
			proto->gen_sockaddr(addr, addrlen);
			return;
		}
	}

	/* Make something up for unknown protocols. */
	*addr = (struct sockaddr *) zmalloc(page_size);
	*addrlen = rnd() % page_size;
}
