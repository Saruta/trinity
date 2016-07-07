#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "log.h"
#include "net.h"
#include "domains.h"
#include "params.h"
#include "utils.h"
#include "compat.h"

struct domain {
	const char *name;
	const unsigned int domain;
};

static const struct domain domains[] = {
	{ "UNSPEC",	AF_UNSPEC },
	{ "LOCAL",	AF_LOCAL },
	{ "UNIX",	AF_LOCAL },
	{ "FILE",	AF_LOCAL },
	{ "INET",	AF_INET },
	{ "AX25",	AF_AX25 },
	{ "IPX",	AF_IPX },
	{ "APPLETALK",	AF_APPLETALK },
	{ "NETROM",	AF_NETROM },
	{ "BRIDGE",	AF_BRIDGE },
	{ "ATMPVC",	AF_ATMPVC },
	{ "X25",	AF_X25 },
	{ "INET6",	AF_INET6 },
	{ "ROSE",	AF_ROSE },
	{ "DECnet",	AF_DECnet },
	{ "NETBEUI",	AF_NETBEUI },
	{ "SECURITY",	AF_SECURITY },
	{ "KEY",	AF_KEY },
	{ "NETLINK",	AF_NETLINK },
	{ "ROUTE",	AF_NETLINK },
	{ "PACKET",	AF_PACKET },
	{ "ASH",	AF_ASH },
	{ "ECONET",	AF_ECONET },
	{ "ATMSVC",	AF_ATMSVC },
	{ "RDS",	AF_RDS },
	{ "SNA",	AF_SNA },
	{ "IRDA",	AF_IRDA },
	{ "PPPOX",	AF_PPPOX },
	{ "WANPIPE",	AF_WANPIPE },
	{ "LLC",	AF_LLC },
	{ "IB",		AF_IB  },
	{ "MPLS",	AF_MPLS },
	{ "CAN",	AF_CAN },
	{ "TIPC",	AF_TIPC },
	{ "BLUETOOTH",	AF_BLUETOOTH },
	{ "IUCV",	AF_IUCV },
	{ "RXRPC",	AF_RXRPC },
	{ "ISDN",	AF_ISDN },
	{ "PHONET",	AF_PHONET },
	{ "IEEE802154",	AF_IEEE802154 },
	{ "CAIF",	AF_CAIF },
	{ "ALG",	AF_ALG },
	{ "NFC",	AF_NFC },
	{ "VSOCK",	AF_VSOCK },
};

static const struct domain *lookup_domain(const char *name)
{
	unsigned int i;

	if (!name)
		return NULL;

	if (strncmp(name, "AF_", 3) == 0)
		name += 3;

	for (i = 0; i < ARRAY_SIZE(domains); i++) {
		if (strncmp(name, domains[i].name, strlen(domains[i].name)) == 0)
			return &domains[i];
	}

	return NULL;
}

const char * get_domain_name(unsigned int domain)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(domains); i++)
		if (domains[i].domain == domain)
			return domains[i].name;
	return NULL;
}

void find_specific_domain(const char *domainarg)
{
	const struct domain *p;
	unsigned int i;

	p = lookup_domain(domainarg);
	if (p) {
		specific_domain = p->domain;
		output(2, "Using domain %s for all sockets\n", p->name);
		return;
	}

	outputerr("Domain unknown. Pass one of ");
	for (i = 0; i < ARRAY_SIZE(domains); i++)
		outputerr("%s ", domains[i].name);
	outputerr("\n");

	exit(EXIT_FAILURE);
}

unsigned int find_next_enabled_domain(unsigned int from)
{
	unsigned int i;

	from %= ARRAY_SIZE(no_domains);

	for (i = from; i < ARRAY_SIZE(no_domains); i++) {
		if (no_domains[i] == FALSE)
			return no_domains[i];
	}

	for (i = 0; i < from; i++) {
		if (no_domains[i] == FALSE)
			return no_domains[i];
	}

	return -1u;
}

void parse_exclude_domains(const char *arg)
{
	char *_arg = strdup(arg);
	const struct domain *p;
	char *tok;

	if (!_arg) {
		outputerr("No free memory\n");
		exit(EXIT_FAILURE);
	}

	for (tok = strtok(_arg, ","); tok; tok = strtok(NULL, ",")) {
		p = lookup_domain(tok);
		if (p) {
			BUG_ON(p->domain >= ARRAY_SIZE(no_domains));
			no_domains[p->domain] = TRUE;
		} else
			goto err;
	}

	free(_arg);
	return;

err:
	free(_arg);
	outputerr("Domain unknown in argument %s\n", arg);
	exit(EXIT_FAILURE);
}
