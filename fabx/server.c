/*
OpenIO SDS fabx
Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <glib.h>

#include <rdma/fabric.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_cm.h>

#include <core/oio_core.h>
#include <metautils/lib/metautils.h>

static gboolean config_system = TRUE;
static GSList *config_paths = NULL;
static gchar config_host[256];
static gchar config_port[32];
static gchar config_ns[LIMIT_LENGTH_NSNAME];

static GThreadPool *pool_workers = NULL;

/* ------------------------------------------------------------------------- */

static const guint64 caps = FI_MSG;

static struct fi_info *info = NULL;
static struct fid_fabric *fabric = NULL;
static struct fid_domain *domain = NULL;
static struct fid_eq *event_queue = NULL;
static struct fid_pep *passive_endpoint = NULL;

/* ------------------------------------------------------------------------- */

struct active_cnx_context_s
{
	struct fid_ep *endpoint;
	struct fid_cq *cq_tx;
	struct fid_cq *cq_rx;
	struct fid_av *av;
	struct fid_eq *eq;
};

static guint8 *_base(guint8 *s) { return s + sizeof(long) - ((unsigned long)s % sizeof(long)); }

static void
_worker(gpointer data, gpointer context UNUSED)
{
	struct active_cnx_context_s *ctx = data;
	g_assert(ctx != NULL);

	ssize_t sz;
	fi_addr_t src_addr = {0};

	guint8 blob[(1024*1024)+sizeof(long)];

	/* Ensure a buffer well aligned */
	guint8 *base = _base(blob);
	size_t length = 1024 * 1024;

	g_strlcpy((char*)base, "plop", length);

	for (;;) {
		/* Post a read order */
		sz = fi_recv(ctx->endpoint, base, length, NULL, src_addr, ctx);
		GRID_WARN("fi_recv rc %ld", sz);
		g_assert(sz == 0);

		/* Wait for the completion of the read command */
		struct fi_cq_entry cq_entry = {NULL};
		sz = fi_cq_sread(ctx->cq_rx, &cq_entry, 1, NULL, -1);
		GRID_WARN("fi_cq_sread rc %ld", sz);
		g_assert(sz == 1);

		GRID_WARN("> %.*s", 4, (char *) base);
	}
}

static int
fi_lookup(const char *host, const char *port,
		gboolean local, struct fi_info **result)
{
	struct fi_info *out = NULL;
	struct fi_info *hints = fi_allocinfo();
	*result = NULL;

	hints->caps = caps;
	hints->addr_format = FI_SOCKADDR;
    hints->domain_attr->threading = FI_THREAD_SAFE;
    hints->domain_attr->data_progress = FI_PROGRESS_AUTO;
    hints->domain_attr->control_progress = FI_PROGRESS_AUTO;
    hints->tx_attr->msg_order = FI_ORDER_SAS;
    hints->rx_attr->msg_order = FI_ORDER_SAS;

	int rc = fi_getinfo(FI_VERSION(1, 6),
			host, port,
			local ? FI_SOURCE : 0,
			hints, &out);
	if (rc != 0)
		return rc;

	for (struct fi_info *fi0 = out; fi0; fi0 = fi0->next) {
		if (((fi0->caps & caps) == caps)
				&& fi0->ep_attr->protocol == FI_PROTO_SOCK_TCP
				&& fi0->addr_format == FI_SOCKADDR_IN
				&& fi0->ep_attr->type == FI_EP_MSG) {
			*result = fi_dupinfo(fi0);
			break;
		}
	}

	fi_freeinfo(hints);
	fi_freeinfo(out);
	return (*result == NULL) ? -FI_ENODATA : 0;
}

static void
_manage_cnx_event(struct fi_eq_cm_entry *cm_entry)
{
	struct active_cnx_context_s ctx = {};
	guint32 event;
	int rc;
	ssize_t sz;

	/* Allocate an new endpoint for the connection */
	if (!cm_entry->info->domain_attr->domain) {
		rc = fi_domain(fabric, cm_entry->info, &domain, NULL);
		g_assert(rc == 0);
	}
	rc = fi_endpoint(domain, cm_entry->info, &ctx.endpoint, NULL);
	g_assert(rc == 0);

	struct fi_eq_attr eq_attr = {};
	eq_attr.size = 1;
	eq_attr.wait_obj = FI_WAIT_UNSPEC;
	rc = fi_eq_open(fabric, &eq_attr, &ctx.eq, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(ctx.endpoint, &ctx.eq->fid, 0);
	g_assert(rc == 0);
	//ctx.eq = event_queue;
	//rc = fi_ep_bind(ctx.endpoint, &ctx.eq->fid, 0);
	g_assert(rc == 0);


	struct fi_cq_attr cq_attr = {};
	cq_attr.wait_obj = FI_WAIT_UNSPEC;
	cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	cq_attr.size = info->tx_attr->size;
	rc = fi_cq_open(domain, &cq_attr, &ctx.cq_tx, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(ctx.endpoint, &ctx.cq_tx->fid, FI_TRANSMIT);
	g_assert(rc == 0);

	cq_attr.wait_obj = FI_WAIT_UNSPEC;
	cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	cq_attr.size = info->rx_attr->size;
	rc = fi_cq_open(domain, &cq_attr, &ctx.cq_rx, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(ctx.endpoint, &ctx.cq_rx->fid, FI_RECV);
	g_assert(rc == 0);


	struct fi_av_attr av_attr = {};
	av_attr.type = info->domain_attr->av_type;
	av_attr.count = 1;
	rc = fi_av_open(domain, &av_attr, &ctx.av, NULL);
	g_assert(rc == 0);

	rc = fi_accept(ctx.endpoint, NULL, 0);
	g_assert(rc == 0);
	rc = fi_enable(ctx.endpoint);
	g_assert(rc == 0);

	GRID_WARN("Polling the connection confirmation");
	struct fi_eq_cm_entry cm_entry1 = {};
	sz = fi_eq_sread(
			ctx.eq, &event,
			&cm_entry1, sizeof(cm_entry1), -1, 0);
	GRID_WARN("Event rc %ld "
			  "event %" G_GINT32_MODIFIER "d/%" G_GINT32_MODIFIER "x",
			  sz, event, event);
	g_assert(event == FI_CONNECTED);

	/* Defer to a worker thread */
	g_thread_pool_push(pool_workers, g_memdup(&ctx, sizeof(ctx)), NULL);
	//_worker(&ctx, NULL);
}

static void
_manage_passive_events(void)
{
	struct fi_eq_cm_entry cm_entry = {};
	guint32 event = 0;

	ssize_t sz = fi_eq_sread(event_queue,
			&event, &cm_entry, sizeof(cm_entry), -1, 0);
	GRID_WARN("fi_eq_sread rc %ld "
			"event %" G_GINT32_MODIFIER "d/%" G_GINT32_MODIFIER "x",
			sz, event, event);
	switch (event) {
		case FI_CONNREQ:
			return _manage_cnx_event(&cm_entry);
		default:
			return;
	}
}

static void
_action (void)
{
	while (grid_main_is_running())
		_manage_passive_events();
	GRID_WARN("Exiting");
}

static gboolean
_configure (int argc, char **argv)
{
	if (argc != 2) {
		GRID_ERROR("Missing argument");
		return FALSE;
	} else {
		gchar url[256], *p_colon = NULL;
		g_strlcpy(url, argv[0], sizeof(url));
		g_strlcpy(config_ns, argv[1], sizeof(config_ns));
		if (!(p_colon = strrchr(url, ':'))) {
			GRID_ERROR("Malformed URL");
			return FALSE;
		} else {
			*p_colon = 0;
			g_strlcpy(config_host, url, sizeof(config_host));
			g_strlcpy(config_port, p_colon + 1, sizeof(config_port));
		}
	}

	/* Load the env and ensure the NS exists */
	if (!oio_var_value_with_files(config_ns, config_system, config_paths)) {
		GRID_ERROR("NS [%s] unknown in the configuration", config_ns);
		return FALSE;
	}

	/* Prepare the concurrency context */
	GError *err = NULL;
	pool_workers = g_thread_pool_new(_worker, NULL, -1, FALSE, &err);
	if (!pool_workers) {
		GRID_ERROR("ThreadPool creation error: %s", err->message);
		return FALSE;
	}

	/* Prepare the libfabric context */
	int rc;

	rc = fi_lookup(config_host, config_port, TRUE, &info);
	g_assert(rc == 0);
	rc = fi_fabric(info->fabric_attr, &fabric, NULL);
	g_assert(rc == 0);
	rc = fi_domain(fabric, info, &domain, NULL);
	g_assert(rc == 0);
	rc = fi_passive_ep(fabric, info, &passive_endpoint, NULL);
	g_assert(rc == 0);

	struct fi_eq_attr eq_attr = {};
	//eq_attr.size = 1;
	eq_attr.wait_obj = FI_WAIT_UNSPEC;
	rc = fi_eq_open(fabric, &eq_attr, &event_queue, NULL);
	g_assert(rc == 0);
	rc = fi_pep_bind(passive_endpoint, &event_queue->fid, 0);
	g_assert(rc == 0);
	rc = fi_listen(passive_endpoint);
	g_assert(rc == 0);

	GRID_INFO("Passive Endpoint listening - provider:%s domain:%s fabric:%s",
			info->fabric_attr->prov_name,
			info->domain_attr->name,
			info->fabric_attr->name);

	return TRUE;
}

static struct grid_main_option_s *
_get_options (void)
{
	static struct grid_main_option_s options[] = {
		{"SysConfig", OT_BOOL, {.b = &config_system},
			"Load the system configuration and overload the central variables"},

		{"Config", OT_LIST, {.lst = &config_paths},
			"Load the given file and overload the central variables"},

		{NULL, 0, {.i = 0}, NULL}
	};

	return options;
}

static void
_specific_fini (void)
{
	if (pool_workers != NULL) {
		g_thread_pool_free(pool_workers, FALSE, TRUE);
		pool_workers = NULL;
	}
	if (config_paths) {
		g_slist_free_full(config_paths, g_free);
		config_paths = NULL;
	}
}

static void
_set_defaults (void)
{
	config_system = TRUE;
	config_paths = NULL;
	memset(config_host, 0, sizeof(config_host));
	memset(config_port, 0, sizeof(config_port));
	memset(config_ns, 0, sizeof(config_ns));
	pool_workers = NULL;
}

static void _specific_stop (void) {}

static const char * _get_usage (void) { return "IP:PORT NS"; }

static struct grid_main_callbacks main_callbacks =
{
	.options = _get_options,
	.action = _action,
	.set_defaults = _set_defaults,
	.specific_fini = _specific_fini,
	.configure = _configure,
	.usage = _get_usage,
	.specific_stop = _specific_stop,
};

int
main (int argc, char **argv)
{
	return grid_main (argc, argv, &main_callbacks);
}
