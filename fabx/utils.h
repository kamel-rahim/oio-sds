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
#include <sys/xattr.h>
#include <core/oio_core.h>


/* -------------------------------------------------------------------------- */
// from rawx-lib/src/attr_handler.c
# define ATTR_DOMAIN "user.grid"
# define ATTR_NAME_CONTENT_CONTAINER "content.container"
# define ATTR_NAME_CONTENT_PATH    "content.path"
# define ATTR_NAME_CONTENT_VERSION "content.version"
# define ATTR_NAME_CONTENT_ID      "content.id"

static volatile ssize_t longest_xattr = 2048;

static gchar *
_getxattr_from_fd(int fd, const char *attrname)
{
	ssize_t size;
	ssize_t s = longest_xattr;
	gchar *buf = g_malloc0(s);
retry:
	size = fgetxattr(fd, attrname, buf, s);
	if (size > 0)
		return buf;
	if (size == 0) {
		*buf = 0;
		return buf;
	}

	if (errno == ERANGE) {
		s = s*2;
		longest_xattr = 1 + MAX(longest_xattr, s);
		buf = g_realloc(buf, s);
		memset(buf, 0, s);
		goto retry;
	}

	int errsav = errno;
	g_free(buf);
	errno = errsav;
	return NULL;
}

static gboolean
_get (int fd, const char *k, gchar **pv)
{
	gchar *v = _getxattr_from_fd (fd, k);
	int errsav = errno;
	oio_str_reuse(pv, v);
	errno = errsav;
	return v != NULL;
}

#define GET(K,R) _get(fd, ATTR_DOMAIN "." K, &(R))
/* -------------------------------------------------------------------------- */
