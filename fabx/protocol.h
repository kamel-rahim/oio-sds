/**
 * This file is part of @PROJECT_NAME@
 * Copyright (C) 2019 @PROJECT_OWNER@
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */

#ifndef OIOSDS_FABX_PROTOCOL_H
#define OIOSDS_FABX_PROTOCOL_H

#include <glib.h>

#include <core/oio_core.h>
#include <metautils/lib/metautils.h>

enum fabx_request_type_e {
	FABX_REQ_PUT = 1,
	FABX_REQ_DEL = 2,
	FABX_REQ_GET = 3,
	FABX_REQ_HEAD = 4,
};

struct fabx_request_header_PUT_s {
	guint32 block_size;
	char chunk_id[STRLEN_CHUNKID];
	char content_id[STRLEN_CONTAINERID];
	char content_version[LIMIT_LENGTH_VERSION];
	char ns_name[LIMIT_LENGTH_NSNAME];
	char account_name[LIMIT_LENGTH_ACCOUNTNAME];
	char user_name[LIMIT_LENGTH_USER];
	char content_path[LIMIT_LENGTH_CONTENTPATH];
} __attribute__((packed));

struct fabx_request_header_GET_s {
	char chunk_id[STRLEN_CHUNKID];
} __attribute__((packed));

struct fabx_request_header_DEL_s {
	char chunk_id[STRLEN_CHUNKID];
} __attribute__((packed));

union fabx_request_choice_u {
	struct fabx_request_header_PUT_s put;
	struct fabx_request_header_DEL_s del;
	struct fabx_request_header_GET_s get;
} __attribute__((packed));

struct fabx_request_header_s {
	guint16 version;
	enum fabx_request_type_e type : 16;
	guint8 request_id[LIMIT_LENGTH_REQID];
	char auth_token[128];
	union fabx_request_choice_u actual;
} __attribute__((packed));

/* ------------------------------------------------------------------------- */

enum fabx_reply_type_e {
	FABX_REP_PUT = 1,
	FABX_REP_DEL = 2,
	FABX_REP_GET = 3,
	FABX_REP_HEAD = 4,
};

struct fabx_reply_header_PUT_s {
	guint32 status;
} __attribute__((packed));

struct fabx_reply_header_DEL_s {
	guint32 status;
} __attribute__((packed));

struct fabx_reply_header_GET_s {
	guint32 status;
	char content_id[STRLEN_CONTAINERID];
	char content_version[LIMIT_LENGTH_VERSION];
	char account_name[LIMIT_LENGTH_USER];
	char user_name[LIMIT_LENGTH_USER];
	char content_path[LIMIT_LENGTH_CONTENTPATH];
} __attribute__((packed));


union fabx_reply_choice_u {
	struct fabx_reply_header_PUT_s put;
	struct fabx_reply_header_DEL_s del;
	struct fabx_reply_header_GET_s get;
} __attribute__((packed));

struct fabx_reply_header_s {
	guint16 version;
	enum fabx_reply_type_e type : 16;
	union fabx_reply_choice_u actual;
} __attribute__((packed));

#endif  // OIOSDS_FABX_PROTOCOL_H
