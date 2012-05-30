/*
 * message.h  Basic D-Bus message parsing
 *
 * Copyright (C) 2010  Collabora Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef DBUS_MESSAGE_H
#define DBUS_MESSAGE_H

#include <linux/list.h>

/* No need to implement a feature-complete parser. It only implement what is
 * needed by the bus. */
struct dbus_message {
	char *message;
	size_t len;
	size_t new_len;

	/* direct pointers to the fields */
	int type;
	char *path;
	char *interface;
	char *member;
	char *destination;
	char *sender;
	char *body_signature;
	int body_length;
	char *arg0;
	char *arg1;
	char *arg2;
	char *name_acquired;
	char *name_lost;

	/* How to add the 'sender' field in the headers */
	int new_header_offset;
	int len_offset;
	int padding_end;
};

int dbus_message_type_from_string(const char *type_str);

const char *dbus_message_type_to_string(int type);

int dbus_message_parse(unsigned char *message, size_t len,
		       struct dbus_message *dbus_message);

int dbus_message_add_sender(struct dbus_message *dbus_message,
			    const char *sender, gfp_t gfp_flags);

#endif /* DBUS_MESSAGE_H */
