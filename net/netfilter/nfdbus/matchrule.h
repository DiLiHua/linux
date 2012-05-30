/*
 * signals.h  Bus signal connection implementation
 *
 * Copyright (C) 2003  Red Hat, Inc.
 *
 * Licensed under the Academic Free License version 2.1
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

#ifndef BUS_SIGNALS_H
#define BUS_SIGNALS_H

#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <net/af_bus.h>

#include "message.h"
#include "dbus-protocol.h"


enum bus_match_flags {
	BUS_MATCH_MESSAGE_TYPE = 1 << 0,
	BUS_MATCH_INTERFACE    = 1 << 1,
	BUS_MATCH_MEMBER       = 1 << 2,
	BUS_MATCH_SENDER       = 1 << 3,
	BUS_MATCH_DESTINATION  = 1 << 4,
	BUS_MATCH_PATH         = 1 << 5,
	BUS_MATCH_ARGS         = 1 << 6
};

struct bus_match_rule *bus_match_rule_new(void);
struct bus_match_rule *bus_match_rule_ref(struct bus_match_rule *rule);
void bus_match_rule_unref(struct bus_match_rule *rule);

int bus_match_rule_set_message_type(struct bus_match_rule *rule, int type);
int bus_match_rule_set_interface(struct bus_match_rule *rule,
				 const char *interface);
int bus_match_rule_set_member(struct bus_match_rule *rule, const char *member);
int bus_match_rule_set_sender(struct bus_match_rule *rule, const char *sender);
int bus_match_rule_set_destination(struct bus_match_rule *rule,
				   const char *destination);
int bus_match_rule_set_path(struct bus_match_rule *rule, const char *path);
int bus_match_rule_set_arg(struct bus_match_rule *rule, int arg,
			   const char *value, int is_path);

struct bus_match_rule *bus_match_rule_parse(const char *rule_text);

struct rule_pool {
	/* Maps non-NULL interface names to a list of bus_match_rule */
	struct rb_root rules_by_iface;

	/* List of bus_match_rule which don't specify an interface */
	struct hlist_head rules_without_iface;
};

struct bus_match_maker {
	struct sockaddr_bus addr;

	struct hlist_node table_node;

	/* Pools of rules, grouped by the type of message they match. 0
	 * (DBUS_MESSAGE_TYPE_INVALID) represents rules that do not specify a
	 * message type.
	 */
	struct rule_pool rules_by_type[DBUS_NUM_MESSAGE_TYPES];

	struct rb_root names;
};


struct bus_match_maker *bus_matchmaker_new(void);
void bus_matchmaker_free(struct bus_match_maker *matchmaker);

int bus_matchmaker_add_rule(struct bus_match_maker *matchmaker,
			    struct bus_match_rule *rule);
void bus_matchmaker_remove_rule_by_value(struct bus_match_maker *matchmaker,
					 struct bus_match_rule *value);
void bus_matchmaker_remove_rule(struct bus_match_maker *matchmaker,
				struct bus_match_rule *rule);

bool bus_matchmaker_filter(struct bus_match_maker *matchmaker,
			   struct bus_match_maker *sender,
			   const struct dbus_message *message);

void bus_matchmaker_add_name(struct bus_match_maker *matchmaker,
			     const char *name);
void bus_matchmaker_remove_name(struct bus_match_maker *matchmaker,
				const char *name);

#endif /* BUS_SIGNALS_H */
