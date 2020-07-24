/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/* Rules are needed for lists */

#ifndef LISTS_H
#define LISTS_H

#include "cdb/cdb.h"
#include "cdb/uint32.h"

#define LR_STRING_MATCH 0
#define LR_STRING_NOT_MATCH 1
#define LR_STRING_MATCH_VALUE 2

#define LR_ADDRESS_MATCH 10
#define LR_ADDRESS_NOT_MATCH 11
#define LR_ADDRESS_MATCH_VALUE 12

typedef struct ListNode {
    int loaded;
    char *cdb_filename;
    char *txt_filename;
    struct cdb cdb;
    struct ListNode *next;
    pthread_mutex_t mutex;
} ListNode;

typedef struct ListRule {
    int loaded;
    int field;
    int lookup_type;
    OSMatch *matcher;
    char *dfield;
    char *filename;
    ListNode *db;
    struct ListRule *next;
    pthread_mutex_t mutex;
} ListRule;

/**
 * @brief Create the rule list
 */
void OS_CreateListsList(void);

/**
 * @brief Add rule information to the list
 * @param new_listnode
 * @param cdblists
 * @return
 */
int OS_AddList( ListNode *new_listnode, ListNode **cdblists);

/**
 * @brief
 * @param listfile
 * @param cdblists
 * @return
 */
int Lists_OP_LoadList(char *listfile, ListNode **cdblists);

/**
 * @brief
 * @param
 * @param
 * @return
 */
int OS_DBSearchKey(ListRule *lrule, char *key);

/**
 * @brief
 * @param lrule
 * @param key
 * @param
 * @return
 */
int OS_DBSearch(ListRule *lrule, char *key, ListNode *l_node);

/**
 * @brief
 * @param l_node
 * @param lrule
 */
void OS_ListLoadRules(ListNode **l_node, ListRule **lrule);

/**
 * @brief
 * @param first_rule_list
 * @param lookup_type
 * @param field
 * @param dfield
 * @param listname
 * @param matcher
 * @param l_node
 * @return
 */
ListRule *OS_AddListRule(ListRule *first_rule_list, int lookup_type, int field,
                         const char *dfield, char *listname, OSMatch *matcher,
                         ListNode *l_node);

/**
 * @brief Get first listnode
 * @return os_analysisd_cdblists list
 */
ListNode *OS_GetFirstList(void);

/**
 * @brief
 * @param listname
 * @param l_node
 * @return
 */
ListNode *OS_FindList(const char *listname, ListNode *l_node);

/**
 * @brief Initialize the cdb lookup lists
 */
void Lists_OP_CreateLists(void);

#endif /* LISTS_H */
