/*
 * Copyright (c) 1999-2000
 *
 * The Regents of the University of Michigan ("The Regents") and
 * Merit Network, Inc. All rights reserved.  Redistribution and use
 * in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the
 * following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of
 * this software must display the following acknowledgement:
 *
 *   This product includes software developed by the University of
 *   Michigan, Merit Network, Inc., and their contributors.
 *
 * 4. Neither the name of the University, Merit Network, nor the
 * names of their contributors may be used to endorse or
 * promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL TH E REGENTS
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HO WEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Imported from the PHP agent

#include "radixlib.h"

#include <stdlib.h>
#include <string.h>

#define BIT_TEST(f, b) ((f) & (b))

#define PREFIX_TO_CHAR(prefix) ((char*) &(prefix)->add)
#define PREFIX_TO_UCHAR(prefix) ((uint8_t*) &(prefix)->add)

#define RADIX_MAXBITS 128

static int _comp_with_mask(uint8_t* addr, uint8_t* dest, uint8_t mask)
{
    if (memcmp(addr, dest, mask / 8) == 0)
    {
        uint8_t n = mask / 8;
        uint8_t m = (uint8_t)((~0U) << (8 - (mask % 8)));

        if (mask % 8 == 0 || (addr[n] & m) == (dest[n] & m))
            return 1;
    }
    return 0;
}

prefix_t* radix_prefix_init(uint8_t family, void* addr, uint8_t bitlen, prefix_t* _prefix)
{
    bool dynamic_allocated = false;
    prefix_t* prefix;

    if (family == FAMILY_IPv6)
    {
        if (_prefix == NULL)
        {
            prefix            = calloc(1, sizeof(*prefix));
            dynamic_allocated = true;
        }
        else
        {
            prefix = (prefix_t*) _prefix;
        }
        memcpy(&prefix->add.sin6, addr, 16);
    }
    else //if (family == FAMILY_IPv4)
    {
        if (_prefix == NULL)
        {
            prefix            = calloc(1, sizeof(*prefix));
            dynamic_allocated = true;
        }
        else
        {
            prefix = (prefix_t*) _prefix;
        }
        memcpy(&prefix->add.sin, addr, 4);
    }

    prefix->bitlen    = bitlen;
    prefix->family    = family;
    prefix->ref_count = 0;
    if (dynamic_allocated)
    {
        prefix->ref_count++;
    }
    return prefix;
}

static prefix_t* _prefix_addref(prefix_t* prefix)
{
    if (prefix == NULL)
    {
        return NULL;
    }
    if (prefix->ref_count == 0)
    {
        /* make a copy in case of a static prefix */
        return radix_prefix_init(prefix->family, &prefix->add, prefix->bitlen, NULL);
    }
    prefix->ref_count++;
    return prefix;
}

static void _radix_prefix_delref(prefix_t* prefix)
{
    if (prefix == NULL)
    {
        return;
    }

    prefix->ref_count--;
    if (prefix->ref_count <= 0)
    {
        free(prefix);
        return;
    }
}

/*
 * Originally from MRT lib/radix/radix.c
 * $MRTId: radix.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

/* these routines support continuous mask only */

radix_tree_t* radix_new(uint8_t max_bits)
{
    radix_tree_t* radix;

    radix = calloc(1, sizeof(*radix));

    radix->maxbits = max_bits;
    radix->head    = NULL;
    return radix;
}

static void _radix_clear(radix_tree_t* radix)
{
    if (!radix->head)
    {
        return;
    }

    radix_node_t* Xstack[RADIX_MAXBITS + 1];
    radix_node_t** Xsp = Xstack;
    radix_node_t* Xrn  = radix->head;

    while (Xrn)
    {
        radix_node_t* l = Xrn->l;
        radix_node_t* r = Xrn->r;

        if (Xrn->prefix)
        {
            _radix_prefix_delref(Xrn->prefix);
        }
        free(Xrn);

        if (l)
        {
            if (r)
                *Xsp++ = r;
            Xrn = l;
        }
        else if (r)
        {
            Xrn = r;
        }
        else if (Xsp != Xstack)
        {
            Xrn = *(--Xsp);
        }
        else
        {
            Xrn = (radix_node_t*) 0;
        }
    }
}

void radix_free(radix_tree_t* radix)
{
    _radix_clear(radix);
    free(radix);
}

radix_node_t* radix_matching_do(radix_tree_t* radix, prefix_t* prefix)
{
    radix_node_t* node;
    radix_node_t* stack[RADIX_MAXBITS + 1];
    uint8_t* addr;
    uint8_t bitlen;
    unsigned cnt = 0;

    if (radix->head == NULL)
        return NULL;

    addr   = PREFIX_TO_UCHAR(prefix);
    bitlen = prefix->bitlen;

    node = radix->head;
    while (node->bit < bitlen)
    {
        if (node->prefix)
            stack[cnt++] = node;
        if (BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
            node = node->r;
        else
            node = node->l;

        if (node == NULL)
            break;
    }

    if (node && node->prefix)
        stack[cnt++] = node;

    node = NULL;
    while (cnt > 0)
    {
        radix_node_t *curnode = stack[--cnt];

        if (_comp_with_mask(PREFIX_TO_UCHAR(curnode->prefix), PREFIX_TO_UCHAR(prefix),
                curnode->prefix->bitlen))
	{
            if (node == NULL || curnode->expiration == 0 || curnode->expiration > node->expiration)
            {
                node = curnode;
                if (node->expiration == 0)
                    break;
            }
        }
    }

    return node;
}

radix_node_t *radix_put_if_absent(radix_tree_t *radix, prefix_t *prefix, uint64_t expiration)
{
    radix_node_t *node, *new_node, *parent, *glue;
    uint8_t *addr, *test_addr;
    uint8_t bitlen, check_bit;
    uint16_t differ_bit;

    if (radix->head == NULL)
    {
        node = calloc(1, sizeof(*node));

        node->bit    = prefix->bitlen;
        node->prefix = _prefix_addref(prefix);
        node->parent = NULL;
        node->l = node->r = NULL;
        node->expiration = expiration;
        radix->head = node;

        return node;
    }
    addr   = PREFIX_TO_UCHAR(prefix);
    bitlen = prefix->bitlen;
    node   = radix->head;

    while (node->bit < bitlen || node->prefix == NULL)
    {
        if (node->bit < radix->maxbits && BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
        {
            if (node->r == NULL)
                break;
            node = node->r;
        }
        else
        {
            if (node->l == NULL)
                break;
            node = node->l;
        }
    }

    test_addr = PREFIX_TO_UCHAR(node->prefix);
    /* find the first bit different */
    check_bit  = (node->bit < bitlen) ? node->bit : bitlen;
    differ_bit = 0;
    for (uint16_t i = 0, j; i * 8 < check_bit; i++)
    {
        uint8_t r = addr[i] ^ test_addr[i];
        if (r == 0)
        {
            differ_bit = (i + 1) * 8;
            continue;
        }
        /* I know the better way, but for now */
        for (j = 0; j < 8; j++)
        {
            if (BIT_TEST(r, (0x80 >> j)))
                break;
        }
        /* must be found */
        differ_bit = i * 8 + j;
        break;
    }
    if (differ_bit > check_bit)
        differ_bit = check_bit;

    parent = node->parent;
    while (parent && parent->bit >= differ_bit)
    {
        node   = parent;
        parent = node->parent;
    }

    if (differ_bit == bitlen && node->bit == bitlen)
    {
        if (node->prefix == NULL)
        {
            node->prefix = _prefix_addref(prefix);
            node->expiration = expiration;
        } else if (node->expiration != 0 && (expiration == 0 || expiration > node->expiration)) {
            /* Update the expiration if it lasts longer than the existing one */
            node->expiration = expiration;
        }
        /* leaves current prefix in place of replacing it with argument */
        return node;
    }

    new_node         = calloc(1, sizeof(*new_node));
    new_node->bit    = prefix->bitlen;
    new_node->prefix = _prefix_addref(prefix);
    new_node->parent = NULL;
    new_node->expiration = expiration;
    new_node->l = new_node->r = NULL;

    if (node->bit == differ_bit)
    {
        new_node->parent = node;
        if (node->bit < radix->maxbits && BIT_TEST(addr[node->bit >> 3], 0x80 >> (node->bit & 0x07)))
            node->r = new_node;
        else
            node->l = new_node;

        return new_node;
    }
    if (bitlen == differ_bit)
    {
        if (bitlen < radix->maxbits && BIT_TEST(test_addr[bitlen >> 3], 0x80 >> (bitlen & 0x07)))
            new_node->r = node;
        else
            new_node->l = node;

        new_node->parent = node->parent;
        if (node->parent == NULL)
            radix->head = new_node;
        else if (node->parent->r == node)
            node->parent->r = new_node;
        else
            node->parent->l = new_node;

        node->parent = new_node;
    }
    else
    {
        glue = calloc(1, sizeof(*glue));

        glue->bit    = (uint8_t) differ_bit;
        glue->prefix = NULL;
        glue->parent = node->parent;
        if (differ_bit < radix->maxbits && BIT_TEST(addr[differ_bit >> 3], 0x80 >> (differ_bit & 0x07)))
        {
            glue->r = new_node;
            glue->l = node;
        }
        else
        {
            glue->r = node;
            glue->l = new_node;
        }
        new_node->parent = glue;

        if (node->parent == NULL)
            radix->head = glue;
        else if (node->parent->r == node)
            node->parent->r = glue;
        else
            node->parent->l = glue;

        node->parent = glue;
    }
    return new_node;
}
