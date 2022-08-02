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

#ifndef RADIXLIB_H
#define RADIXLIB_H

#include <stdbool.h>
#include <stdint.h>

#define FAMILY_IPv4 4
#define FAMILY_IPv6 6

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct _prefix_t
    {
        union
        {
            uint8_t sin[4];
            uint8_t sin6[16];
        } add;
        int ref_count;
        uint8_t family; /* AF_INET | AF_INET6 */
        uint8_t bitlen;
    } prefix_t;

    typedef struct _radix_node_t
    {
        prefix_t* prefix;             /* who we are in radix tree; null if glue */
        struct _radix_node_t *l, *r;  /* left and right children */
        struct _radix_node_t* parent; /* may be used */
        uint64_t expiration;          /* the expiration epoch of this entry */
        uint8_t bit;                  /* flag if this node used */
    } radix_node_t;

    typedef struct _radix_tree_t
    {
        radix_node_t* head;
        uint8_t maxbits;
    } radix_tree_t;

    prefix_t* radix_prefix_init(uint8_t family, void* addr, uint8_t bitlen, prefix_t* _prefix);

    radix_tree_t* radix_new(uint8_t max_bits);
    void radix_free(radix_tree_t* radix);

    bool radix_matching_do(radix_tree_t* radix, prefix_t* prefix);
    radix_node_t* radix_put_if_absent(radix_tree_t* radix, prefix_t* prefix);
    void radix_remove(radix_tree_t* radix, radix_node_t* node);

#ifdef __cplusplus
}
#endif

#endif /* RADIXLIB_H */
