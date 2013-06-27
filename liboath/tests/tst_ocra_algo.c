/*
 * tst_ocra_algo.c - self-tests for liboath OCRA algorithm functions
 * Copyright (C) 2013 Fabian Grünbichler
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#include <config.h>

#include "oath.h"

#include <stdio.h>

#define MAX_DIGIT 8
#define MAX_ITER 20

int
main (void)
{
    oath_rc rc;

    rc = oath_init ();
    if (rc != OATH_OK)
    {
        printf ("oath_init: %d\n", rc);
        return 1;
    }
    const char *secret = "12345678901234567890";
    char suite[] = "OCRA-1:HOTP-SHA1-6:QN08";
//    char suite[] = "OCRA-1:HOTP-SHA1-5:C-QA26-PSHA1-S021-T30S";
    uint64_t counter = 12356789;
    char challenges_hex[] = "5F5E0FF"; // 99999999
    size_t challenges_bin_length = strlen(challenges_hex)*2+1;
    char challenges_bin[challenges_bin_length];
    oath_hex2bin(challenges_hex,challenges_bin,&challenges_bin_length);
    char pHash[20] = "\xa9\x4a\x8f\xe5\xcc\xb1\x9b\xa6\x1c\x4c\x08\x73\xd3\x91\xe9\x87\x98\x2f\xbb\xd3";
    char session[] = "blablablablablablabla";
    time_t now = 90;
    char output_ocra[9];

    printf("length of key: %d\n",strlen(secret));

    rc = oath_ocra_generate(secret, strlen(secret), 
            suite, strlen(suite), 
            counter, challenges_bin, 
            strlen(challenges_bin), pHash, session, now, output_ocra);

    if (rc != OATH_OK) {
        printf ("oath_ocra_generate: %d\n",rc);
        return 1;
    }
}
