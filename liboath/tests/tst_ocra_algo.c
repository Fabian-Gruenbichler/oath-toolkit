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
    const char *secret = "000000";
    char suite[] = "OCRA-1:HOTP-SHA1-5:C-QN05-S064-T05H-PSHA1";

    rc = oath_ocra_generate(secret, strlen(secret), 
            suite, strlen(suite), 
            0, NULL, 0, NULL, NULL, NULL, NULL);

    if (rc != OATH_OK) {
        printf ("oath_ocra_generate: %d\n",rc);
        return 1;
    }
}
