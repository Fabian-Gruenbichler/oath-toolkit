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

#define MAX_DIGIT 10
#define MAX_ITER 20

const char *secret1 = "12345678901234567890";
const char *secret2 = "12345678901234567890123456789012";
const char *secret3 = "1234567890123456789012345678901234567890123456789012345678901234";
const char *pHash = "\x71\x10\xed\xa4\xd0\x9e\x06\x2a\xa5\xe4\xa3\x90\xb0\xa5\x72\xac\x0d\x2c\x02\x20";

const char *suite1 = "OCRA-1:HOTP-SHA1-6:QN08";
const char *suite2 = "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1"; // actually sha256
const char *suite3 = "OCRA-1:HOTP-SHA1-8:QN08-PSHA1"; // 256

const struct {
    char *secret;
    char *ocra_suite;
    uint64_t counter;
    char *challenges_hex;
    char *session;
    time_t secs;
    char *ocra;
} tv[] = {
    /* From RFC 6287. */
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "000000000", NULL, 0, "237653" },
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "A98AC7", NULL, 0, "243178" },
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "153158E0", NULL, 0, "653583" },
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "1FCA0550", NULL, 0, "740991" },
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "2A62B1C0", NULL, 0, "608993" },
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "34FB5E30", NULL, 0, "388898" },
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "3F940AA0", NULL, 0, "816933" },
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "4A2CB710", NULL, 0, "224598" },
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "54C56380", NULL, 0, "750600" },
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "5F5E0FF0", NULL, 0, "294470" },
    /* From RFC 6287, modified to use SHA1 */
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 0, "BC614E", NULL, 0, "54935162"},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 1, "BC614E", NULL, 0, "04872189"},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 2, "BC614E", NULL, 0, "61331807"},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 3, "BC614E", NULL, 0, "32008934"},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 4, "BC614E", NULL, 0, "61397730"},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 5, "BC614E", NULL, 0, "32585279"},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 6, "BC614E", NULL, 0, "73120191"},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 7, "BC614E", NULL, 0, "81525786"},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 8, "BC614E", NULL, 0, "54862057"},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 9, "BC614E", NULL, 0, "28506332"}
};


    int
main (void)
{
    oath_rc rc;
    int i;

    rc = oath_init ();
    if (rc != OATH_OK)
    {
        printf ("oath_init: %d\n", rc);
        return 1;
    }

    for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
        char output_ocra[strlen(tv[i].ocra)+1];
        size_t bin_length=0;
        rc = oath_hex2bin(tv[i].challenges_hex,NULL,&bin_length);
        char challenges_bin[bin_length];
        rc = oath_hex2bin(tv[i].challenges_hex,challenges_bin,&bin_length);

        rc = oath_ocra_generate(tv[i].secret, strlen(tv[i].secret), 
                tv[i].ocra_suite, strlen(tv[i].ocra_suite), 
                tv[i].counter, challenges_bin, 
                bin_length, pHash, 
                tv[i].session, tv[i].secs, output_ocra);

        if (rc != OATH_OK) {
            printf ("oath_ocra_generate at %d: %d\n",i,rc);
            return 1;
        }

        if(strcmp(output_ocra,tv[i].ocra)!=0) {
            printf ("wrong ocra value at %d: %s / %s\n",i,output_ocra,tv[i].ocra);
            return 1;
        }
    }
}
