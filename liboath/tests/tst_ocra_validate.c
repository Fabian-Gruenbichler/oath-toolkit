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

const char *pHash = "\x71\x10\xed\xa4\xd0\x9e\x06\x2a\xa5\xe4\xa3\x90\xb0\xa5\x72\xac\x0d\x2c\x02\x20";

const struct {
    char *secret;
    char *ocra_suite;
    uint64_t counter;
    char *challenges_hex;
    char *session;
    time_t now;
    char *validate_ocra;
    int expected_rc;
} tv[] = {
    /* OCRA value modified */
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "000000000", NULL, 0, "237654" , OATH_STRCMP_ERROR},
    /* From RFC 6287. */
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "000000000", NULL, 0, "237653" , OATH_OK},
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "A98AC7", NULL, 0, "243178" , OATH_OK},
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "153158E0", NULL, 0, "653583" , OATH_OK},
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "1FCA0550", NULL, 0, "740991" , OATH_OK},
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "2A62B1C0", NULL, 0, "608993" , OATH_OK},
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "34FB5E30", NULL, 0, "388898" , OATH_OK},
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "3F940AA0", NULL, 0, "816933" , OATH_OK},
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "4A2CB710", NULL, 0, "224598" , OATH_OK},
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "54C56380", NULL, 0, "750600" , OATH_OK},
    { "12345678901234567890", "OCRA-1:HOTP-SHA1-6:QN08", 0, "5F5E0FF0", NULL, 0, "294470" , OATH_OK},
    /* From RFC 6287, modified to use SHA1 */
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 0, "BC614E", NULL, 0, "54935162", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 1, "BC614E", NULL, 0, "04872189", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 2, "BC614E", NULL, 0, "61331807", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 3, "BC614E", NULL, 0, "32008934", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 4, "BC614E", NULL, 0, "61397730", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 5, "BC614E", NULL, 0, "32585279", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 6, "BC614E", NULL, 0, "73120191", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 7, "BC614E", NULL, 0, "81525786", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 8, "BC614E", NULL, 0, "54862057", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:C-QN08-PSHA1", 9, "BC614E", NULL, 0, "28506332", OATH_OK},
    /* From RFC, changed to SHA1 */
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:QN08-PSHA1", 0, "00000000", NULL, 0, "03315581", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:QN08-PSHA1", 0, "A98AC7", NULL, 0, "29216175", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:QN08-PSHA1", 0, "153158E0", NULL, 0, "73602538", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:QN08-PSHA1", 0, "1FCA0550", NULL, 0, "83764441", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:QN08-PSHA1", 0, "2A62B1C0", NULL, 0, "46427248", OATH_OK},
    /* TODO :                         OCRA-1:HOTP-SHA512-8:C-QN08*/
    /* From RFC, changed to SHA1, epoch time 1206446790 == "Mar 25 2008, 12:06:30 GMT" */
    {"1234567890123456789012345678901234567890123456789012345678901234","OCRA-1:HOTP-SHA1-8:QN08-T1M", 0, "00000000", NULL, 1206446790, "53251232", OATH_OK},
    {"1234567890123456789012345678901234567890123456789012345678901234","OCRA-1:HOTP-SHA1-8:QN08-T1M", 0, "A98AC7", NULL, 1206446790, "51245531", OATH_OK},
    {"1234567890123456789012345678901234567890123456789012345678901234","OCRA-1:HOTP-SHA1-8:QN08-T1M", 0, "153158E0", NULL, 1206446790, "70654774", OATH_OK},
    {"1234567890123456789012345678901234567890123456789012345678901234","OCRA-1:HOTP-SHA1-8:QN08-T1M", 0, "1FCA0550", NULL, 1206446790, "07834989", OATH_OK},
    {"1234567890123456789012345678901234567890123456789012345678901234","OCRA-1:HOTP-SHA1-8:QN08-T1M", 0, "2A62B1C0", NULL, 1206446790, "73318629", OATH_OK},
    /* From RFC, changed to SHA, only server part, alpha-numeric
     * challenges hex-encoded */
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:QA08", 0, "434c4932323232305352563131313130", NULL, 0, "50170510", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:QA08", 0, "434c4932323232315352563131313131", NULL, 0, "36708682", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:QA08", 0, "434c4932323232325352563131313132", NULL, 0, "53418875", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:QA08", 0, "434c4932323232335352563131313133", NULL, 0, "32625183", OATH_OK},
    {"12345678901234567890123456789012", "OCRA-1:HOTP-SHA1-8:QA08", 0, "434c4932323232345352563131313134", NULL, 0, "86690266", OATH_OK}
    /* TODO: client part */
    /* TODO: OCRASuite (server computation) = OCRA-1:HOTP-SHA512-8:QA08 */
    /* TODO: OCRASuite (client computation) = OCRA-1:HOTP-SHA512-8:QA08-PSHA1 */
    /* TODO plain signature test vectors */

    /* Note: all of the TODOs are already covered test cases until SHA256/512 is
     *       available. */

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
        size_t bin_length=0;
        rc = oath_hex2bin(tv[i].challenges_hex,NULL,&bin_length);
        char challenges_bin[bin_length];
        rc = oath_hex2bin(tv[i].challenges_hex,challenges_bin,&bin_length);

        rc = oath_ocra_validate(tv[i].secret, strlen(tv[i].secret), 
                tv[i].ocra_suite, strlen(tv[i].ocra_suite), 
                tv[i].counter, challenges_bin, 
                bin_length, pHash, 
                tv[i].session, tv[i].now, tv[i].validate_ocra);

        if (rc != tv[i].expected_rc) {
            printf ("oath_ocra_validate at %d: %d, should have been %d\n",i,rc,tv[i].expected_rc);
            return 1;
        }

    }
}

