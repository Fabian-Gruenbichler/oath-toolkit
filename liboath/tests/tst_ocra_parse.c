/*
 * tst_ocra_parse.c - self-tests for liboath OCRA algorithm functions
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

const struct {
    char *ocra_suite;
    ocra_suite_t exp; //expected result
    int rc;
} tv[] = {
    { "OCRA-1:HOTP-SHA1-8:QN08", { 0, NO_HASH, SHA1, NUM, 8, 0, 0, 8, 152}, OATH_OK },
    { "OCRA-2:HOTP-SHA1-6:QN08", { }, -1 },
    { "OCRA-1:HOTP-SHA256-6:C-QA10", { 1, NO_HASH, SHA256, ALPHA, 10, 0, 0, 6, 164}, OATH_OK},
    { "OCRA-1:HOTP-SHA512-2:C-QH24", { 1, NO_HASH, SHA512, HEX, 24, 0, 0, 2, 0}, -1 },
    { "OCRA-1:HOTP-SHA1-0:C-QA20-PSHA512-S128-T12M", {1, SHA512, SHA1, ALPHA, 20, 720, 128, 0, 380}, OATH_OK}
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
                ocra_suite_t osi;
                rc = oath_ocra_parse_suite(tv[i].ocra_suite,
                        strlen(tv[i].ocra_suite),
                        &osi);

                if(rc != tv[i].rc) {
                    printf("rc mismatch for testcase #%d: %d vs %d\n",i,rc,tv[i].rc);
                    return 1;
                }
                if(rc == OATH_OK) {
                    if(osi.use_counter != tv[i].exp.use_counter) {
                        printf("use_counter mismatch for testcase #%d: %d vs %d\n",i,osi.use_counter,tv[i].exp.use_counter);
                        return 1;
                    }
                    if(osi.password_hash != tv[i].exp.password_hash) {
                        printf("password_hash mismatch for testcase #%d: %d vs %d\n",i,osi.password_hash,tv[i].exp.password_hash);
                        return 1;
                    }
                    if(osi.ocra_hash != tv[i].exp.ocra_hash) {
                        printf("ocra_hash mismatch for testcase #%d: %d vs %d\n",i,osi.ocra_hash,tv[i].exp.ocra_hash);
                        return 1;
                    }
                    if(osi.challenge_type != tv[i].exp.challenge_type) {
                        printf("challenge_type mismatch for testcase #%d: %d vs %d\n",i,osi.challenge_type,tv[i].exp.challenge_type);
                        return 1;
                    }
                    if(osi.challenge_length != tv[i].exp.challenge_length) {
                        printf("challenge_length mismatch for testcase #%d: %d vs %d\n",i,osi.challenge_length,tv[i].exp.challenge_length);
                        return 1;
                    }
                    if(osi.timestamp_div != tv[i].exp.timestamp_div) {
                        printf("timestamp_div mismatch for testcase #%d: %d vs %d\n",i,osi.timestamp_div,tv[i].exp.timestamp_div);
                        return 1;
                    }
                    if(osi.session_length != tv[i].exp.session_length) {
                        printf("session_length mismatch for testcase #%d: %d vs %d\n",i,osi.session_length,tv[i].exp.session_length);
                        return 1;
                    }
                    if(osi.digits != tv[i].exp.digits) {
                        printf("digits mismatch for testcase #%d: %d vs %d\n",i,osi.digits,tv[i].exp.digits);
                        return 1;
                    }
                    if(osi.datainput_length != tv[i].exp.datainput_length) {
                        printf("datainput_length mismatch for testcase #%d: %d vs %d\n",i,osi.datainput_length,tv[i].exp.datainput_length);
                        return 1;
                    }
                }
            }
        }
