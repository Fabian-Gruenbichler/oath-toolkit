/*
 * ocra.c - implementation of the OATH OCRA algorithm
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
#include <string.h> //for tokenization
#include "gc.h"

/**
 * ocra_generate:
 * @secret: the shared secret string
 * @secret_length: length of @secret
 * @ocra_suite: string with information about used hash algorithms and input
 * @ocra_suite_length: length of @ocra_suite
 * @counter: counter value, optional (see @ocra_suite)
 * @challenges: client/server challenge values, mandatory
 * @challenges_length: length of @challenges
 * @pHash: hashed password value, optional (see @ocra_suite)
 * @session: static data about current session, optional (see @ocra-suite)
 * @timestamp: current timestamp, optional (see @ocra_suite)
 * @output_ocra: output buffer,
 *
 * Generate a truncated hash-value used for challenge-response-based
 * authentication according to the OCRA algorithm described in RFC 6287. 
 * Besides the mandatory challenge(s), additional input is optional.
 *
 * The string @ocra_suite denotes which mode of OCRA is to be used. Furthermore
 * it contains information about which of the possible optional data inputs are
 * to be used, and how.
 *
 * The output buffer @output_ocra must have room for at least as many digits as
 * specified as part of @ocra_suite, plus one terminating NUL char.
 *
 * Returns: on success, %OATH_OK (zero) is returned, otherwise an error code is
 *   returned.
 *
 * Since: 2.4.0
 **/

int
oath_ocra_generate(const char *secret, size_t secret_length, 
            char *ocra_suite, size_t ocra_suite_length, 
            uint64_t counter, char *challenges, 
            size_t challenges_length, char *pHash, 
            char *session, time_t timestamp, char *output_ocra) {

    char *alg, *crypto, *hash, *datainput, *tmp;
    char *save_ptr_inner, *save_ptr_outer;
    uint8_t digits;

    {
        char suite_tmp[strlen(ocra_suite)]; //needed for strtok_r
        strncpy(suite_tmp,ocra_suite,strlen(ocra_suite)+1);
        printf("OCRA Suite orig/copy\n%s\n%s\n",ocra_suite,suite_tmp);
        
        alg = strtok_r (suite_tmp,":",&save_ptr_outer);
        if(alg == NULL)
        {
            printf("alg tokenization returned NULL!\n");
            return -1;
        }
        if(strcmp(alg,"OCRA-1") != 0) {
            printf("unsupported algorithm requested: %s\n",alg);
            return -1;
        }

        crypto = strtok_r (NULL,":",&save_ptr_outer);
        if(crypto == NULL) {
            printf("crypto tokenization returned NULL!\n");
            return -1;
        }
        hash = strtok_r (crypto,"-",&save_ptr_inner);
        if(hash == NULL) {
            printf("hash family tokenization returned NULL!\n");
            return -1;
        }
        if(strcmp(hash,"HOTP")!=0) {
            printf("only HOTP is supported as hash family (was: %s)\n",hash);
            return -1;
        }
        hash = strtok_r (NULL,"-",&save_ptr_inner);
        if(hash == NULL) {
            printf("hash funktion tokenization returned NULL\n");
            return -1;
        }
        if(strcmp(hash,"SHA1")!= 0
                && strcmp(hash,"SHA256") != 0
               && strcmp(hash,"SHA512") != 0 ) {
            printf("only SHA1, 256 and 512 are supported as hash algorithms (was: %s)\n",hash);
            return -1;
        }
        tmp = strtok_r (NULL,"-",&save_ptr_inner);
        if(tmp == NULL) {
            printf("truncation digits tokenization returned NULL\n");
            return -1;
        }
        for (digits=0; (*tmp-'0'<10) && (*tmp-'0'>=0); tmp++) 
            digits=10*digits+(*tmp-'0');
        if(*tmp != '\0') {
            printf("truncation digits must only contain digits! (%d / \"%c\")\n",digits,*tmp);
            return -1;
        }
        if(digits!=0 && (digits<4 || digits>10)) {
            printf("truncation digits must either be 0 or between 4 and 10! (%d)\n",digits);
            return -1;
        }

        datainput = strtok_r (NULL,":",&save_ptr_outer);
        if(datainput == NULL)
            return -1;
        printf("DATA:\n");
        printf(datainput);
        printf("\n");
        
        return OATH_OK;
    }
}

