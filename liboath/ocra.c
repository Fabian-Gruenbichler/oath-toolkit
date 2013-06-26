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
#include <ctype.h>
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

enum challenge_t {
   HEX,
   ALPHA,
   NUM
};

enum hash_type {
    NO_HASH,
    SHA1,
    SHA256,
    SHA512
};

enum time_step_t {
    NO_TIMESTAMP,
    SECONDS,
    MINUTES,
    HOURS
};

int strtouint(char *string, uint8_t *uint) {
    if(*string == '\0')
        return -1;
    for (*uint=0; (*string-'0'<10) && (*string-'0'>=0); *string++) 
        *uint=10*(*uint)+(unsigned)(*string-'0');
    if(*string != '\0')
        return -1;
    return 0;
}

int
oath_ocra_generate(const char *secret, size_t secret_length, 
            char *ocra_suite, size_t ocra_suite_length, 
            uint64_t counter, char *challenges, 
            size_t challenges_length, char *pHash, 
            char *session, time_t timestamp, char *output_ocra) {

    char *alg, *crypto, *datainput, *tmp;
    char *save_ptr_inner, *save_ptr_outer;
    uint8_t digits;

    uint8_t challenge_length, session_length=0, time_step_size, use_counter;
    enum time_step_t time_step_unit = NO_TIMESTAMP;
    enum challenge_t challenge_type;
    enum hash_type password_hash = NO_HASH;
    enum hash_type ocra_hash = NO_HASH;
    

    {
        char suite_tmp[strlen(ocra_suite)]; //needed as working copy for strtok_r
        strncpy(suite_tmp,ocra_suite,strlen(ocra_suite)+1);
        printf("OCRA Suite \n%s\n",ocra_suite);
        
        alg = strtok_r (suite_tmp,":",&save_ptr_outer);
        if(alg == NULL)
        {
            printf("alg tokenization returned NULL!\n");
            return -1;
        }
        if(strcasecmp(alg,"OCRA-1") != 0) {
            printf("unsupported algorithm requested: %s\n",alg);
            return -1;
        }

        printf("ALG: %s\n",alg);

        crypto = strtok_r (NULL,":",&save_ptr_outer);
        if(crypto == NULL) {
            printf("crypto tokenization returned NULL!\n");
            return -1;
        }
        tmp = strtok_r (crypto,"-",&save_ptr_inner);
        if(tmp == NULL) {
            printf("hash family tokenization returned NULL!\n");
            return -1;
        }
        if(strcasecmp(tmp,"HOTP")!=0) {
            printf("only HOTP is supported as hash family (was: %s)\n",tmp);
            return -1;
        }
        tmp = strtok_r (NULL,"-",&save_ptr_inner);
        if(tmp == NULL) {
            printf("hash funktion tokenization returned NULL\n");
            return -1;
        }
        if(strcasecmp(tmp,"SHA1")==0) {
            ocra_hash = SHA1;
        } else if (strcasecmp(tmp,"SHA256") == 0) {
            ocra_hash = SHA256;
        } else if (strcasecmp(tmp,"SHA512") != 0 ) {
            ocra_hash = SHA512;
        } else {
            printf("only SHA1, 256 and 512 are supported as hash algorithms (was: %s)\n",tmp);
            return -1;
        }

        printf("HASH: %s\n",tmp);

        tmp = strtok_r (NULL,"-",&save_ptr_inner);
        if(tmp == NULL) {
            printf("truncation digits tokenization returned NULL\n");
            return -1;
        }
        if(strtouint(tmp,&digits)!=0) {
            printf("converting truncation digits failed.\n");
            return -1;
        }
        if(digits!=0 && (digits<4 || digits>10)) {
            printf("truncation digits must either be 0 or between 4 and 10! (%d)\n",digits);
            return -1;
        }
        
        printf("DIGITS: %d\n",digits);

        datainput = strtok_r (NULL,":",&save_ptr_outer);
        if(datainput == NULL) {
            printf("data input tokenization returned NULL!\n");
            return -1;
        }
        
        size_t datainput_length = 0; //in byte
        printf("DATA: %s\n",datainput);
        tmp = strtok_r (datainput,"-",&save_ptr_inner);
        if(tmp==NULL) {
            printf("NULL returned while trying to tokenize datainput\n");
            return -1;
        }
        if(tolower(tmp[0])=='c' && tmp[1] =='\0') {
            datainput_length += 8;
            use_counter = 1;
            tmp = strtok_r (NULL,"-",&save_ptr_inner);
        }
        if(tmp==NULL) {
            printf("NULL returned while trying to tokenize datainput\n");
            return -1;
        }
        if(tolower(tmp[0])=='q') {
            tmp++;
            switch(tolower(tmp[0])) {
                case 'a':
                    challenge_type = ALPHA;
                    break;
                case 'n':
                    challenge_type = NUM;
                    break;
                case 'h':
                    challenge_type = HEX;
                    break;
                default:
                    printf("challenge type wrongly specified: %c\n",tmp[0]);
                    return -1;
            }
            tmp++;
            if(strtouint(tmp,&challenge_length)!=0) {
                printf("couldn't convert challenge length!\n");
                return -1;
            }
            if(challenge_length<4 || challenge_length > 64) {
                printf("challenge length not between 4 and 64\n");
                return -1;
            }
            if(tmp[2]!='\0'){
                printf("challenge specification not correct (not QFXX)\n");
                return -1;
            }
            datainput_length += 128; //challenges need zero-padding anyway!
            tmp = strtok_r (NULL,"-",&save_ptr_inner);
        } else {
            printf("mandatory challenge string not found in datainput, aborting\n");
            printf(tmp);
            return -1;
        }
        
        while(tmp!=NULL) {
            switch(tolower(tmp[0])) {
                case 'p':
                    if(password_hash != NO_HASH) {
                        printf("password hash type specified twice\n");
                        return -1;
                    }
                    tmp++;
                    if(strcasecmp(tmp,"SHA1")==0) {
                        password_hash = SHA1;
                        datainput_length += 20;
                    } else if (strcasecmp(tmp,"SHA256")) {
                        password_hash = SHA256;
                        datainput_length += 32;
                    } else if (strcasecmp(tmp,"SHA512")) {
                        password_hash = SHA512;
                        datainput_length += 64;
                    } else {
                        printf("incorrect password hash function specified\n");
                        return -1;
                    }
                    printf("password hash function specified\n");
                    break;

                case 's':
                    if(session_length>0) {
                        printf("session specified twice\n");
                        return -1;
                    }
                    tmp++;
                    if(strtouint(tmp,&session_length)!=0) {
                        printf("couldn't convert session length specification\n");
                        return -1;
                    }
                    if(session_length>512) {
                        printf("session length too big (>512)\n");
                        return -1;
                    }
                    if(tmp[3]!='\0') {
                        printf("session length specification not correct (not SXXX)\n");
                        return -1;
                    }
                    datainput_length+=session_length;
                    printf("session information length specified\n");
                    break;

                case 't':
                    if(time_step_unit != NO_TIMESTAMP) {
                        printf("timestep size specified twice\n");
                        return -1;
                    }
                    tmp++;
                    for (time_step_size=0; (*tmp-'0'<10) && (*tmp-'0'>=0); tmp++) 
                        time_step_size=10*time_step_size+(*tmp-'0');
                    switch (tolower(tmp[0])) {
                        case 's':
                            if(time_step_size>59 || time_step_size==0) {
                                printf("time_step_size invalid\n");
                                return -1;
                            }
                            time_step_unit = SECONDS;
                            break;

                        case 'm':
                            if(time_step_size>59 || time_step_size==0) {
                                printf("time_step_size invalid\n");
                                return -1;
                            }
                            time_step_unit = MINUTES;
                            break;

                        case 'h':
                            if(time_step_size>48) {
                                printf("time_step_size invalid\n");
                                return -1;
                            }
                            time_step_unit = HOURS;
                            break;

                        default:
                            printf("invalid timestep unit specified\n");
                            return -1;
                    }
                    if(tmp[1]!='\0') {
                        printf("timestep specification not correctly formatted (not TXXU)\n");
                        return -1;
                    }
                    datainput_length+=8;
                    printf("timestep size and unit specified\n");
                    break;

                default:
                    printf("invalid data input string.. (%c)\n",tmp[0]);
                    return -1;
            }
            tmp = strtok_r (NULL,"-",&save_ptr_inner);
        }

        return OATH_OK;
    }
}

