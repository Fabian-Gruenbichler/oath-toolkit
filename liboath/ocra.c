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
#include <stdlib.h>
#include <string.h> //for tokenization
#include <ctype.h>
#include <inttypes.h>
#include "gc.h"

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

/**
 * ocra_generate:
 * @secret: the shared secret string
 * @secret_length: length of @secret
 * @ocra_suite: string with information about used hash algorithms and input
 * @ocra_suite_length: length of @ocra_suite
 * @counter: counter value, optional (see @ocra_suite)
 * @challenges: client/server challenge values, byte-array, mandatory
 * @challenges_length: length of @challenges
 * @pHash: hashed password value, optional (see @ocra_suite)
 * @session: static data about current session, optional (see @ocra-suite)
 * @now: current timestamp, optional (see @ocra_suite)
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
 * Numeric challenges must be converted to base16 before passing as byte-array.
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
        char *session, time_t now, char *output_ocra) {

    char *alg, *crypto, *datainput, *tmp;
    char *save_ptr_inner, *save_ptr_outer;

    int i;

    uint8_t digits;

    uint8_t challenge_length, session_length=0, time_step_size;
    uint8_t use_counter=0;

    enum time_step_t time_step_unit = NO_TIMESTAMP;
    enum challenge_t challenge_type;
    enum hash_type password_hash = NO_HASH;
    enum hash_type ocra_hash = NO_HASH;

    char suite_tmp[strlen(ocra_suite)]; //needed as working copy for strtok_r

    int rc;

    strncpy(suite_tmp,ocra_suite,strlen(ocra_suite)+1);

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

    datainput = strtok_r (NULL,":",&save_ptr_outer);
    if(datainput == NULL) {
        printf("data input tokenization returned NULL!\n");
        return -1;
    }

    size_t datainput_length = ocra_suite_length+1; //in byte

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

        if(challenges_length > 128) {
            printf("challenge string too long!\n");
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
                break;

            default:
                printf("invalid data input string.. (%c)\n",tmp[0]);
                return -1;
        }
        tmp = strtok_r (NULL,"-",&save_ptr_inner);
    }

    char byte_array[datainput_length];
    char *curr_ptr = byte_array;

    memcpy(curr_ptr,ocra_suite,ocra_suite_length);
    curr_ptr += ocra_suite_length;

    curr_ptr[0] = '\0';
    curr_ptr ++;

    if(use_counter) {
        char tmp_str[16];
        sprintf(tmp_str, "%016" PRIX64, counter );
        size_t len = 8;
        char tmp_str2[len];
        rc=oath_hex2bin(tmp_str,tmp_str2,&len);
        memcpy(curr_ptr,tmp_str2,8);
        curr_ptr+=8;
    }

    memcpy(curr_ptr,challenges,challenges_length);
    curr_ptr+=challenges_length;

    if(challenges_length<128) {
        memset(curr_ptr,'\0',(128-challenges_length));
        curr_ptr+=(128-challenges_length);
    }

    switch(password_hash) {
        case SHA1:
            memcpy(curr_ptr,pHash,20);
            curr_ptr+=20;
            break;

        case SHA256:
            memcpy(curr_ptr,pHash,32);
            curr_ptr+=32;
            break;

        case SHA512:
            memcpy(curr_ptr,pHash,64);
            curr_ptr+=64;
            break;

        default:
            break;
    }

    if(session_length>0) {
        memcpy(curr_ptr,session,session_length);
        curr_ptr+=session_length;
    }

    uint64_t time_steps = 0;

    switch(time_step_unit) {
        case HOURS:
            time_steps = now / (60 * 60 * time_step_size);
            break;

        case MINUTES:
            time_steps = now / (60 * time_step_size);
            break;

        case SECONDS:
            time_steps = now / time_step_size;
            break;

        default:
            break;
    }

    if(time_step_unit != NO_TIMESTAMP) {
        char tmp_str[16];
        sprintf(tmp_str, "%016" PRIX64, time_steps );
        size_t len = 8;
        oath_hex2bin(tmp_str,curr_ptr,&len);
        curr_ptr+=8;
    }


    char hexstring[datainput_length*2+1];
    oath_bin2hex(byte_array,datainput_length,hexstring);

    //printf("BYTE_ARRAY: %d\n",datainput_length);
    //printf(hexstring);

    char *hs;
    size_t hs_size;

    switch(ocra_hash) {
        case SHA1:
            hs_size = GC_SHA1_DIGEST_SIZE;
            hs = (char *) malloc(hs_size*sizeof(char));
            rc = gc_hmac_sha1 (secret, secret_length,
                    byte_array, sizeof(byte_array), 
                    hs);
            break;

            /*   case SHA256:
                 hs_size = GC_SHA256_DIGEST_SIZE;
                 hs = (char *) malloc(hs_size*sizeof(char));
                 printf("Calculating SHA256, key: %s (length %d)\n",secret,secret_length);
                 rc = gc_hmac_sha256 (secret, secret_length,
                 byte_array, sizeof(byte_array), 
                 hs);
                 break;*/

        default:
            printf("unsupported hash\n");
            return -1;
    }

    long S;
    uint8_t offset = hs[hs_size - 1] & 0x0f;

    S = (((hs[offset] & 0x7f) << 24)
            | ((hs[offset + 1] & 0xff) << 16)
            | ((hs[offset + 2] & 0xff) << 8) | ((hs[offset + 3] & 0xff)));

    free(hs);

    switch (digits)
    {
        case 4:
            S = S % 10000;
            break;

        case 5:
            S = S % 100000;
            break;

        case 6:
            S = S % 1000000;
            break;

        case 7:
            S = S % 10000000;
            break;

        case 8:
            S = S % 100000000;
            break;

        case 9:
            S = S % 1000000000;
            break;

        case 10:
            S = S % 10000000000;
            break;

        case 0:
            break;

        default:
            return OATH_INVALID_DIGITS;
            break;
    }

    {
        int len = snprintf (output_ocra, digits + 1, "%.*ld", digits, S);
        output_ocra[digits] = '\0';
        if (len <= 0 || ((unsigned) len) != digits)
            return OATH_PRINTF_ERROR;
    }

    //printf("OCRA: %s\n\n",output_ocra);

    return OATH_OK;
}


int
oath_ocra_validate(const char *secret, size_t secret_length, 
        char *ocra_suite, size_t ocra_suite_length, 
        uint64_t counter, char *challenges, 
        size_t challenges_length, char *pHash, 
        char *session, time_t now, char *validate_ocra) {
    
    int rc;
    char generated_ocra[11]; //max 10 digits

    rc = oath_ocra_generate(secret, secret_length,
                            ocra_suite, ocra_suite_length,
                            counter, challenges,
                            challenges_length, pHash,
                            session, now, generated_ocra);

    if(rc!=OATH_OK)
        return rc;

    if(strcmp(generated_ocra,validate_ocra)!=0)
        return OATH_STRCMP_ERROR;

    return OATH_OK;
}
