#include <config.h>

#include "oath.h"

#include <ctype.h>

#include <stdio.h>


const struct {
    enum ocra_challenge_t type;
    size_t length;
} tv[] = {
    { HEX, 8},
    { NUM, 5},
    { ALPHA, 10},
    { HEX, 24},
    { HEX, 5},
    { HEX, 64},
    { NUM, 2},
    { NUM, 23},
    { NUM, 64},
    { ALPHA, 2},
    { ALPHA, 15},
    { ALPHA, 64}
};
    
int
main (void)
{
    int i;
    for ( i=0; i< sizeof (tv) / sizeof (tv[0]); i++) {
        char challenge[tv[i].length+1];
        char *tmp = challenge;
        int j;
        oath_ocra_generate_challenge(tv[i].type,tv[i].length,challenge);

        printf("Challenge #%d, length %d:\n",i,tv[i].length);
        printf(challenge);
        printf("\n\n");

        if(strlen(challenge) != tv[i].length) {
            printf("challenge string doesn't have desired length: %d vs %d\n",strlen(challenge), tv[i].length);
            return 1;
        }
        switch(tv[i].type) {
            case NUM:
                for(j = 0; j < strlen(challenge); j++) {
                    if(!isdigit(*tmp)) {
                        printf("NUM challenge contains non-digit char at position %d: %c\n",j,*tmp);
                        return 1;
                    }
                }
                break;

            case HEX:
                for(j = 0; j < strlen(challenge); j++) {
                    if(!isxdigit(*tmp)) {
                        printf("HEX challenge contains non-hex char at position %d: %c\n",j,*tmp);
                        return 1;
                    }
                }
                break;

            case ALPHA:
                for(j = 0; j < strlen(challenge); j++) {
                    if(!isalnum(*tmp)) {
                        printf("ALPHA challenge contains non-alphanumeric char at position %d: %c\n",j,*tmp);
                        return 1;
                    }
                }
                break;

        }
    }
    return 0;
}

