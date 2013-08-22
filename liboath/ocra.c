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
#include <string.h>		//for tokenization
#include <ctype.h>
#include <inttypes.h>
#include "gc.h"

int strtouint (char *string, uint8_t * uint);

int
strtouint (char *string, uint8_t * uint)
{
  if (*string == '\0')
    return -1;
  *uint = 0;
  while ((*string - '0' < 10) && (*string - '0' >= 0))
    {
      *uint = 10 * (*uint) + (unsigned) (*string - '0');
      string++;
    }
  if (*string != '\0')
    return -1;
  return 0;
}

int strtouint_16 (char *string, uint16_t * uint);

int
strtouint_16 (char *string, uint16_t * uint)
{
  if (*string == '\0')
    return -1;
  *uint = 0;
  while ((*string - '0' < 10) && (*string - '0' >= 0))
    {
      *uint = 10 * (*uint) + (unsigned) (*string - '0');
      string++;
    }
  if (*string != '\0')
    return -1;
  return 0;
}



/**
 * oath_ocra_parse_suite:
 * @ocra_suite: string to be parsed
 * @ocra_suite_length: length of string to be parsed
 * @ocra_suite_info: struct where parsed information is stored
 *
 * Parses the string in @ocra_suite, storing the results in @ocra_suite_info. 
 *
 * Returns: on success, %OATH_OK (zero) is returned, otherwise an error code is
 * returned.
 *
 * Since: 2.6.0
 **/

int
oath_ocra_parse_suite (const char *ocra_suite, size_t ocra_suite_length,
		       ocra_suite_t * ocra_suite_info)
{
  char *alg, *crypto, *datainput, *tmp;
  char *save_ptr_inner, *save_ptr_outer;

  ocra_suite_info->password_hash = OATH_OCRA_HASH_NONE;
  ocra_suite_info->ocra_hash = OATH_OCRA_HASH_NONE;
  ocra_suite_info->use_counter = 0;
  ocra_suite_info->timestamp_div = 0;
  ocra_suite_info->session_length = 0;
  if (ocra_suite_info == NULL)
    {
      printf ("ocra_suite_info is null!\n");
      return -1;
    }

  char *suite_tmp = calloc (strlen (ocra_suite), sizeof (char));	//needed as working copy for strtok_r
  if (suite_tmp == NULL)
    {
      printf ("couldn't allocate temp buffer for ocra_suite\n");
      return -1;
    }

  strncpy (suite_tmp, ocra_suite, strlen (ocra_suite) + 1);

  alg = strtok_r (suite_tmp, ":", &save_ptr_outer);
  if (alg == NULL)
    {
      printf ("alg tokenization returned NULL!\n");
      free (suite_tmp);
      return -1;
    }
  if (strcasecmp (alg, "OCRA-1") != 0)
    {
      printf ("unsupported algorithm requested: %s\n", alg);
      free (suite_tmp);
      return -1;
    }

  crypto = strtok_r (NULL, ":", &save_ptr_outer);
  if (crypto == NULL)
    {
      printf ("crypto tokenization returned NULL!\n");
      free (suite_tmp);
      return -1;
    }
  tmp = strtok_r (crypto, "-", &save_ptr_inner);
  if (tmp == NULL)
    {
      printf ("hash family tokenization returned NULL!\n");
      free (suite_tmp);
      return -1;
    }
  if (strcasecmp (tmp, "HOTP") != 0)
    {
      printf ("only HOTP is supported as hash family (was: %s)\n", tmp);
      free (suite_tmp);
      return -1;
    }
  tmp = strtok_r (NULL, "-", &save_ptr_inner);
  if (tmp == NULL)
    {
      printf ("hash funktion tokenization returned NULL\n");
      free (suite_tmp);
      return -1;
    }
  if (strcasecmp (tmp, "SHA1") == 0)
    {
      ocra_suite_info->ocra_hash = OATH_OCRA_HASH_SHA1;
    }
  else if (strcasecmp (tmp, "SHA256") == 0)
    {
      ocra_suite_info->ocra_hash = OATH_OCRA_HASH_SHA256;
    }
  else if (strcasecmp (tmp, "SHA512") == 0)
    {
      ocra_suite_info->ocra_hash = OATH_OCRA_HASH_SHA512;
    }
  else
    {
      printf
	("only SHA1, 256 and 512 are supported as hash algorithms (was: %s)\n",
	 tmp);
      free (suite_tmp);
      return -1;
    }

  tmp = strtok_r (NULL, "-", &save_ptr_inner);
  if (tmp == NULL)
    {
      printf ("truncation digits tokenization returned NULL\n");
      free (suite_tmp);
      return -1;
    }
  if (strtouint (tmp, &(ocra_suite_info->digits)) != 0)
    {
      printf ("converting truncation digits failed.\n");
      free (suite_tmp);
      return -1;
    }
  if (ocra_suite_info->digits != 0 &&
      ((ocra_suite_info->digits) < 4 || (ocra_suite_info->digits) > 10))
    {
      printf
	("truncation digits must either be 0 or between 4 and 10! (%d)\n",
	 ocra_suite_info->digits);
      free (suite_tmp);
      return -1;
    }

  datainput = strtok_r (NULL, ":", &save_ptr_outer);

  free (suite_tmp);		//no longer needed

  if (datainput == NULL)
    {
      printf ("data input tokenization returned NULL!\n");
      return -1;
    }

  ocra_suite_info->datainput_length = ocra_suite_length + 1;	//in byte

  tmp = strtok_r (datainput, "-", &save_ptr_inner);
  if (tmp == NULL)
    {
      printf ("NULL returned while trying to tokenize datainput\n");
      return -1;
    }
  if (tolower (tmp[0]) == 'c' && tmp[1] == '\0')
    {
      ocra_suite_info->datainput_length += 8;
      ocra_suite_info->use_counter = 1;
      tmp = strtok_r (NULL, "-", &save_ptr_inner);
    }

  if (tmp == NULL)
    {
      printf ("NULL returned while trying to tokenize datainput\n");
      return -1;
    }
  if (tolower (tmp[0]) == 'q')
    {
      tmp++;
      switch (tolower (tmp[0]))
	{
	case 'a':
	  ocra_suite_info->challenge_type = OATH_OCRA_CHALLENGE_ALPHA;
	  break;
	case 'n':
	  ocra_suite_info->challenge_type = OATH_OCRA_CHALLENGE_NUM;
	  break;
	case 'h':
	  ocra_suite_info->challenge_type = OATH_OCRA_CHALLENGE_HEX;
	  break;
	default:
	  printf ("challenge type wrongly specified: %c\n", tmp[0]);
	  return -1;
	}
      tmp++;
      if (strtouint (tmp, &(ocra_suite_info->challenge_length)) != 0)
	{
	  printf ("couldn't convert challenge length!\n");
	  printf ("string: %s\n", tmp);
	  return -1;
	}
      if (ocra_suite_info->challenge_length < 4
	  || ocra_suite_info->challenge_length > 64)
	{
	  printf ("challenge length not between 4 and 64 (%d)\n",
		  ocra_suite_info->challenge_length);
	  return -1;
	}
      if (tmp[2] != '\0')
	{
	  printf ("challenge specification not correct (not QFXX)\n");
	  return -1;
	}

      ocra_suite_info->datainput_length += 128;	//challenges need zero-padding anyway!
      tmp = strtok_r (NULL, "-", &save_ptr_inner);
    }
  else
    {
      printf
	("mandatory challenge string not found in datainput, aborting\n");
      return -1;
    }

  while (tmp != NULL)
    {
      switch (tolower (tmp[0]))
	{
	case 'p':
	  if (ocra_suite_info->password_hash != OATH_OCRA_HASH_NONE)
	    {
	      printf ("password hash type specified twice\n");
	      return -1;
	    }
	  tmp++;
	  if (strcasecmp (tmp, "SHA1") == 0)
	    {
	      ocra_suite_info->password_hash = OATH_OCRA_HASH_SHA1;
	      ocra_suite_info->datainput_length += 20;
	    }
	  else if (strcasecmp (tmp, "SHA256") == 0)
	    {
	      ocra_suite_info->password_hash = OATH_OCRA_HASH_SHA256;
	      ocra_suite_info->datainput_length += 32;
	    }
	  else if (strcasecmp (tmp, "SHA512") == 0)
	    {
	      ocra_suite_info->password_hash = OATH_OCRA_HASH_SHA512;
	      ocra_suite_info->datainput_length += 64;
	    }
	  else
	    {
	      printf ("incorrect password hash function specified\n");
	      return -1;
	    }
	  break;

	case 's':
	  if (ocra_suite_info->session_length > 0)
	    {
	      printf ("session specified twice\n");
	      return -1;
	    }
	  tmp++;
	  if (strtouint_16 (tmp, &(ocra_suite_info->session_length)) != 0)
	    {
	      printf ("couldn't convert session length specification\n");
	      return -1;
	    }
	  if (ocra_suite_info->session_length > 512)
	    {
	      printf ("session length too big (>512)\n");
	      return -1;
	    }
	  if (tmp[3] != '\0')
	    {
	      printf
		("session length specification not correct (not SXXX)\n");
	      return -1;
	    }
	  ocra_suite_info->datainput_length +=
	    ocra_suite_info->session_length;
	  break;

	case 't':
	  if (ocra_suite_info->timestamp_div != 0)
	    {
	      printf ("timestep size specified twice\n");
	      return -1;
	    }
	  tmp++;
	  for (ocra_suite_info->timestamp_div = 0;
	       (*tmp - '0' < 10) && (*tmp - '0' >= 0); tmp++)
	    ocra_suite_info->timestamp_div =
	      10 * ocra_suite_info->timestamp_div + (*tmp - '0');
	  switch (tolower (tmp[0]))
	    {
	    case 's':
	      if (ocra_suite_info->timestamp_div > 59
		  || ocra_suite_info->timestamp_div == 0)
		{
		  printf ("ocra_suite_info->timestamp_div invalid\n");
		  return -1;
		}
	      break;

	    case 'm':
	      if (ocra_suite_info->timestamp_div > 59
		  || ocra_suite_info->timestamp_div == 0)
		{
		  printf ("ocra_suite_info->timestamp_div invalid\n");
		  return -1;
		}
	      ocra_suite_info->timestamp_div *= 60;
	      break;

	    case 'h':
	      if (ocra_suite_info->timestamp_div > 48)
		{
		  printf ("ocra_suite_info->timestamp_div invalid\n");
		  return -1;
		}
	      ocra_suite_info->timestamp_div *= 3600;
	      break;

	    default:
	      printf ("invalid timestep unit specified\n");
	      return -1;
	    }
	  if (tmp[1] != '\0')
	    {
	      printf
		("timestep specification not correctly formatted (not TXXU)\n");
	      return -1;
	    }
	  ocra_suite_info->datainput_length += 8;
	  break;

	default:
	  printf ("invalid data input string.. (%c)\n", tmp[0]);
	  return -1;
	}
      tmp = strtok_r (NULL, "-", &save_ptr_inner);
    }

  return OATH_OK;

}

/**
 * oath_ocra_generate:
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
 * Since: 2.6.0
 **/

int
oath_ocra_generate (const char *secret, size_t secret_length,
		    const char *ocra_suite, size_t ocra_suite_length,
		    uint64_t counter, const char *challenges,
		    size_t challenges_length, const char *pHash,
		    const char *session, time_t now, char *output_ocra)
{

  ocra_suite_t ocra_suite_info;

  int rc = oath_ocra_parse_suite (ocra_suite, ocra_suite_length,
				  &ocra_suite_info);

  if (rc != OATH_OK)
    return rc;

  char *byte_array = malloc (ocra_suite_info.datainput_length);

  if (byte_array == NULL)
    {
      printf ("couldn't allocate memory for byte array\n");
      return -1;
    }

  char *curr_ptr = byte_array;

  memcpy (curr_ptr, ocra_suite, ocra_suite_length);
  curr_ptr += ocra_suite_length;

  curr_ptr[0] = '\0';
  curr_ptr++;

  if (ocra_suite_info.use_counter)
    {
      char tmp_str[16];
      sprintf (tmp_str, "%016" PRIX64, counter);
      size_t len = 8;
      char tmp_str2[8];
      oath_hex2bin (tmp_str, tmp_str2, &len);
      memcpy (curr_ptr, tmp_str2, 8);
      curr_ptr += 8;
    }

  if (challenges == NULL)
    {
      printf ("challenges are mandatory, but pointer = NULL!\n");
      free (byte_array);
      return -1;
    }

  if (challenges_length > 128)
    {
      printf ("challenges are not allowed to be longer than 128!\n");
      free (byte_array);
      return -1;
    }

  memcpy (curr_ptr, challenges, challenges_length);
  curr_ptr += challenges_length;

  if (challenges_length < 128)
    {
      memset (curr_ptr, '\0', (128 - challenges_length));
      curr_ptr += (128 - challenges_length);
    }

  if (ocra_suite_info.password_hash != OATH_OCRA_HASH_NONE && pHash == NULL)
    {
      printf
	("suite specified password hash to be used, but pHash is NULL!\n");
      free (byte_array);
      return -1;
    }

  switch (ocra_suite_info.password_hash)
    {
    case OATH_OCRA_HASH_SHA1:
      memcpy (curr_ptr, pHash, 20);
      curr_ptr += 20;
      break;

    case OATH_OCRA_HASH_SHA256:
      memcpy (curr_ptr, pHash, 32);
      curr_ptr += 32;
      break;

    case OATH_OCRA_HASH_SHA512:
      memcpy (curr_ptr, pHash, 64);
      curr_ptr += 64;
      break;

    default:
      break;
    }

  if (ocra_suite_info.session_length > 0)
    {
      if (session == NULL)
	{
	  printf
	    ("suite specified session information to be used, but session is NULL!\n");
	  free (byte_array);
	  return -1;
	}
      memcpy (curr_ptr, session, ocra_suite_info.session_length);
      curr_ptr += ocra_suite_info.session_length;
    }

  if (ocra_suite_info.timestamp_div != 0)
    {
      uint64_t time_steps = now / ocra_suite_info.timestamp_div;
      char tmp_str[16];
      sprintf (tmp_str, "%016" PRIX64, time_steps);
      size_t len = 8;
      oath_hex2bin (tmp_str, curr_ptr, &len);
      curr_ptr += 8;
    }

  /*
     char hexstring[ocra_suite_info.datainput_length*2+1];
     oath_bin2hex(byte_array,ocra_suite_info.datainput_length,hexstring);

     printf("BYTE_ARRAY: %d\n",ocra_suite_info.datainput_length);
     printf(hexstring);
     printf("\n"); 
   */


  char *hs;
  size_t hs_size;

  switch (ocra_suite_info.ocra_hash)
    {
    case OATH_OCRA_HASH_SHA1:
      hs_size = GC_SHA1_DIGEST_SIZE;
      hs = (char *) malloc (hs_size * sizeof (char));
      rc = gc_hmac_sha1 (secret, secret_length,
			 byte_array, sizeof (byte_array), hs);
      break;

      /*   case SHA256:
         hs_size = GC_SHA256_DIGEST_SIZE;
         hs = (char *) malloc(hs_size*sizeof(char));
         printf("Calculating SHA256, key: %s (length %d)\n",secret,secret_length);
         rc = gc_hmac_sha256 (secret, secret_length,
         byte_array, sizeof(byte_array), 
         hs);
         break; */

    default:
      printf ("unsupported hash\n");
      free (byte_array);
      return -1;
    }

  free (byte_array);

  long S;
  uint8_t offset = hs[hs_size - 1] & 0x0f;

  S = (((hs[offset] & 0x7f) << 24)
       | ((hs[offset + 1] & 0xff) << 16)
       | ((hs[offset + 2] & 0xff) << 8) | ((hs[offset + 3] & 0xff)));

  free (hs);

  switch (ocra_suite_info.digits)
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
    int len = snprintf (output_ocra, ocra_suite_info.digits + 1, "%.*ld",
			ocra_suite_info.digits, S);
    output_ocra[ocra_suite_info.digits] = '\0';
    if (len <= 0 || ((unsigned) len) != ocra_suite_info.digits)
      return OATH_PRINTF_ERROR;
  }

  //printf("OCRA: %s\n\n",output_ocra);

  return OATH_OK;
}

/**
 * oath_ocra_validate:
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
 * @validate_ocra: OCRA value to validate against
 *
 * Validates a given OCRA value by generating an OCRA value using the given
 * parameters and comparing the result.
 *
 * Returns: OATH_OK (zero) on successful validation, an error code otherwise.
 * Since: 2.6.0
 **/
int
oath_ocra_validate (const char *secret, size_t secret_length,
		    const char *ocra_suite, size_t ocra_suite_length,
		    uint64_t counter, const char *challenges,
		    size_t challenges_length, const char *pHash,
		    const char *session, time_t now,
		    const char *validate_ocra)
{

  int rc;
  char generated_ocra[11];	//max 10 digits

  rc = oath_ocra_generate (secret, secret_length,
			   ocra_suite, ocra_suite_length,
			   counter, challenges,
			   challenges_length, pHash,
			   session, now, generated_ocra);

  if (rc != OATH_OK)
    return rc;

  if (strcmp (generated_ocra, validate_ocra) != 0)
    return OATH_STRCMP_ERROR;

  return OATH_OK;
}


/**
 * oath_ocra_generate_challenge:
 * @challenge_type: OATH_OCRA_CHALLENGE_NUM, OATH_OCRA_CHALLENGE_HEX or OATH_OCRA_CHALLENGE_ALPHA; chars allowed in challenge
 * @challenge_length: number of chars in challenge
 * @challenge: output buffer, needs space for @challenge_length+1 chars
 *
 * Generates a (pseudo)random challenge string depending on the type and length
 * given by @challenge_type and @challenge_length.
 *
 * Since: 2.6.0
 **/
void
oath_ocra_generate_challenge (oath_ocra_challenge_t challenge_type,
			      size_t challenge_length, char *challenge)
{
  long int random_number;
  long int max;
  char *tmp = challenge;
  uint8_t i;

  srandom (time (NULL));
  switch (challenge_type)
    {
    case OATH_OCRA_CHALLENGE_NUM:
      {
	for (i = 0; i < challenge_length; i++)
	  {
	    random_number = random () % 10;
	    if (random_number < 10)
	      *tmp = '0' + random_number;
	    tmp++;
	  }
	*tmp = '\0';
      }
      break;

    case OATH_OCRA_CHALLENGE_HEX:
      {
	for (i = 0; i < challenge_length; i++)
	  {
	    random_number = random () % 16;
	    if (random_number < 10)
	      *tmp = '0' + random_number;
	    else if (random_number < 16)
	      *tmp = 'A' + (random_number - 10);
	    tmp++;
	  }
	*tmp = '\0';
      }
      break;

    case OATH_OCRA_CHALLENGE_ALPHA:
      {
	for (i = 0; i < challenge_length; i++)
	  {
	    random_number = random () % 62;
	    if (random_number < 10)
	      *tmp = '0' + random_number;
	    else if (random_number < 36)
	      *tmp = 'A' + (random_number - 10);
	    else
	      *tmp = 'a' + (random_number - 36);
	    tmp++;
	  }
	*tmp = '\0';
      }
      break;
    }
}

/**
 * oath_ocra_convert_challenge:
 * @challenge_type: OATH_OCRA_CHALLENGE_NUM, OATH_OCRA_CHALLENGE_HEX or OATH_OCRA_CHALLENGE_ALPHA; chars allowed in challenge
 * @challenge_string: challenge string
 * @challenge_binary_length: length of returned byte-array
 *
 * Converts @challenge_string to binary representation. Numerical values are
 * converted to base16 and then converted using @oath_hex2bin. Hexadecimal
 * values are simply converted using @oath_hex2bin, alpha numerical values are
 * just copied.
 *
 * Returns: malloc'ed byte-array of length @challenge_binary_length
 *
 * Since: 2.6.0
 **/
char *
oath_ocra_convert_challenge (oath_ocra_challenge_t challenge_type,
			     char *challenge_string,
			     size_t * challenge_binary_length)
{
  char *challenges;
  size_t challenge_length = strlen (challenge_string);
  switch (challenge_type)
    {
    case OATH_OCRA_CHALLENGE_NUM:
      {
	unsigned long int num_value = strtoul (challenge_string, NULL, 10);
	char *temp = malloc (challenge_length + 2);
	if (temp == NULL)
	  {
	    printf
	      ("couldn't allocate temp buffer for challenge conversion\n");
	    return NULL;
	  }
	sprintf (temp, "%lX", num_value);
	size_t hex_length = strlen (temp);
	if (hex_length % 2 == 1)
	  {
	    temp[hex_length] = '0';
	    temp[hex_length + 1] = '\0';
	  }
	oath_hex2bin (temp, NULL, challenge_binary_length);
	challenges = malloc (*challenge_binary_length);
	oath_hex2bin (temp, challenges, challenge_binary_length);
	free (temp);
      }
      break;

    case OATH_OCRA_CHALLENGE_HEX:
      {
	char *temp = malloc (challenge_length + 2);
	if (temp == NULL)
	  {
	    printf
	      ("couldn't allocate temp buffer for challenge conversion\n");
	    return NULL;
	  }
	strncpy (temp, challenge_string, challenge_length + 1);
	if (challenge_length % 2 == 1)
	  {
	    temp[challenge_length] = '0';
	    temp[challenge_length + 1] = '\0';
	  }
	oath_hex2bin (temp, NULL, challenge_binary_length);
	challenges = malloc (*challenge_binary_length);
	oath_hex2bin (temp, challenges, challenge_binary_length);
	free (temp);
      }
      break;

    case OATH_OCRA_CHALLENGE_ALPHA:
      {
	*challenge_binary_length = challenge_length;
	challenges = malloc (*challenge_binary_length);
	strncpy (challenges, challenge_string, *challenge_binary_length);
      }
      break;
    }
  return challenges;
}
