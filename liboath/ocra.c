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
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "gc.h"

static int strtouint (char *string, uint8_t * uint);

static int
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

static int strtouint_16 (char *string, uint16_t * uint);

static int
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

struct oath_ocra_suite_st
{
  /* Flag indicating whether a counter value is used as data input. */
  uint8_t use_counter;
  /* Defines which hash function is used for password hashes.
     OATH_OCRA_HAS_NONE means no password hash is included as data
     input. */
  oath_ocra_hash_t password_hash;
  /* Defines which hash function is used to calculate the HMAC value
     on which the OCRA value is based. */
  oath_ocra_hash_t ocra_hash;
  /* Defines challenge type, see %oath_ocra_challenge_t. */
  oath_ocra_challenge_t challenge_type;
  /*  Defines length of one challenge string. */
  uint8_t challenge_length;
  /* Divisor used to calculate timesteps passed since beginning of
     epoch (0 means no timestamp included as data input). */
  uint16_t timestamp_div;
  /* Number of bytes of session information used as data input. */
  uint16_t session_length;
  /* Length  of OCRA value (0 == no truncation, full HMAC length). */
  uint8_t digits;
  /* Total length of data input (in bytes). */
  size_t datainput_length;
};
typedef struct oath_ocra_suite_st oath_ocra_suite_t;

/*
 * oath_ocra_parse_suite:
 * @ocra_suite: String to be parsed.
 * @ocra_suite_length: Length of string to be parsed.
 * @ocra_suite_info: Struct where parsed information is stored.
 *
 * Parses the string in @ocra_suite, storing the results in @ocra_suite_info.
 *
 * Returns: on success, %OATH_OK (zero) is returned, otherwise an error code is
 * returned.
 *
 * Since: 2.6.0
 **/
static int
oath_ocra_parse_suite (const char *ocra_suite,
		       oath_ocra_suite_t * ocra_suite_info)
{
  char *alg, *crypto, *datainput, *tmp;
  char *save_ptr_inner, *save_ptr_outer;
  char *suite_tmp = NULL;

  if (ocra_suite_info == NULL || ocra_suite == NULL)
    return OATH_SUITE_PARSE_ERROR;

  ocra_suite_info->password_hash = OATH_OCRA_HASH_NONE;
  ocra_suite_info->ocra_hash = OATH_OCRA_HASH_NONE;
  ocra_suite_info->use_counter = 0;
  ocra_suite_info->timestamp_div = 0;
  ocra_suite_info->session_length = 0;

  suite_tmp = strdup (ocra_suite);
  if (suite_tmp == NULL)
    return OATH_MALLOC_ERROR;

  alg = strtok_r (suite_tmp, ":", &save_ptr_outer);
  if (alg == NULL)
    {
      free (suite_tmp);
      return OATH_SUITE_PARSE_ERROR;
    }

  if (strcasecmp (alg, "OCRA-1") != 0)
    {
      free (suite_tmp);
      return OATH_SUITE_PARSE_ERROR;
    }

  crypto = strtok_r (NULL, ":", &save_ptr_outer);
  if (crypto == NULL)
    {
      free (suite_tmp);
      return OATH_SUITE_PARSE_ERROR;
    }

  tmp = strtok_r (crypto, "-", &save_ptr_inner);
  if (tmp == NULL)
    {
      free (suite_tmp);
      return OATH_SUITE_PARSE_ERROR;
    }

  if (strcasecmp (tmp, "HOTP") != 0)
    {
      free (suite_tmp);
      return OATH_SUITE_PARSE_ERROR;
    }

  tmp = strtok_r (NULL, "-", &save_ptr_inner);
  if (tmp == NULL)
    {
      free (suite_tmp);
      return OATH_SUITE_PARSE_ERROR;
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
      free (suite_tmp);
      return OATH_SUITE_PARSE_ERROR;
    }

  tmp = strtok_r (NULL, "-", &save_ptr_inner);
  if (tmp == NULL)
    {
      free (suite_tmp);
      return OATH_SUITE_PARSE_ERROR;
    }

  if (strtouint (tmp, &(ocra_suite_info->digits)) != 0)
    {
      free (suite_tmp);
      return OATH_SUITE_PARSE_ERROR;
    }
  if (ocra_suite_info->digits != 0 &&
      ((ocra_suite_info->digits) < 4 || (ocra_suite_info->digits) > 10))
    {
      free (suite_tmp);
      return OATH_SUITE_PARSE_ERROR;
    }

  datainput = strtok_r (NULL, ":", &save_ptr_outer);
  free (suite_tmp);

  if (datainput == NULL)
    {
      return OATH_SUITE_PARSE_ERROR;
    }

  ocra_suite_info->datainput_length = strlen (ocra_suite) + 1;

  tmp = strtok_r (datainput, "-", &save_ptr_inner);
  if (tmp == NULL)
    {
      return OATH_SUITE_PARSE_ERROR;
    }
  if (tolower (tmp[0]) == 'c' && tmp[1] == '\0')
    {
      ocra_suite_info->datainput_length += 8;
      ocra_suite_info->use_counter = 1;
      tmp = strtok_r (NULL, "-", &save_ptr_inner);
    }

  if (tmp == NULL)
    {
      return OATH_SUITE_PARSE_ERROR;
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
	  return OATH_SUITE_PARSE_ERROR;
	}
      tmp++;
      if (strtouint (tmp, &(ocra_suite_info->challenge_length)) != 0)
	{
	  return OATH_SUITE_PARSE_ERROR;
	}
      if (ocra_suite_info->challenge_length < 4
	  || ocra_suite_info->challenge_length > 64)
	{
	  return OATH_SUITE_PARSE_ERROR;
	}
      if (tmp[2] != '\0')
	{
	  return OATH_SUITE_PARSE_ERROR;
	}

      ocra_suite_info->datainput_length += 128;
      tmp = strtok_r (NULL, "-", &save_ptr_inner);
    }
  else
    {
      return OATH_SUITE_PARSE_ERROR;
    }

  while (tmp != NULL)
    {
      switch (tolower (tmp[0]))
	{
	case 'p':
	  if (ocra_suite_info->password_hash != OATH_OCRA_HASH_NONE)
	    {
	      return OATH_SUITE_PARSE_ERROR;
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
	      return OATH_SUITE_PARSE_ERROR;
	    }
	  break;

	case 's':
	  if (ocra_suite_info->session_length > 0)
	    {
	      return OATH_SUITE_PARSE_ERROR;
	    }
	  tmp++;
	  if (strtouint_16 (tmp, &(ocra_suite_info->session_length)) != 0)
	    {
	      return OATH_SUITE_PARSE_ERROR;
	    }
	  if (ocra_suite_info->session_length > 512)
	    {
	      return OATH_SUITE_PARSE_ERROR;
	    }
	  if (tmp[3] != '\0')
	    {
	      return OATH_SUITE_PARSE_ERROR;
	    }
	  ocra_suite_info->datainput_length +=
	    ocra_suite_info->session_length;
	  break;

	case 't':
	  if (ocra_suite_info->timestamp_div != 0)
	    {
	      return OATH_SUITE_PARSE_ERROR;
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
		  return OATH_SUITE_PARSE_ERROR;
		}
	      break;

	    case 'm':
	      if (ocra_suite_info->timestamp_div > 59
		  || ocra_suite_info->timestamp_div == 0)
		{
		  return OATH_SUITE_PARSE_ERROR;
		}
	      ocra_suite_info->timestamp_div *= 60;
	      break;

	    case 'h':
	      if (ocra_suite_info->timestamp_div > 48)
		{
		  return OATH_SUITE_PARSE_ERROR;
		}
	      ocra_suite_info->timestamp_div *= 3600;
	      break;

	    default:
	      return OATH_SUITE_PARSE_ERROR;
	    }
	  if (tmp[1] != '\0')
	    {
	      return OATH_SUITE_PARSE_ERROR;
	    }
	  ocra_suite_info->datainput_length += 8;
	  break;

	default:
	  return OATH_SUITE_PARSE_ERROR;
	}
      tmp = strtok_r (NULL, "-", &save_ptr_inner);
    }

  return OATH_OK;

}

static char *oath_ocra_convert_challenge (oath_ocra_challenge_t
					  challenge_type,
					  const char *challenge_string,
					  size_t * challenge_binary_length);

static int oath_ocra_generate_internal (const char *secret,
					size_t secret_length,
					const char *ocra_suite,
					uint64_t counter,
					const char *challenges,
					size_t challenges_length,
					const char *password_hash,
					const char *session, time_t now,
					oath_ocra_suite_t parsed_suite,
					char *output_ocra);

/**
 * oath_ocra_generate:
 * @secret: The shared secret string.
 * @secret_length: Length of @secret.
 * @ocra_suite: String with information about used hash algorithms and input.
 * @counter: Counter value, optional (see @ocra_suite).
 * @challenges: Client/server challenge values, byte-array, mandatory.
 * @challenges_length: Length of @challenges.
 * @password_hash: Hashed password value, optional (see @ocra_suite).
 * @session: Static data about current session, optional (see @ocra-suite).
 * @now: Current timestamp, optional (see @ocra_suite).
 * @output_ocra: Output buffer.
 *
 * Generate a truncated hash-value used for challenge-response-based
 * authentication according to the OCRA algorithm described in RFC 6287.
 * Besides the mandatory challenge(s), additional input is optional.
 *
 * The string @ocra_suite denotes which mode of OCRA is to be used. Furthermore
 * it contains information about which of the possible optional data inputs are
 * to be used, and how.
 *
 * Numeric challenges must be converted to base16 before being passed as byte-array.
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
		    const char *ocra_suite, uint64_t counter,
		    const char *challenges,
		    size_t challenges_length, const char *password_hash,
		    const char *session, time_t now, char *output_ocra)
{
  int rc;
  oath_ocra_suite_t ocra_suite_info;

  rc = oath_ocra_parse_suite (ocra_suite, &ocra_suite_info);
  if (rc != OATH_OK)
    return rc;

  return oath_ocra_generate_internal (secret, secret_length, ocra_suite,
				      counter, challenges,
				      challenges_length, password_hash,
				      session, now, ocra_suite_info,
				      output_ocra);

}

/**
 * oath_ocra_generate2:
 * @secret: The shared secret string.
 * @secret_length: Length of @secret.
 * @ocra_suite: String with information about used hash algorithms and input.
 * @counter: Counter value, optional (see @ocra_suite).
 * @challenges: Array of challenge strings, mandatory
 * @password_hash: Hashed password value, optional (see @ocra_suite).
 * @session: Static data about current session, optional (see @ocra-suite).
 * @now: Current timestamp, optional (see @ocra_suite).
 * @output_ocra: Output buffer.
 *
 * Generate a truncated hash-value used for challenge-response-based
 * authentication according to the OCRA algorithm described in RFC 6287.
 * Besides the mandatory challenge(s), additional input is optional.
 *
 * The string @ocra_suite denotes which mode of OCRA is to be used. Furthermore
 * it contains information about which of the possible optional data inputs are
 * to be used, and how.
 *
 * The challenge strings passed in @challenges are combined into one long
 * challenge string, which is then converted to binary. They must be
 * NUL-terminated.
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
oath_ocra_generate2 (const char *secret, size_t secret_length,
		     const char *ocra_suite,
		     uint64_t counter, const char *challenges[2],
		     const char *password_hash,
		     const char *session, time_t now, char *output_ocra)
{

  int rc;
  oath_ocra_suite_t ocra_suite_info;
  char *challenges_combined;
  char *challenges_combined_bin;
  size_t challenges_combined_bin_length;

  rc =
    oath_ocra_parse_suite (ocra_suite, &ocra_suite_info);

  if (rc != OATH_OK)
    return rc;

  if (challenges[1] == NULL)
    {
      challenges_combined = malloc (strlen (challenges[0]) + 1);
      if (challenges_combined == NULL)
	return OATH_MALLOC_ERROR;
      memcpy (challenges_combined, challenges[0], strlen (challenges[0]));
      challenges_combined[strlen (challenges[0])] = '\0';
    }
  else
    {
      challenges_combined =
	malloc (strlen (challenges[0]) + strlen (challenges[1]) + 1);
      if (challenges_combined == NULL)
	return OATH_MALLOC_ERROR;
      memcpy (challenges_combined, challenges[0], strlen (challenges[0]));
      memcpy (challenges_combined +
	      strlen (challenges[0]), challenges[1], strlen (challenges[1]));
      challenges_combined[strlen (challenges[0]) +
			  strlen (challenges[1])] = '\0';
    }

  challenges_combined_bin =
    oath_ocra_convert_challenge (ocra_suite_info.challenge_type,
				 challenges_combined,
				 &challenges_combined_bin_length);
  if (challenges_combined == NULL)
    return -1;
  rc =
    oath_ocra_generate_internal (secret, secret_length, ocra_suite,
				 counter,
				 challenges_combined,
				 challenges_combined_bin_length,
				 password_hash, session, now,
				 ocra_suite_info, output_ocra);
  free (challenges_combined);
  free (challenges_combined_bin);
  return rc;
}

/**
 * oath_ocra_generate3:
 * @secret: The shared secret string.
 * @secret_length: Length of @secret.
 * @ocra_suite: String with information about used hash algorithms and input.
 * @counter: Counter value, optional (see @ocra_suite).
 * @challenges: Challenge string, mandatory
 * @password_hash: Hashed password value, optional (see @ocra_suite).
 * @session: Static data about current session, optional (see @ocra-suite).
 * @now: Current timestamp, optional (see @ocra_suite).
 * @output_ocra: Output buffer.
 *
 * Generate a truncated hash-value used for challenge-response-based
 * authentication according to the OCRA algorithm described in RFC 6287.
 * Besides the mandatory challenge(s), additional input is optional.
 *
 * The string @ocra_suite denotes which mode of OCRA is to be used. Furthermore
 * it contains information about which of the possible optional data inputs are
 * to be used, and how.
 *
 * The challenge string passed in @challenges contains either one challenge
 * question (in case of one-way authentication) or the correct concatenation of
 * both challenge questions (in case of two-way authentication). It must be
 * NUL-terminated.
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
oath_ocra_generate3 (const char *secret, size_t secret_length,
		     const char *ocra_suite,
		     uint64_t counter, const char *challenges,
		     const char *password_hash,
		     const char *session, time_t now, char *output_ocra)
{
  int rc;
  oath_ocra_suite_t ocra_suite_info;
  char *challenges_bin;
  size_t challenges_bin_length;

  rc =
    oath_ocra_parse_suite (ocra_suite, &ocra_suite_info);

  if (rc != OATH_OK)
    return rc;

  if (challenges == NULL)
    return OATH_SUITE_MISMATCH_ERROR;

  challenges_bin =
    oath_ocra_convert_challenge (ocra_suite_info.challenge_type,
				 challenges, &challenges_bin_length);
  if (challenges_bin == NULL)
    return -1;
  rc =
    oath_ocra_generate_internal (secret, secret_length, ocra_suite,
				 counter,
				 challenges_bin,
				 challenges_bin_length,
				 password_hash, session, now,
				 ocra_suite_info, output_ocra);
  free (challenges_bin);
  return rc;
}

static int
oath_ocra_generate_internal (const char *secret,
			     size_t secret_length,
			     const char *ocra_suite,
			     uint64_t counter,
			     const char *challenges,
			     size_t challenges_length,
			     const char *password_hash,
			     const char *session, time_t now,
			     oath_ocra_suite_t parsed_suite,
			     char *output_ocra)
{

  int rc;
  char *byte_array = NULL;
  char *curr_ptr = NULL;
  uint64_t time_steps = 0;
  char tmp_str[17];
  size_t tmp_len;
  char *hs;
  size_t hs_size;
  uint8_t offset;
  long S;
  int otp_len;
  byte_array = malloc (parsed_suite.datainput_length);
  if (byte_array == NULL)
    {
      return OATH_MALLOC_ERROR;
    }

  curr_ptr = byte_array;
  memcpy (curr_ptr, ocra_suite, strlen (ocra_suite));
  curr_ptr += strlen (ocra_suite);
  curr_ptr[0] = '\0';
  curr_ptr++;
  if (parsed_suite.use_counter)
    {
      tmp_len = 8;
      sprintf (tmp_str, "%016" PRIX64, counter);
      oath_hex2bin (tmp_str, curr_ptr, &tmp_len);
      curr_ptr += 8;
    }

  if (challenges == NULL)
    {
      free (byte_array);
      return OATH_SUITE_MISMATCH_ERROR;
    }

  if (challenges_length > 128)
    {
      free (byte_array);
      return OATH_SUITE_MISMATCH_ERROR;
    }

  memcpy (curr_ptr, challenges, challenges_length);
  curr_ptr += challenges_length;
  if (challenges_length < 128)
    {
      memset (curr_ptr, '\0', (128 - challenges_length));
      curr_ptr += (128 - challenges_length);
    }

  if (parsed_suite.password_hash != OATH_OCRA_HASH_NONE
      && password_hash == NULL)
    {
      free (byte_array);
      return OATH_SUITE_MISMATCH_ERROR;
    }

  switch (parsed_suite.password_hash)
    {
    case OATH_OCRA_HASH_SHA1:
      memcpy (curr_ptr, password_hash, 20);
      curr_ptr += 20;
      break;
    case OATH_OCRA_HASH_SHA256:
      memcpy (curr_ptr, password_hash, 32);
      curr_ptr += 32;
      break;
    case OATH_OCRA_HASH_SHA512:
      memcpy (curr_ptr, password_hash, 64);
      curr_ptr += 64;
      break;
    default:
      break;
    }

  if (parsed_suite.session_length > 0)
    {
      if (session == NULL)
	{
	  free (byte_array);
	  return OATH_SUITE_MISMATCH_ERROR;
	}
      memcpy (curr_ptr, session, parsed_suite.session_length);
      curr_ptr += parsed_suite.session_length;
    }

  if (parsed_suite.timestamp_div != 0)
    {
      time_steps = now / parsed_suite.timestamp_div;
      tmp_len = 8;
      sprintf (tmp_str, "%016" PRIX64, time_steps);
      oath_hex2bin (tmp_str, curr_ptr, &tmp_len);
    }

  /*
     char hexstring[parsed_suite.datainput_length*2+1];
     oath_bin2hex(byte_array,parsed_suite.datainput_length,hexstring);

     printf("BYTE_ARRAY: %d\n",parsed_suite.datainput_length);
     printf(hexstring);
     printf("\n");
   */

  switch (parsed_suite.ocra_hash)
    {
    case OATH_OCRA_HASH_SHA1:
      hs_size = GC_SHA1_DIGEST_SIZE;
      hs = (char *) malloc (hs_size * sizeof (char));
      if (hs == NULL)
	{
	  free (byte_array);
	  return OATH_MALLOC_ERROR;
	}
      rc =
	gc_hmac_sha1 (secret, secret_length, byte_array,
		      parsed_suite.datainput_length, hs);
      break;
    case OATH_OCRA_HASH_SHA256:
      hs_size = GC_SHA256_DIGEST_SIZE;
      hs = (char *) malloc (hs_size * sizeof (char));
      if (hs == NULL)
	{
	  free (byte_array);
	  return OATH_MALLOC_ERROR;
	}
      rc =
	gc_hmac_sha256 (secret, secret_length, byte_array,
			parsed_suite.datainput_length, hs);
      break;
    case OATH_OCRA_HASH_SHA512:
      hs_size = GC_SHA512_DIGEST_SIZE;
      hs = (char *) malloc (hs_size * sizeof (char));
      if (hs == NULL)
	{
	  free (byte_array);
	  return OATH_MALLOC_ERROR;
	}
      rc =
	gc_hmac_sha512 (secret, secret_length, byte_array,
			parsed_suite.datainput_length, hs);
      break;
    default:
      free (byte_array);
      return OATH_SUITE_PARSE_ERROR;
    }

  free (byte_array);
  if (rc != 0)
    {
      return OATH_CRYPTO_ERROR;
    }

  offset = hs[hs_size - 1] & 0x0f;
  S = (((hs[offset] & 0x7f) << 24)
       | ((hs[offset + 1] & 0xff) << 16)
       | ((hs[offset + 2] & 0xff) << 8) | ((hs[offset + 3] & 0xff)));
  free (hs);
  switch (parsed_suite.digits)
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

  otp_len =
    snprintf (output_ocra, parsed_suite.digits + 1, "%.*ld",
	      parsed_suite.digits, S);
  output_ocra[parsed_suite.digits] = '\0';
  if (otp_len <= 0 || ((unsigned) otp_len) != parsed_suite.digits)
    return OATH_PRINTF_ERROR;
  return OATH_OK;
}

/**
 * oath_ocra_validate:
 * @secret: The shared secret string.
 * @secret_length: Length of @secret.
 * @ocra_suite: String with information about used hash algorithms and input.
 * @ocra_suite_length: Length of @ocra_suite.
 * @counter: Counter value, optional (see @ocra_suite).
 * @challenges: Client/server challenge values, byte-array, mandatory.
 * @challenges_length: Length of @challenges.
 * @password_hash: Hashed password value, optional (see @ocra_suite).
 * @session: Static data about current session, optional (see @ocra-suite).
 * @now: Current timestamp, optional (see @ocra_suite).
 * @validate_ocra: OCRA value to validate against.
 *
 * Validates a given OCRA value by generating an OCRA value using the given
 * parameters and comparing the result.
 *
 * Returns: %OATH_OK (zero) on successful validation, an error code otherwise.
 * Since: 2.6.0
 **/
int
oath_ocra_validate (const char *secret, size_t secret_length,
		    const char *ocra_suite,
		    uint64_t counter,
		    const char *challenges,
		    size_t challenges_length,
		    const char *password_hash,
		    const char *session, time_t now,
		    const char *validate_ocra)
{

  int rc;
  char generated_ocra[11];	/* max 10 digits */
  rc = oath_ocra_generate (secret, secret_length,
			   ocra_suite,
			   counter, challenges,
			   challenges_length, password_hash,
			   session, now, generated_ocra);
  if (rc != OATH_OK)
    return rc;
  if (strcmp (generated_ocra, validate_ocra) != 0)
    return OATH_STRCMP_ERROR;
  return OATH_OK;
}

/**
 * oath_ocra_validate2:
 * @secret: The shared secret string.
 * @secret_length: Length of @secret.
 * @ocra_suite: String with information about used hash algorithms and input.
 * @counter: Counter value, optional (see @ocra_suite).
 * @challenges: Array of challenge strings, mandatory
 * @password_hash: Hashed password value, optional (see @ocra_suite).
 * @session: Static data about current session, optional (see @ocra-suite).
 * @now: Current timestamp, optional (see @ocra_suite).
 * @validate_ocra: OCRA value to validate against.
 *
 * Validates a given OCRA value by generating an OCRA value by passing the given
 * parameters to %oath_ocra_generate2 and comparing the result.
 *
 * The string @ocra_suite denotes which mode of OCRA is to be used. Furthermore
 * it contains information about which of the possible optional data inputs are
 * to be used, and how.
 *
 * The challenge strings passed in @challenges are combined into one long
 * challenge string, which is then converted to binary. They must be
 * NUL-terminated.
 *
 * Returns: %OATH_OK (zero) on successful validation, an error code otherwise.
 *
 * Since: 2.6.0
 **/
int
oath_ocra_validate2 (const char *secret, size_t secret_length,
		     const char *ocra_suite,
		     uint64_t counter,
		     const char *challenges[2], const char *password_hash,
		     const char *session, time_t now,
		     const char *validate_ocra)
{
  int rc;
  char generated_ocra[11];
  rc =
    oath_ocra_generate2 (secret, secret_length, ocra_suite,
			 counter, challenges, password_hash,
			 session, now, generated_ocra);
  if (rc != OATH_OK)
    return rc;
  if (strcmp (generated_ocra, validate_ocra) != 0)
    return OATH_STRCMP_ERROR;
  return OATH_OK;
}

/**
 * oath_ocra_validate3:
 * @secret: The shared secret string.
 * @secret_length: Length of @secret.
 * @ocra_suite: String with information about used hash algorithms and input.
 * @counter: Counter value, optional (see @ocra_suite).
 * @challenges: Challenge string, mandatory
 * @password_hash: Hashed password value, optional (see @ocra_suite).
 * @session: Static data about current session, optional (see @ocra-suite).
 * @now: Current timestamp, optional (see @ocra_suite).
 * @validate_ocra: OCRA value to validate against.
 *
 * Validates a given OCRA value by generating an OCRA value by passing the given
 * parameters to %oath_ocra_generate3 and comparing the result.
 * 
 * The challenge string passed in @challenges contains either one challenge
 * question (in case of one-way authentication) or the correct concatenation of
 * both challenge questions (in case of two-way authentication). It must be
 * NUL-terminated.
 *
 * Returns: %OATH_OK (zero) on successful validation, an error code otherwise.
 *
 * Since: 2.6.0
 **/

int
oath_ocra_validate3 (const char *secret, size_t secret_length,
		     const char *ocra_suite,
		     uint64_t counter, const char *challenges,
		     const char *password_hash,
		     const char *session, time_t now,
		     const char *validate_ocra)
{
  int rc;
  char generated_ocra[11];
  rc =
    oath_ocra_generate3 (secret, secret_length, ocra_suite,
			 counter, challenges, password_hash, session, now,
			 generated_ocra);
  if (rc != OATH_OK)
    return rc;
  if (strcmp (generated_ocra, validate_ocra) != 0)
    return OATH_STRCMP_ERROR;
  return OATH_OK;
}

static void
oath_ocra_generate_challenge_internal (oath_ocra_challenge_t
				       challenge_type,
				       size_t challenge_length,
				       char *challenge)
{
  long int random_number;
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
    default:
      break;
    }
}

/**
 * oath_ocra_generate_challenge:
 * @ocra_suite: String containing challenge specification and other OCRA
 * parameters.
 * @challenge: Output buffer, needs space for 65 chars.
 *
 * Generates a (pseudo)random challenge string depending on the type and length
 * given by @ocra_suite.
 *
 * Returns: %OATH_OK (zero) on success, an error code otherwise.
 *
 * Since: 2.6.0
 **/
int
oath_ocra_generate_challenge (const char *ocra_suite,
			      char *challenge)
{
  int rc;
  oath_ocra_suite_t parsed_suite;

  rc = oath_ocra_parse_suite (ocra_suite, &parsed_suite);

  if (rc != OATH_OK)
    return rc;

  oath_ocra_generate_challenge_internal (parsed_suite.challenge_type,
					 parsed_suite.challenge_length,
					 challenge);

  return rc;
}

/**
 * oath_ocra_convert_challenge:
 * @challenge_type: Type of challenge, see %oath_ocra_challenge_t .
 * @challenge_string: Challenge string.
 * @challenge_binary_length: Length of returned byte-array.
 *
 * Converts @challenge_string to binary representation. Numerical values are
 * converted to base16 and then converted using %oath_hex2bin. Hexadecimal
 * values are simply converted using %oath_hex2bin, alpha numerical values are
 * just copied.
 *
 * Returns: malloc'ed byte-array of length @challenge_binary_length.
 *
 * Since: 2.6.0
 **/
char *
oath_ocra_convert_challenge (oath_ocra_challenge_t
			     challenge_type,
			     const char *challenge_string,
			     size_t * challenge_binary_length)
{
  char *challenges = NULL;
  size_t challenge_length = strlen (challenge_string);
  switch (challenge_type)
    {
    case OATH_OCRA_CHALLENGE_NUM:
      {
	unsigned long int num_value = strtoul (challenge_string, NULL, 10);
	char *temp = malloc (challenge_length + 2);
	if (temp == NULL)
	  {
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
	if (challenges == NULL)
	  {
	    free (temp);
	    return NULL;
	  }
	oath_hex2bin (temp, challenges, challenge_binary_length);
	free (temp);
      }
      break;
    case OATH_OCRA_CHALLENGE_HEX:
      {
	char *temp = malloc (challenge_length + 2);
	if (temp == NULL)
	  {
	    return NULL;
	  }
	memcpy (temp, challenge_string, challenge_length);
	temp[challenge_length] = '\0';
	if (challenge_length % 2 == 1)
	  {
	    temp[challenge_length] = '0';
	    temp[challenge_length + 1] = '\0';
	  }
	oath_hex2bin (temp, NULL, challenge_binary_length);
	challenges = malloc (*challenge_binary_length);
	if (challenges == NULL)
	  {
	    free (temp);
	    return NULL;
	  }

	oath_hex2bin (temp, challenges, challenge_binary_length);
	free (temp);
      }
      break;
    case OATH_OCRA_CHALLENGE_ALPHA:
      {
	*challenge_binary_length = challenge_length;
	challenges = malloc (*challenge_binary_length);
	if (challenges == NULL)
	  {
	    return NULL;
	  }

	memcpy (challenges, challenge_string, *challenge_binary_length);
      }
      break;
    default:
      break;
    }
  return challenges;
}
