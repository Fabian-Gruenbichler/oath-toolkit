/*
 * tst_ocra_parse.c - self-tests for liboath OCRASuite parser functions
 * Copyright (C) 2013 Fabian Grünbichler
 * Copyright (C) 2013 Simon Josefsson
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

const struct
{
  char *ocrasuite;
  int rc;
  oath_ocra_hash_t ocra_hash;
  uint8_t digits;
  bool counter;
  oath_ocra_hash_t password_hash;
  oath_ocra_challenge_t challenge_type;
  uint8_t challenge_length;
  uint16_t time_step_size;
  uint16_t session_length;
} tv[] =
{
  {
    "OCRA-1:HOTP-SHA1-8:QN08", OATH_OK,
    OATH_OCRA_HASH_SHA1, 8, 0,
    OATH_OCRA_HASH_NONE, OATH_OCRA_CHALLENGE_NUM, 8, 0, 0
  },
  {
    "OCRA-2:HOTP-SHA1-6:QN08", OATH_SUITE_PARSE_ERROR
  },
  {
    "OCRA-1:HOTP-SHA256-6:C-QA10", OATH_OK,
    OATH_OCRA_HASH_SHA256, 6, 1, OATH_OCRA_HASH_NONE,
    OATH_OCRA_CHALLENGE_ALPHANUM, 10, 0, 0
  },
  {
    "OCRA-1:HOTP-SHA512-2:C-QH24", OATH_SUITE_PARSE_ERROR
  },
  {
    "OCRA-1:HOTP-SHA1-0:C-QA20-PSHA512-S128-T12M", OATH_OK,
    OATH_OCRA_HASH_SHA1, 0, 1, OATH_OCRA_HASH_SHA512,
    OATH_OCRA_CHALLENGE_ALPHANUM, 20, 720, 128
  },
  {
    "OCRA-1:HOTP-SHA256-10:QN64-PSHA512-S064-T12H", OATH_OK,
    OATH_OCRA_HASH_SHA256, 10, 0, OATH_OCRA_HASH_SHA512,
    OATH_OCRA_CHALLENGE_NUM, 64, 12 * 60 * 60, 64
  }
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
      oath_ocrasuite_t *osi;
      oath_ocra_hash_t ocra_hash;
      int digits;
      bool counter;
      oath_ocra_hash_t password_hash;
      oath_ocra_challenge_t challenge_type;
      size_t challenge_length;
      uint16_t time_step_size;
      size_t session_length;

      rc = oath_ocrasuite_parse (tv[i].ocrasuite, &osi);
      if (rc != tv[i].rc)
	{
	  printf ("rc mismatch for testcase #%d: %d vs %d\n", i, rc,
		  tv[i].rc);
	  return 1;
	}
      if (rc != OATH_OK)
	continue;

      ocra_hash = oath_ocrasuite_get_cryptofunction_hash (osi);
      if (ocra_hash != tv[i].ocra_hash)
	{
	  printf ("hash mismatch for testcase #%d: %d vs %d\n", i, ocra_hash,
		  tv[i].ocra_hash);
	  return 1;
	}

      digits = oath_ocrasuite_get_cryptofunction_digits (osi);
      if (digits != tv[i].digits)
	{
	  printf ("digits mismatch for testcase #%d: %d vs %d\n", i, digits,
		  tv[i].digits);
	  return 1;
	}

      counter = oath_ocrasuite_get_counter (osi);
      if (counter != tv[i].counter)
	{
	  printf ("counter mismatch for testcase #%d: %d vs %d\n", i, counter,
		  tv[i].counter);
	  return 1;
	}

      challenge_type = oath_ocrasuite_get_challenge_type (osi);
      if (challenge_type != tv[i].challenge_type)
	{
	  printf ("challenge_type mismatch for testcase #%d: %d vs %d\n", i,
		  challenge_type, tv[i].challenge_type);
	  return 1;
	}

      challenge_length = oath_ocrasuite_get_challenge_length (osi);
      if (challenge_length != tv[i].challenge_length)
	{
	  printf ("challenge_length mismatch for testcase #%d: %d vs %d\n", i,
		  challenge_length, tv[i].challenge_length);
	  return 1;
	}

      password_hash = oath_ocrasuite_get_password_hash (osi);
      if (password_hash != tv[i].password_hash)
	{
	  printf ("password_hash mismatch for testcase #%d: %d vs %d\n", i,
		  password_hash, tv[i].password_hash);
	  return 1;
	}

      session_length = oath_ocrasuite_get_session_length (osi);
      if (session_length != tv[i].session_length)
	{
	  printf ("session_length mismatch for testcase #%d: %d vs %d\n", i,
		  session_length, tv[i].session_length);
	  return 1;
	}

      oath_ocrasuite_done (osi);
    }

  return 0;
}
