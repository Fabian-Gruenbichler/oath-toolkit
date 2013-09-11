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

/* Taken from liboath/ocra.c */
struct oath_ocra_suite_st
{
  uint8_t use_counter;
  oath_ocra_hash_t password_hash;
  oath_ocra_hash_t ocra_hash;
  oath_ocra_challenge_t challenge_type;
  uint8_t challenge_length;
  uint16_t time_step_size;
  uint16_t session_length;
  uint8_t digits;
  size_t datainput_length;
};
typedef struct oath_ocra_suite_st oath_ocra_suite_t;

const struct
{
  char *ocra_suite;
  oath_ocra_suite_t exp;
  int rc;
} tv[] =
{
  {
    "OCRA-1:HOTP-SHA1-8:QN08",
    {
    0, OATH_OCRA_HASH_NONE, OATH_OCRA_HASH_SHA1, OATH_OCRA_CHALLENGE_NUM, 8,
	0, 0, 8, 152}
  , OATH_OK},
  {
    "OCRA-2:HOTP-SHA1-6:QN08",
    {
  }, OATH_SUITE_PARSE_ERROR},
  {
    "OCRA-1:HOTP-SHA256-6:C-QA10",
    {
  1, OATH_OCRA_HASH_NONE, OATH_OCRA_HASH_SHA256,
	OATH_OCRA_CHALLENGE_ALPHA, 10, 0, 0, 6, 164}, OATH_OK},
  {
    "OCRA-1:HOTP-SHA512-2:C-QH24",
    {
  1, OATH_OCRA_HASH_NONE, OATH_OCRA_HASH_SHA512, OATH_OCRA_CHALLENGE_HEX,
	25, 0, 0, 0}, OATH_SUITE_PARSE_ERROR},
  {
    "OCRA-1:HOTP-SHA1-0:C-QA20-PSHA512-S128-T12M",
    {
    1, OATH_OCRA_HASH_SHA512, OATH_OCRA_HASH_SHA1,
	OATH_OCRA_CHALLENGE_ALPHA, 20, 720, 128, 0, 380}
  , OATH_OK},
  {
    "OCRA-1:HOTP-SHA256-10:QN64-PSHA512-S064-T12H",
    {
    0, OATH_OCRA_HASH_SHA512, OATH_OCRA_HASH_SHA256,
	OATH_OCRA_CHALLENGE_NUM, 64, 12 * 60 * 60, 64, 10, 309}
  , OATH_OK}
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
      oath_ocra_suite_t osi;

      rc = oath_ocra_suite_counter (tv[i].ocra_suite, &(osi.use_counter));
      if (rc != tv[i].rc)
	{
	  printf ("rc mismatch for testcase #%d: %d vs %d\n", i, rc,
		  tv[i].rc);
	  return 1;
	}
      rc =
	oath_ocra_suite_challenge (tv[i].ocra_suite, &(osi.challenge_type),
				   &(osi.challenge_length));
      if (rc != tv[i].rc)
	{
	  printf ("rc mismatch for testcase #%d: %d vs %d\n", i, rc,
		  tv[i].rc);
	  return 1;
	}
      rc =
	oath_ocra_suite_data_length (tv[i].ocra_suite,
				     &(osi.datainput_length));
      if (rc != tv[i].rc)
	{
	  printf ("rc mismatch for testcase #%d: %d vs %d\n", i, rc,
		  tv[i].rc);
	  return 1;
	}
      rc = oath_ocra_suite_digits (tv[i].ocra_suite, &(osi.digits));
      if (rc != tv[i].rc)
	{
	  printf ("rc mismatch for testcase #%d: %d vs %d\n", i, rc,
		  tv[i].rc);
	  return 1;
	}
      rc = oath_ocra_suite_hash (tv[i].ocra_suite, &(osi.ocra_hash));
      if (rc != tv[i].rc)
	{
	  printf ("rc mismatch for testcase #%d: %d vs %d\n", i, rc,
		  tv[i].rc);
	  return 1;
	}
      rc = oath_ocra_suite_password (tv[i].ocra_suite, &(osi.password_hash));
      if (rc != tv[i].rc)
	{
	  printf ("rc mismatch for testcase #%d: %d vs %d\n", i, rc,
		  tv[i].rc);
	  return 1;
	}
      rc = oath_ocra_suite_session (tv[i].ocra_suite, &(osi.session_length));
      if (rc != tv[i].rc)
	{
	  printf ("rc mismatch for testcase #%d: %d vs %d\n", i, rc,
		  tv[i].rc);
	  return 1;
	}
      rc = oath_ocra_suite_time (tv[i].ocra_suite, &(osi.time_step_size));
      if (rc != tv[i].rc)
	{
	  printf ("rc mismatch for testcase #%d: %d vs %d\n", i, rc,
		  tv[i].rc);
	  return 1;
	}
      if (rc == OATH_OK)
	{
	  if (osi.use_counter != tv[i].exp.use_counter)
	    {
	      printf ("use_counter mismatch for testcase #%d: %d vs %d\n", i,
		      osi.use_counter, tv[i].exp.use_counter);
	      return 1;
	    }
	  if (osi.password_hash != tv[i].exp.password_hash)
	    {
	      printf ("password_hash mismatch for testcase #%d: %d vs %d\n",
		      i, osi.password_hash, tv[i].exp.password_hash);
	      return 1;
	    }
	  if (osi.ocra_hash != tv[i].exp.ocra_hash)
	    {
	      printf ("ocra_hash mismatch for testcase #%d: %d vs %d\n", i,
		      osi.ocra_hash, tv[i].exp.ocra_hash);
	      return 1;
	    }
	  if (osi.challenge_type != tv[i].exp.challenge_type)
	    {
	      printf ("challenge_type mismatch for testcase #%d: %d vs %d\n",
		      i, osi.challenge_type, tv[i].exp.challenge_type);
	      return 1;
	    }
	  if (osi.challenge_length != tv[i].exp.challenge_length)
	    {
	      printf
		("challenge_length mismatch for testcase #%d: %d vs %d\n", i,
		 osi.challenge_length, tv[i].exp.challenge_length);
	      return 1;
	    }
	  if (osi.time_step_size != tv[i].exp.time_step_size)
	    {
	      printf ("time_step_size mismatch for testcase #%d: %d vs %d\n",
		      i, osi.time_step_size, tv[i].exp.time_step_size);
	      return 1;
	    }
	  if (osi.session_length != tv[i].exp.session_length)
	    {
	      printf ("session_length mismatch for testcase #%d: %d vs %d\n",
		      i, osi.session_length, tv[i].exp.session_length);
	      return 1;
	    }
	  if (osi.digits != tv[i].exp.digits)
	    {
	      printf ("digits mismatch for testcase #%d: %d vs %d\n", i,
		      osi.digits, tv[i].exp.digits);
	      return 1;
	    }
	  if (osi.datainput_length != tv[i].exp.datainput_length)
	    {
	      printf
		("datainput_length mismatch for testcase #%d: %d vs %d\n", i,
		 osi.datainput_length, tv[i].exp.datainput_length);
	      return 1;
	    }
	}
    }
  return 0;
}
