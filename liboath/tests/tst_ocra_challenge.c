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

#include <ctype.h>

#include <stdio.h>


const struct
{
  oath_ocra_challenge_t type;
  const char *ocra_suite;
  size_t length;
} tv[] =
{
  {
  OATH_OCRA_CHALLENGE_HEX, "OCRA-1:HOTP-SHA256-8:QH08", 8},
  {
  OATH_OCRA_CHALLENGE_NUM, "OCRA-1:HOTP-SHA256-8:QN05", 5},
  {
  OATH_OCRA_CHALLENGE_ALPHA, "OCRA-1:HOTP-SHA256-8:QA10", 10},
  {
  OATH_OCRA_CHALLENGE_HEX, "OCRA-1:HOTP-SHA256-8:QH24", 24},
  {
  OATH_OCRA_CHALLENGE_HEX, "OCRA-1:HOTP-SHA256-8:QH05", 5},
  {
  OATH_OCRA_CHALLENGE_HEX, "OCRA-1:HOTP-SHA256-8:QH64", 64},
  {
  OATH_OCRA_CHALLENGE_NUM, "OCRA-1:HOTP-SHA256-8:QN04", 4},
  {
  OATH_OCRA_CHALLENGE_NUM, "OCRA-1:HOTP-SHA256-8:QN23", 23},
  {
  OATH_OCRA_CHALLENGE_NUM, "OCRA-1:HOTP-SHA256-8:QN64", 64},
  {
  OATH_OCRA_CHALLENGE_ALPHA, "OCRA-1:HOTP-SHA256-8:QA04", 4},
  {
  OATH_OCRA_CHALLENGE_ALPHA, "OCRA-1:HOTP-SHA256-8:QA15", 15},
  {
  OATH_OCRA_CHALLENGE_ALPHA, "OCRA-1:HOTP-SHA256-8:QA64", 64}
};

int
main (void)
{
  int rc, i;

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      char challenge[tv[i].length + 1];
      char *tmp = challenge;
      int j;

      rc = oath_ocra_challenge_generate_suitestr (tv[i].ocra_suite, challenge);
      if (rc != OATH_OK)
	{
	  printf ("oath_ocra_challenge_generate_suitestr at %d: %d\n", i, rc);
	  return 1;
	}

      printf ("Challenge #%d length %d for suite %s:\n", i, tv[i].length,
	      tv[i].ocra_suite);
      printf (challenge);
      printf ("\n\n");

      if (strlen (challenge) != tv[i].length)
	{
	  printf ("challenge string doesn't have desired length: %d vs %d\n",
		  strlen (challenge), tv[i].length);
	  return 1;
	}
      switch (tv[i].type)
	{
	case OATH_OCRA_CHALLENGE_NUM:
	  for (j = 0; j < strlen (challenge); j++)
	    {
	      if (!isdigit (*tmp))
		{
		  printf
		    ("OATH_OCRA_CHALLENGE_NUM challenge contains non-digit char at position %d: %c\n",
		     j, *tmp);
		  return 1;
		}
	    }
	  break;

	case OATH_OCRA_CHALLENGE_HEX:
	  for (j = 0; j < strlen (challenge); j++)
	    {
	      if (!isxdigit (*tmp))
		{
		  printf
		    ("OATH_OCRA_CHALLENGE_HEX challenge contains non-hex char at position %d: %c\n",
		     j, *tmp);
		  return 1;
		}
	    }
	  break;

	case OATH_OCRA_CHALLENGE_ALPHA:
	  for (j = 0; j < strlen (challenge); j++)
	    {
	      if (!isalnum (*tmp))
		{
		  printf
		    ("OATH_OCRA_CHALLENGE_ALPHA challenge contains non-alphanumeric char at position %d: %c\n",
		     j, *tmp);
		  return 1;
		}
	    }
	  break;

	}
    }
  return 0;
}
