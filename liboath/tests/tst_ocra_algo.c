/*
 * tst_ocra_algo.c - self-tests for liboath OCRA algorithm functions
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

const char *pHash =
  "\x71\x10\xed\xa4\xd0\x9e\x06\x2a\xa5\xe4"
  "\xa3\x90\xb0\xa5\x72\xac\x0d\x2c\x02\x20";

const char *secret =
  "1234567890123456789012345678901234567890123456789012345678901234";

const struct
{
  size_t secretlen;
  char *ocra_suite;
  uint64_t counter;
  char *challenges_hex;
  char *session;
  time_t now;
  char *ocra;
} tv[] =
{
  /* From RFC 6287. */
  {
  20, "OCRA-1:HOTP-SHA1-6:QN08", 0, "000000000", NULL, 0, "237653"},
  {
  20, "OCRA-1:HOTP-SHA1-6:QN08", 0, "A98AC7", NULL, 0, "243178"},
  {
  20, "OCRA-1:HOTP-SHA1-6:QN08", 0, "153158E0", NULL, 0, "653583"},
  {
  20, "OCRA-1:HOTP-SHA1-6:QN08", 0, "1FCA0550", NULL, 0, "740991"},
  {
  20, "OCRA-1:HOTP-SHA1-6:QN08", 0, "2A62B1C0", NULL, 0, "608993"},
  {
  20, "OCRA-1:HOTP-SHA1-6:QN08", 0, "34FB5E30", NULL, 0, "388898"},
  {
  20, "OCRA-1:HOTP-SHA1-6:QN08", 0, "3F940AA0", NULL, 0, "816933"},
  {
  20, "OCRA-1:HOTP-SHA1-6:QN08", 0, "4A2CB710", NULL, 0, "224598"},
  {
  20, "OCRA-1:HOTP-SHA1-6:QN08", 0, "54C56380", NULL, 0, "750600"},
  {
  20, "OCRA-1:HOTP-SHA1-6:QN08", 0, "5F5E0FF0", NULL, 0, "294470"},
  {
  32, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", 0, "BC614E", NULL, 0, "65347737"},
  {
  32, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", 1, "BC614E", NULL, 0, "86775851"},
  {
  32, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", 2, "BC614E", NULL, 0, "78192410"},
  {
  32, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", 3, "BC614E", NULL, 0, "71565254"},
  {
  32, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", 4, "BC614E", NULL, 0, "10104329"},
  {
  32, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", 5, "BC614E", NULL, 0, "65983500"},
  {
  32, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", 6, "BC614E", NULL, 0, "70069104"},
  {
  32, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", 7, "BC614E", NULL, 0, "91771096"},
  {
  32, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", 8, "BC614E", NULL, 0, "75011558"},
  {
  32, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", 9, "BC614E", NULL, 0, "08522129"},
    /* From RFC, changed to SHA1 */
  {
  32, "OCRA-1:HOTP-SHA256-8:QN08-PSHA1", 0, "00000000", NULL, 0, "83238735"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QN08-PSHA1", 0, "A98AC7", NULL, 0, "01501458"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QN08-PSHA1", 0, "153158E0", NULL, 0, "17957585"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QN08-PSHA1", 0, "1FCA0550", NULL, 0, "86776967"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QN08-PSHA1", 0, "2A62B1C0", NULL, 0, "86807031"},
  {
  64, "OCRA-1:HOTP-SHA512-8:C-QN08", 0, "00000000", NULL, 0, "07016083"},
  {
  64, "OCRA-1:HOTP-SHA512-8:C-QN08", 1, "A98AC7", NULL, 0, "63947962"},
  {
  64, "OCRA-1:HOTP-SHA512-8:C-QN08", 2, "153158E0", NULL, 0, "70123924"},
  {
  64, "OCRA-1:HOTP-SHA512-8:C-QN08", 3, "1FCA0550", NULL, 0, "25341727"},
  {
  64, "OCRA-1:HOTP-SHA512-8:C-QN08", 4, "2A62B1C0", NULL, 0, "33203315"},
  {
  64, "OCRA-1:HOTP-SHA512-8:C-QN08", 5, "34FB5E30", NULL, 0, "34205738"},
  {
  64, "OCRA-1:HOTP-SHA512-8:C-QN08", 6, "3F940AA0", NULL, 0, "44343969"},
  {
  64, "OCRA-1:HOTP-SHA512-8:C-QN08", 7, "4A2CB710", NULL, 0, "51946085"},
  {
  64, "OCRA-1:HOTP-SHA512-8:C-QN08", 8, "54C56380", NULL, 0, "20403879"},
  {
  64, "OCRA-1:HOTP-SHA512-8:C-QN08", 9, "5F5E0FF0", NULL, 0, "31409299"},
    /* epoch time 1206446790 == "Mar 25 2008, 12:06:30 GMT" */
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QN08-T1M", 0, "00000000", NULL, 1206446790,
      "95209754"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QN08-T1M", 0, "A98AC7", NULL, 1206446790,
      "55907591"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QN08-T1M", 0, "153158E0", NULL, 1206446790,
      "22048402"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QN08-T1M", 0, "1FCA0550", NULL, 1206446790,
      "24218844"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QN08-T1M", 0, "2A62B1C0", NULL, 1206446790,
      "36209546"},
    /* From RFC, changed to SHA, only server part, alpha-numeric
     * challenges hex-encoded */
  {
  32, "OCRA-1:HOTP-SHA256-8:QA08", 0,
      "434c4932323232305352563131313130", NULL, 0, "28247970"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QA08", 0,
      "434c4932323232315352563131313131", NULL, 0, "01984843"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QA08", 0,
      "434c4932323232325352563131313132", NULL, 0, "65387857"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QA08", 0,
      "434c4932323232335352563131313133", NULL, 0, "03351211"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QA08", 0,
      "434c4932323232345352563131313134", NULL, 0, "83412541"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QA08", 0,
      "5352563131313130434c493232323230", NULL, 0, "15510767"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QA08", 0,
      "5352563131313131434c493232323231", NULL, 0, "90175646"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QA08", 0,
      "5352563131313132434c493232323232", NULL, 0, "33777207"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QA08", 0,
      "5352563131313133434c493232323233", NULL, 0, "95285278"},
  {
  32, "OCRA-1:HOTP-SHA256-8:QA08", 0,
      "5352563131313134434c493232323234", NULL, 0, "28934924"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QA08", 0, "434c4932323232305352563131313130",
      NULL, 0, "79496648"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QA08", 0, "434c4932323232315352563131313131",
      NULL, 0, "76831980"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QA08", 0, "434c4932323232325352563131313132",
      NULL, 0, "12250499"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QA08", 0, "434c4932323232335352563131313133",
      NULL, 0, "90856481"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QA08", 0, "434c4932323232345352563131313134",
      NULL, 0, "12761449"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QA08-PSHA1", 0,
      "5352563131313130434c493232323230", NULL, 0, "18806276"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QA08-PSHA1", 0,
      "5352563131313131434c493232323231", NULL, 0, "70020315"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QA08-PSHA1", 0,
      "5352563131313132434c493232323232", NULL, 0, "01600026"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QA08-PSHA1", 0,
      "5352563131313133434c493232323233", NULL, 0, "18951020"},
  {
  64,
      "OCRA-1:HOTP-SHA512-8:QA08-PSHA1", 0,
      "5352563131313134434c493232323234", NULL, 0, "32528969"}
  /* TODO plain signature test vectors */
  /* Note: all of the TODOs are already covered test cases until SHA256/512 is
   *       available. */
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
      char output_ocra[strlen (tv[i].ocra) + 1];
      size_t bin_length = 0;
      rc = oath_hex2bin (tv[i].challenges_hex, NULL, &bin_length);
      char challenges_bin[bin_length];
      rc = oath_hex2bin (tv[i].challenges_hex, challenges_bin, &bin_length);

      rc = oath_ocra_generate (secret, tv[i].secretlen,
			       tv[i].ocra_suite,
			       tv[i].counter, challenges_bin,
			       bin_length, pHash,
			       tv[i].session, tv[i].now, output_ocra);
      if (rc != OATH_OK)
	{
	  printf ("oath_ocra_generate at %d: %d\n", i, rc);
	  return 1;
	}

      if (strcmp (output_ocra, tv[i].ocra) != 0)
	{
	  printf ("wrong ocra value at %d: %s / %s\n", i, output_ocra,
		  tv[i].ocra);
	  return 1;
	}
    }

  rc = oath_done ();
  if (rc != OATH_OK)
    {
      printf ("oath_done: %d\n", rc);
      return 1;
    }

  return 0;
}
