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
  "\x71\x10\xed\xa4\xd0\x9e\x06\x2a\xa5\xe4\xa3\x90\xb0\xa5\x72\xac\x0d\x2c\x02\x20";

#define KEY_1 "12345678901234567890"
#define KEY_2 "12345678901234567890123456789012"
#define KEY_3 "1234567890123456789012345678901234567890123456789012345678901234"

#define SUITE_1 "OCRA-1:HOTP-SHA1-6:QN08"
#define SUITE_2 "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1"
#define SUITE_3 "OCRA-1:HOTP-SHA256-8:QN08-PSHA1"
#define SUITE_4 "OCRA-1:HOTP-SHA512-8:C-QN08"
#define SUITE_5 "OCRA-1:HOTP-SHA512-8:QN08-T1M"
#define SUITE_6 "OCRA-1:HOTP-SHA256-8:QA08"
#define SUITE_7 "OCRA-1:HOTP-SHA512-8:QA08"
#define SUITE_8 "OCRA-1:HOTP-SHA512-8:QA08-PSHA1"

#define CHALL_N OATH_OCRA_CHALLENGE_NUM
#define CHALL_H OATH_OCRA_CHALLENGE_HEX
#define CHALL_A OATH_OCRA_CHALLENGE_ALPHANUM

#define CHALL_0 "00000000"
#define CHALL_0_B "\x00"
#define CHALL_1 "11111111"
#define CHALL_1_B "\xa9\x8a\xc7"
#define CHALL_2 "22222222"
#define CHALL_2_B "\x15\x31\x58\xe0"
#define CHALL_3 "33333333"
#define CHALL_3_B "\x1f\xca\x05\x50"
#define CHALL_4 "44444444"
#define CHALL_4_B "\x2a\x62\xb1\xc0"
#define CHALL_5 "55555555"
#define CHALL_5_B "\x34\xfb\x5e\x30"
#define CHALL_6 "66666666"
#define CHALL_6_B "\x3f\x94\x0a\xa0"
#define CHALL_7 "77777777"
#define CHALL_7_B "\x4a\x2c\xb7\x10"
#define CHALL_8 "88888888"
#define CHALL_8_B "\x54\xc5\x63\x80"
#define CHALL_9 "99999999"
#define CHALL_9_B "\x5f\x5e\x0f\xf0"

#define CHALL_10 "12345678"
#define CHALL_10_B "\xbc\x61\x4e"

const struct
{
  char *secret;
  char *ocra_suite;
  uint64_t counter;
  char *challenge_strings[2];
  size_t number_of_challenges;
  oath_ocra_hash_t challenge_types[2];
  char *challenges_binary;
  size_t challenges_binary_length;
  char *session;
  time_t now;
  char *ocra;
} tv[] =
{
  /* From RFC 6287. */
  {
    KEY_1, SUITE_1, 0,
    {
    CHALL_0}, 1,
    {
  CHALL_N}, CHALL_0_B, 1, NULL, 0, "237653"},
  {
    KEY_1, SUITE_1, 0,
    {
    CHALL_1}, 1,
    {
  CHALL_N}, CHALL_1_B, 3, NULL, 0, "243178"},
  {
    KEY_1, SUITE_1, 0,
    {
    CHALL_2}, 1,
    {
  CHALL_N}, CHALL_2_B, 4, NULL, 0, "653583"},
  {
    KEY_1, SUITE_1, 0,
    {
    CHALL_3}, 1,
    {
  CHALL_N}, CHALL_3_B, 4, NULL, 0, "740991"},
  {
    KEY_1, SUITE_1, 0,
    {
    CHALL_4}, 1,
    {
  CHALL_N}, CHALL_4_B, 4, NULL, 0, "608993"},
  {
    KEY_1, SUITE_1, 0,
    {
    CHALL_5}, 1,
    {
  CHALL_N}, CHALL_5_B, 4, NULL, 0, "388898"},
  {
    KEY_1, SUITE_1, 0,
    {
    CHALL_6}, 1,
    {
  CHALL_N}, CHALL_6_B, 4, NULL, 0, "816933"},
  {
    KEY_1, SUITE_1, 0,
    {
    CHALL_7}, 1,
    {
  CHALL_N}, CHALL_7_B, 4, NULL, 0, "224598"},
  {
    KEY_1, SUITE_1, 0,
    {
    CHALL_8}, 1,
    {
  CHALL_N}, CHALL_8_B, 4, NULL, 0, "750600"},
  {
    KEY_1, SUITE_1, 0,
    {
    CHALL_9}, 1,
    {
  CHALL_N}, CHALL_9_B, 4, NULL, 0, "294470"},
  {
    KEY_2, SUITE_2, 0,
    {
    CHALL_10}, 1,
    {
  CHALL_N}, CHALL_10_B, 3, NULL, 0, "65347737"},
  {
    KEY_2, SUITE_2, 1,
    {
    CHALL_10}, 1,
    {
  CHALL_N}, CHALL_10_B, 3, NULL, 0, "86775851"},
  {
    KEY_2, SUITE_2, 2,
    {
    CHALL_10}, 1,
    {
  CHALL_N}, CHALL_10_B, 3, NULL, 0, "78192410"},
  {
    KEY_2, SUITE_2, 3,
    {
    CHALL_10}, 1,
    {
  CHALL_N}, CHALL_10_B, 3, NULL, 0, "71565254"},
  {
    KEY_2, SUITE_2, 4,
    {
    CHALL_10}, 1,
    {
  CHALL_N}, CHALL_10_B, 3, NULL, 0, "10104329"},
  {
    KEY_2, SUITE_2, 5,
    {
    CHALL_10}, 1,
    {
  CHALL_N}, CHALL_10_B, 3, NULL, 0, "65983500"},
  {
    KEY_2, SUITE_2, 6,
    {
    CHALL_10}, 1,
    {
  CHALL_N}, CHALL_10_B, 3, NULL, 0, "70069104"},
  {
    KEY_2, SUITE_2, 7,
    {
    CHALL_10}, 1,
    {
  CHALL_N}, CHALL_10_B, 3, NULL, 0, "91771096"},
  {
    KEY_2, SUITE_2, 8,
    {
    CHALL_10}, 1,
    {
  CHALL_N}, CHALL_10_B, 3, NULL, 0, "75011558"},
  {
    KEY_2, SUITE_2, 9,
    {
    CHALL_10}, 1,
    {
  CHALL_N}, CHALL_10_B, 3, NULL, 0, "08522129"},
  {
    KEY_2, SUITE_3, 0,
    {
    CHALL_0}, 1,
    {
  CHALL_N}, CHALL_0_B, 1, NULL, 0, "83238735"},
  {
    KEY_2, SUITE_3, 0,
    {
    CHALL_1}, 1,
    {
  CHALL_N}, CHALL_1_B, 3, NULL, 0, "01501458"},
  {
    KEY_2, SUITE_3, 0,
    {
    CHALL_2}, 1,
    {
  CHALL_N}, CHALL_2_B, 4, NULL, 0, "17957585"},
  {
    KEY_2, SUITE_3, 0,
    {
    CHALL_3}, 1,
    {
  CHALL_N}, CHALL_3_B, 4, NULL, 0, "86776967"},
  {
    KEY_2, SUITE_3, 0,
    {
    CHALL_4}, 1,
    {
  CHALL_N}, CHALL_4_B, 4, NULL, 0, "86807031"},
  {
    KEY_3, SUITE_4, 0,
    {
    CHALL_0}, 1,
    {
  CHALL_N}, CHALL_0_B, 1, NULL, 0, "07016083"},
  {
    KEY_3, SUITE_4, 1,
    {
    CHALL_1}, 1,
    {
  CHALL_N}, CHALL_1_B, 3, NULL, 0, "63947962"},
  {
    KEY_3, SUITE_4, 2,
    {
    CHALL_2}, 1,
    {
  CHALL_N}, CHALL_2_B, 4, NULL, 0, "70123924"},
  {
    KEY_3, SUITE_4, 3,
    {
    CHALL_3}, 1,
    {
  CHALL_N}, CHALL_3_B, 4, NULL, 0, "25341727"},
  {
    KEY_3, SUITE_4, 4,
    {
    CHALL_4}, 1,
    {
  CHALL_N}, CHALL_4_B, 4, NULL, 0, "33203315"},
  {
    KEY_3, SUITE_4, 5,
    {
    CHALL_5}, 1,
    {
  CHALL_N}, CHALL_5_B, 4, NULL, 0, "34205738"},
  {
    KEY_3, SUITE_4, 6,
    {
    CHALL_6}, 1,
    {
  CHALL_N}, CHALL_6_B, 4, NULL, 0, "44343969"},
  {
    KEY_3, SUITE_4, 7,
    {
    CHALL_7}, 1,
    {
  CHALL_N}, CHALL_7_B, 4, NULL, 0, "51946085"},
  {
    KEY_3, SUITE_4, 8,
    {
    CHALL_8}, 1,
    {
  CHALL_N}, CHALL_8_B, 4, NULL, 0, "20403879"},
  {
    KEY_3, SUITE_4, 9,
    {
    CHALL_9}, 1,
    {
  CHALL_N}, CHALL_9_B, 4, NULL, 0, "31409299"},
    /* epoch time 1206446790 == "Mar 25 2008, 12:06:30 GMT" */
  {
    KEY_3, SUITE_5, 0,
    {
    CHALL_0}, 1,
    {
  CHALL_N}, CHALL_0_B, 1, NULL, 1206446790, "95209754"},
  {
    KEY_3, SUITE_5, 0,
    {
    CHALL_1}, 1,
    {
  CHALL_N}, CHALL_1_B, 3, NULL, 1206446790, "55907591"},
  {
    KEY_3, SUITE_5, 0,
    {
    CHALL_2}, 1,
    {
  CHALL_N}, CHALL_2_B, 4, NULL, 1206446790, "22048402"},
  {
    KEY_3, SUITE_5, 0,
    {
    CHALL_3}, 1,
    {
  CHALL_N}, CHALL_3_B, 4, NULL, 1206446790, "24218844"},
  {
    KEY_3, SUITE_5, 0,
    {
    CHALL_4}, 1,
    {
  CHALL_N}, CHALL_4_B, 4, NULL, 1206446790, "36209546"},
  {
    KEY_2, SUITE_6, 0,
    {
    "CLI22220", "SRV11110"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x43\x4c\x49\x32\x32\x32\x32\x30\x53\x52\x56\x31\x31\x31\x31\x30",
      16, NULL, 0, "28247970"},
  {
    KEY_2, SUITE_6, 0,
    {
    "CLI22221", "SRV11111"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x43\x4c\x49\x32\x32\x32\x32\x31\x53\x52\x56\x31\x31\x31\x31\x31",
      16, NULL, 0, "01984843"},
  {
    KEY_2, SUITE_6, 0,
    {
    "CLI22222", "SRV11112"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x43\x4c\x49\x32\x32\x32\x32\x32\x53\x52\x56\x31\x31\x31\x31\x32",
      16, NULL, 0, "65387857"},
  {
    KEY_2, SUITE_6, 0,
    {
    "CLI22223", "SRV11113"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x43\x4c\x49\x32\x32\x32\x32\x33\x53\x52\x56\x31\x31\x31\x31\x33",
      16, NULL, 0, "03351211"},
  {
    KEY_2, SUITE_6, 0,
    {
    "CLI22224", "SRV11114"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x43\x4c\x49\x32\x32\x32\x32\x34\x53\x52\x56\x31\x31\x31\x31\x34",
      16, NULL, 0, "83412541"},
  {
    KEY_2, SUITE_6, 0,
    {
    "SRV11110", "CLI22220"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x53\x52\x56\x31\x31\x31\x31\x30\x43\x4c\x49\x32\x32\x32\x32\x30",
      16, NULL, 0, "15510767"},
  {
    KEY_2, SUITE_6, 0,
    {
    "SRV11111", "CLI22221"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x53\x52\x56\x31\x31\x31\x31\x31\x43\x4c\x49\x32\x32\x32\x32\x31",
      16, NULL, 0, "90175646"},
  {
    KEY_2, SUITE_6, 0,
    {
    "SRV11112", "CLI22222"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x53\x52\x56\x31\x31\x31\x31\x32\x43\x4c\x49\x32\x32\x32\x32\x32",
      16, NULL, 0, "33777207"},
  {
    KEY_2, SUITE_6, 0,
    {
    "SRV11113", "CLI22223"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x53\x52\x56\x31\x31\x31\x31\x33\x43\x4c\x49\x32\x32\x32\x32\x33",
      16, NULL, 0, "95285278"},
  {
    KEY_2, SUITE_6, 0,
    {
    "SRV11114", "CLI22224"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x53\x52\x56\x31\x31\x31\x31\x34\x43\x4c\x49\x32\x32\x32\x32\x34",
      16, NULL, 0, "28934924"},
  {
    KEY_3, SUITE_7, 0,
    {
    "CLI22220", "SRV11110"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x43\x4c\x49\x32\x32\x32\x32\x30\x53\x52\x56\x31\x31\x31\x31\x30",
      16, NULL, 0, "79496648"},
  {
    KEY_3, SUITE_7, 0,
    {
    "CLI22221", "SRV11111"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x43\x4c\x49\x32\x32\x32\x32\x31\x53\x52\x56\x31\x31\x31\x31\x31",
      16, NULL, 0, "76831980"},
  {
    KEY_3, SUITE_7, 0,
    {
    "CLI22222", "SRV11112"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x43\x4c\x49\x32\x32\x32\x32\x32\x53\x52\x56\x31\x31\x31\x31\x32",
      16, NULL, 0, "12250499"},
  {
    KEY_3, SUITE_7, 0,
    {
    "CLI22223", "SRV11113"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x43\x4c\x49\x32\x32\x32\x32\x33\x53\x52\x56\x31\x31\x31\x31\x33",
      16, NULL, 0, "90856481"},
  {
    KEY_3, SUITE_7, 0,
    {
    "CLI22224", "SRV11114"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x43\x4c\x49\x32\x32\x32\x32\x34\x53\x52\x56\x31\x31\x31\x31\x34",
      16, NULL, 0, "12761449"},
  {
    KEY_3, SUITE_8, 0,
    {
    "SRV11110", "CLI22220"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x53\x52\x56\x31\x31\x31\x31\x30\x43\x4c\x49\x32\x32\x32\x32\x30",
      16, NULL, 0, "18806276"},
  {
    KEY_3, SUITE_8, 0,
    {
    "SRV11111", "CLI22221"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x53\x52\x56\x31\x31\x31\x31\x31\x43\x4c\x49\x32\x32\x32\x32\x31",
      16, NULL, 0, "70020315"},
  {
    KEY_3, SUITE_8, 0,
    {
    "SRV11112", "CLI22222"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x53\x52\x56\x31\x31\x31\x31\x32\x43\x4c\x49\x32\x32\x32\x32\x32",
      16, NULL, 0, "01600026"},
  {
    KEY_3, SUITE_8, 0,
    {
    "SRV11113", "CLI22223"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x53\x52\x56\x31\x31\x31\x31\x33\x43\x4c\x49\x32\x32\x32\x32\x33",
      16, NULL, 0, "18951020"},
  {
    KEY_3, SUITE_8, 0,
    {
    "SRV11114", "CLI22224"}, 2,
    {
  CHALL_A, CHALL_A},
      "\x53\x52\x56\x31\x31\x31\x31\x34\x43\x4c\x49\x32\x32\x32\x32\x34",
      16, NULL, 0, "32528969"}
  /* TODO plain signature test vectors */
  /* Note: all of the TODOs are already covered test cases until SHA256/512 is
   *       available. */
};


int
main (void)
{
  oath_rc rc, rc2;
  int i;

  rc = oath_init ();
  if (rc != OATH_OK)
    {
      printf ("oath_init: %d\n", rc);
      return 1;
    }

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      char output_ocra1[strlen (tv[i].ocra) + 1];
      char output_ocra2[strlen (tv[i].ocra) + 1];
      /*  size_t bin_length = 0;
         rc = oath_hex2bin (tv[i].challenges_hex, NULL, &bin_length);
         char challenges_bin[bin_length];
         rc = oath_hex2bin (tv[i].challenges_hex, challenges_bin, &bin_length); */
      rc =
	oath_ocra_generate (tv[i].secret, strlen (tv[i].secret),
			    tv[i].ocra_suite, tv[i].counter,
			    tv[i].challenges_binary,
			    tv[i].challenges_binary_length, pHash,
			    tv[i].session, tv[i].now, output_ocra1);
      rc2 =
	oath_ocra_generate2 (tv[i].secret, strlen (tv[i].secret),
			     tv[i].ocra_suite, tv[i].counter,
			     tv[i].number_of_challenges,
			     &(tv[i].challenge_types),
			     tv[i].challenge_strings, pHash, tv[i].session,
			     tv[i].now, output_ocra2);

      if (rc != OATH_OK && rc2 != OATH_OK)
	{
	  printf ("oath_ocra_generate at %d: %d\n", i, rc);
	  printf ("oath_ocra_generate2 at %d: %d\n", i, rc2);
	  return 1;
	}

      if (strcmp (output_ocra1, tv[i].ocra) != 0
	  || strcmp (output_ocra2, tv[i].ocra) != 0)
	{
	  printf ("wrong ocra value at %d: %s / %s / %s\n", i, output_ocra1,
		  output_ocra2, tv[i].ocra);
	  return 1;
	}
    }
  return 0;
}
