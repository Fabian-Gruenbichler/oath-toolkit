/*
 * oathtool.c - command line tool for OATH one-time passwords
 * Copyright (C) 2009-2013 Simon Josefsson
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include "oath.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

/* Gnulib. */
#include "progname.h"
#include "error.h"
#include "version-etc.h"
#include "parse-duration.h"
#include "parse-datetime.h"

#include "oathtool_cmd.h"

const char version_etc_copyright[] =
/* Do *not* mark this string for translation.  %s is a copyright
   symbol suitable for this locale, and %d is the copyright
   year.  */
  "Copyright %s %d Simon Josefsson.";

/* This feature is available in gcc versions 2.5 and later.  */
#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#define OATH_ATTR_NO_RETURN
#else
#define OATH_ATTR_NO_RETURN __attribute__ ((__noreturn__))
#endif

/* *INDENT-OFF* */
static void usage (int status)
    OATH_ATTR_NO_RETURN;
    /* *INDENT-ON* */

static void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, "Try `%s --help' for more information.\n", program_name);
  else
    {
      cmdline_parser_print_help ();
      emit_bug_reporting_address ();
    }
  exit (status);
}

static time_t
parse_time (const char *p, const time_t now)
{
  struct timespec nowspec = { 0, 0 };
  struct timespec thenspec;

  nowspec.tv_sec = now;

  if (!parse_datetime (&thenspec, p, &nowspec))
    return BAD_TIME;

  return thenspec.tv_sec;
}

static void
verbose_hotp (uint64_t moving_factor)
{
  printf ("Start counter: 0x%" PRIX64 " (%" PRIu64 ")\n\n",
	  moving_factor, moving_factor);
}

static void
verbose_totp (time_t t0, time_t time_step_size, time_t when)
{
  struct tm tmp;
  char outstr[200];

  if (gmtime_r (&t0, &tmp) == NULL)
    error (EXIT_FAILURE, 0, "gmtime_r");

  if (strftime (outstr, sizeof (outstr), "%Y-%m-%d %H:%M:%S UTC", &tmp) == 0)
    error (EXIT_FAILURE, 0, "strftime");

  printf ("Step size (seconds): %ld\n", time_step_size);
  printf ("Start time: %s (%ld)\n", outstr, t0);

  if (gmtime_r (&when, &tmp) == NULL)
    error (EXIT_FAILURE, 0, "gmtime_r");

  if (strftime (outstr, sizeof (outstr), "%Y-%m-%d %H:%M:%S UTC", &tmp) == 0)
    error (EXIT_FAILURE, 0, "strftime");

  printf ("Current time: %s (%ld)\n", outstr, when);
  printf ("Counter: 0x%lX (%ld)\n\n", (when - t0) / time_step_size,
	  (when - t0) / time_step_size);
}

#define generate_otp_p(n) ((n) == 1)
#define validate_otp_p(n) ((n) == 2)

#define EXIT_OTP_INVALID 2

int
main (int argc, char *argv[])
{
  struct gengetopt_args_info args_info;
  char *secret;
  size_t secretlen = 0;
  int rc;
  size_t window;
  uint64_t moving_factor;
  unsigned digits;
  char otp[11];
  time_t now, when, t0, time_step_size;
  oath_alg_t mode = OATH_ALGO_HOTP;

  size_t bin_length;
  char *challenges_bin = NULL;
  char *phash_bin = NULL;
  int totpflags = 0;

  set_program_name (argv[0]);

  if (cmdline_parser (argc, argv, &args_info) != 0)
    return EXIT_FAILURE;

  if (args_info.version_given)
    {
      char *p;
      int l = -1;

      if (strcmp (oath_check_version (NULL), OATH_VERSION) != 0)
	l = asprintf (&p, "OATH Toolkit liboath.so %s oath.h %s",
		      oath_check_version (NULL), OATH_VERSION);
      else if (strcmp (OATH_VERSION, PACKAGE_VERSION) != 0)
	l = asprintf (&p, "OATH Toolkit %s",
		      oath_check_version (NULL), OATH_VERSION);
      version_etc (stdout, "oathtool", l == -1 ? "OATH Toolkit" : p,
		   PACKAGE_VERSION, "Simon Josefsson", (char *) NULL);
      if (l != -1)
	free (p);
      return EXIT_SUCCESS;
    }

  if (args_info.help_given)
    usage (EXIT_SUCCESS);

  if (args_info.inputs_num == 0)
    {
      cmdline_parser_print_help ();
      emit_bug_reporting_address ();
      return EXIT_SUCCESS;
    }

  rc = oath_init ();
  if (rc != OATH_OK)
    error (EXIT_FAILURE, 0, "liboath initialization failed: %s",
	   oath_strerror (rc));

  if (args_info.base32_flag)
    {
      rc = oath_base32_decode (args_info.inputs[0],
			       strlen (args_info.inputs[0]),
			       &secret, &secretlen);
      if (rc != OATH_OK)
	error (EXIT_FAILURE, 0, "base32 decoding failed: %s",
	       oath_strerror (rc));
    }
  else
    {
      secretlen = 1 + strlen (args_info.inputs[0]) / 2;
      secret = malloc (secretlen);
      if (!secret)
	error (EXIT_FAILURE, errno, "malloc");

      rc = oath_hex2bin (args_info.inputs[0], secret, &secretlen);
      if (rc != OATH_OK)
	error (EXIT_FAILURE, 0, "hex decoding of secret key failed");
    }

  if (args_info.counter_orig)
    moving_factor = args_info.counter_arg;
  else
    moving_factor = 0;

  if (args_info.digits_orig)
    digits = args_info.digits_arg;
  else
    digits = 6;

  if (args_info.window_orig)
    window = args_info.window_arg;
  else
    window = 0;
  if (args_info.hotp_flag + args_info.totp_given + args_info.ocra_flag > 1)
    error (EXIT_FAILURE, 0,
	   "more than one mode set! use either --hotp, --totp or --ocra");
  if (args_info.totp_given)
    mode = OATH_ALGO_TOTP;
  if (args_info.ocra_flag)
    mode = OATH_ALGO_OCRA;

  if (validate_otp_p (args_info.inputs_num) && !args_info.digits_orig)
    digits = strlen (args_info.inputs[1]);
  else if (validate_otp_p (args_info.inputs_num) && args_info.digits_orig &&
	   args_info.digits_arg != strlen (args_info.inputs[1]))
    error (EXIT_FAILURE, 0,
	   "given one-time password has bad length %d != %ld",
	   args_info.digits_arg, strlen (args_info.inputs[1]));

  if (args_info.inputs_num > 2)
    error (EXIT_FAILURE, 0, "too many parameters");

  if (args_info.verbose_flag)
    {
      char *tmp;

      tmp = malloc (2 * secretlen + 1);
      if (!tmp)
	error (EXIT_FAILURE, errno, "malloc");

      oath_bin2hex (secret, secretlen, tmp);

      printf ("Hex secret: %s\n", tmp);
      free (tmp);

      rc = oath_base32_encode (secret, secretlen, &tmp, NULL);
      if (rc != OATH_OK)
	error (EXIT_FAILURE, 0, "base32 encoding failed: %s",
	       oath_strerror (rc));

      printf ("Base32 secret: %s\n", tmp);
      free (tmp);

      if (args_info.inputs_num == 2)
	printf ("OTP: %s\n", args_info.inputs[1]);
      printf ("Digits: %d\n", digits);
      printf ("Window size: %ld\n", window);
    }

  switch (mode)
    {
    case OATH_ALGO_TOTP:
      if (digits != 6 && digits != 7 && digits != 8)
	error (EXIT_FAILURE, 0, "only digits 6, 7 and 8 are supported");

      now = time (NULL);
      when = parse_time (args_info.now_arg, now);
      t0 = parse_time (args_info.start_time_arg, now);
      time_step_size = parse_duration (args_info.time_step_size_arg);

      if (when == BAD_TIME)
	error (EXIT_FAILURE, 0, "cannot parse time `%s'", args_info.now_arg);

      if (t0 == BAD_TIME)
	error (EXIT_FAILURE, 0, "cannot parse time `%s'",
	       args_info.start_time_arg);

      if (time_step_size == BAD_TIME)
	error (EXIT_FAILURE, 0, "cannot parse time `%s'",
	       args_info.time_step_size_arg);

      if (strcmp (args_info.totp_arg, "sha256") == 0)
	totpflags = OATH_TOTP_HMAC_SHA256;
      else if (strcmp (args_info.totp_arg, "sha512") == 0)
	totpflags = OATH_TOTP_HMAC_SHA512;

      if (args_info.verbose_flag)
	verbose_totp (t0, time_step_size, when);
      if (generate_otp_p (args_info.inputs_num))
	{
	  size_t iter = 0;

	  do
	    {
	      rc = oath_totp_generate2 (secret,
					secretlen,
					when + iter * time_step_size,
					time_step_size, t0, digits, totpflags,
					otp);

	      if (rc != OATH_OK)
		error (EXIT_FAILURE, 0,
		       "generating one-time password failed (%d)", rc);

	      printf ("%s\n", otp);
	    }
	  while (window - iter++ > 0);
	}
      else if (validate_otp_p (args_info.inputs_num))
	{
	  rc = oath_totp_validate4 (secret,
				    secretlen,
				    when,
				    time_step_size,
				    t0,
				    window,
				    NULL, NULL, totpflags,
				    args_info.inputs[1]);

	  if (rc == OATH_INVALID_OTP)
	    error (EXIT_OTP_INVALID, 0,
		   "password \"%s\" not found in range %ld .. %ld",
		   args_info.inputs[1],
		   (long) ((when - t0) / time_step_size - window / 2),
		   (long) ((when - t0) / time_step_size + window / 2));
	  else if (rc < 0)
	    error (EXIT_FAILURE, 0,
		   "validating one-time password failed (%d)", rc);
	  printf ("%d\n", rc);
	}
      break;

    case OATH_ALGO_HOTP:
      if (digits != 6 && digits != 7 && digits != 8)
	error (EXIT_FAILURE, 0, "only digits 6, 7 and 8 are supported");
      if (args_info.verbose_flag)
	verbose_hotp (moving_factor);
      if (generate_otp_p (args_info.inputs_num))
	{
	  size_t iter = 0;

	  do
	    {
	      rc = oath_hotp_generate (secret,
				       secretlen,
				       moving_factor + iter,
				       digits,
				       false, OATH_HOTP_DYNAMIC_TRUNCATION,
				       otp);
	      if (rc != OATH_OK)
		error (EXIT_FAILURE, 0,
		       "generating one-time password failed (%d)", rc);

	      printf ("%s\n", otp);
	    }
	  while (window - iter++ > 0);
	}
      else if (validate_otp_p (args_info.inputs_num))
	{
	  rc = oath_hotp_validate (secret,
				   secretlen,
				   moving_factor, window,
				   args_info.inputs[1]);
	  if (rc == OATH_INVALID_OTP)
	    error (EXIT_OTP_INVALID, 0,
		   "password \"%s\" not found in range %ld .. %ld",
		   args_info.inputs[1],
		   (long) moving_factor, (long) moving_factor + window);
	  else if (rc < 0)
	    error (EXIT_FAILURE, 0,
		   "validating one-time password failed (%d)", rc);
	  printf ("%d\n", rc);
	}
      break;

    case OATH_ALGO_OCRA:
      bin_length = 0;
      if (!args_info.challenges_given)
	error (EXIT_FAILURE, 0,
	       "challenges string is mandatory in OCRA mode");
      if (!args_info.suite_given)
	error (EXIT_FAILURE, 0,
	       "ocra suite string is mandatory in OCRA mode");
      if (args_info.phash_given)
	{
	  rc = oath_hex2bin (args_info.phash_arg, NULL, &bin_length);
	  phash_bin = calloc (bin_length, sizeof (char));
	  if (rc != OATH_TOO_SMALL_BUFFER || phash_bin == NULL)
	    error (EXIT_FAILURE, 0,
		   "could not convert phash string to byte-array (length: %d, rc: %d)",
		   bin_length, rc);

	  rc = oath_hex2bin (args_info.phash_arg, phash_bin, &bin_length);
	  if (rc != OATH_OK)
	    {
	      free (phash_bin);
	      error (EXIT_FAILURE, 0,
		     "could not convert phash string to byte-array");
	    }
	}
      bin_length = 0;
      rc = oath_hex2bin (args_info.challenges_arg, NULL, &bin_length);
      challenges_bin = calloc (bin_length, sizeof (char));
      if (rc != OATH_TOO_SMALL_BUFFER || challenges_bin == NULL)
	error (EXIT_FAILURE, 0,
	       "could not convert challenges string to byte-array");
      rc =
	oath_hex2bin (args_info.challenges_arg, challenges_bin, &bin_length);
      if (rc != OATH_OK)
	{
	  free (challenges_bin);
	  error (EXIT_FAILURE, 0,
		 "could not convert challenges string to byte-array");
	}
      now = time (NULL);
      when = parse_time (args_info.now_arg, now);
      if (generate_otp_p (args_info.inputs_num))
	{
	  rc = oath_ocra_generate (secret,
				   secretlen,
				   args_info.suite_arg,
				   strlen (args_info.suite_arg),
				   args_info.counter_arg,
				   challenges_bin,
				   bin_length,
				   phash_bin,
				   args_info.session_info_arg, when, otp);
	  if (rc != OATH_OK)
	    error (EXIT_FAILURE, 0, "generating OCRA value failed (%d)", rc);
	  printf ("%s\n", otp);
	}
      else if (validate_otp_p (args_info.inputs_num))
	{
	  rc = oath_ocra_validate (secret,
				   secretlen,
				   args_info.suite_arg,
				   strlen (args_info.suite_arg),
				   args_info.counter_arg,
				   challenges_bin,
				   bin_length,
				   phash_bin,
				   args_info.session_info_arg,
				   when, args_info.inputs[1]);
	  if (rc != OATH_OK)
	    error (EXIT_FAILURE, 0, "validating OCRA value failed (%d)", rc);
	  printf ("%d\n", rc);

	}
      free (phash_bin);
      free (challenges_bin);
      break;

    default:
      break;
    }

  free (secret);
  oath_done ();

  return EXIT_SUCCESS;
}
