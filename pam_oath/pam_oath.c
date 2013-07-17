/*
 * pam_oath.c - a PAM module for OATH one-time passwords
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

/* Libtool defines PIC for shared objects */
#ifndef PIC
#define PAM_STATIC
#endif

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#define D(x) do {							\
    printf ("[%s:%s(%d)] ", __FILE__, __FUNCTION__, __LINE__);		\
    printf x;								\
    printf ("\n");							\
  } while (0)
#define DBG(x) if (cfg.debug) { D(x); }

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

#define MIN_OTP_LEN 6
#define MAX_OTP_LEN 8

struct cfg
{
  int debug;
  int alwaysok;
  int try_first_pass;
  int use_first_pass;
  char *usersfile;
  unsigned digits;
  unsigned window;
};

static void
parse_cfg (int flags, int argc, const char **argv, struct cfg *cfg)
{
  int i;

  cfg->debug = 0;
  cfg->alwaysok = 0;
  cfg->try_first_pass = 0;
  cfg->use_first_pass = 0;
  cfg->usersfile = NULL;
  cfg->digits = -1;
  cfg->window = 5;

  for (i = 0; i < argc; i++)
    {
      if (strcmp (argv[i], "debug") == 0)
	cfg->debug = 1;
      if (strcmp (argv[i], "alwaysok") == 0)
	cfg->alwaysok = 1;
      if (strcmp (argv[i], "try_first_pass") == 0)
	cfg->try_first_pass = 1;
      if (strcmp (argv[i], "use_first_pass") == 0)
	cfg->use_first_pass = 1;
      if (strncmp (argv[i], "usersfile=", 10) == 0)
	cfg->usersfile = (char *) argv[i] + 10;
      if (strncmp (argv[i], "digits=", 7) == 0)
	cfg->digits = atoi (argv[i] + 7);
      if (strncmp (argv[i], "window=", 7) == 0)
	cfg->window = atoi (argv[i] + 7);
    }

  if (cfg->digits != 6 && cfg->digits != 7 && cfg->digits != 8)
    {
      if (cfg->digits != -1)
	D (("only 6, 7, and 8 OTP lengths are supported: invalid value %d",
	    cfg->digits));
      cfg->digits = 0;
    }

  if (cfg->debug)
    {
      D (("called."));
      D (("flags %d argc %d", flags, argc));
      for (i = 0; i < argc; i++)
	D (("argv[%d]=%s", i, argv[i]));
      D (("debug=%d", cfg->debug));
      D (("alwaysok=%d", cfg->alwaysok));
      D (("try_first_pass=%d", cfg->try_first_pass));
      D (("use_first_pass=%d", cfg->use_first_pass));
      D (("usersfile=%s", cfg->usersfile ? cfg->usersfile : "(null)"));
      D (("digits=%d", cfg->digits));
      D (("window=%d", cfg->window));
    }
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  int retval, rc;
  const char *user = NULL;
  const char *password = NULL;
  char *challenges = NULL;
  size_t challenges_length = 0;
  char otp[MAX_OTP_LEN + 1];
  int password_len = 0;
  struct pam_conv *conv;
  struct pam_message *pmsg[1], msg[1];
  struct pam_response *resp;
  int nargs = 1;
  struct cfg cfg;
  char *query_prompt = NULL;
  char *onlypasswd = strdup ("");	/* empty passwords never match */

  parse_cfg (flags, argc, argv, &cfg);

  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    {
      DBG (("get user returned error: %s", pam_strerror (pamh, retval)));
      goto done;
    }
  DBG (("get user returned: %s", user));

  if (cfg.try_first_pass || cfg.use_first_pass)
    {
      retval = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &password);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("get password returned error: %s",
		pam_strerror (pamh, retval)));
	  goto done;
	}
      DBG (("get password returned: %s", password));
    }

  if (cfg.use_first_pass && password == NULL)
    {
      DBG (("use_first_pass set and no password, giving up"));
      retval = PAM_AUTH_ERR;
      goto done;
    }

  rc = oath_init ();
  if (rc != OATH_OK)
    {
      DBG (("oath_init() failed (%d)", rc));
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }

  if (password == NULL)
    {
      retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("get conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      pmsg[0] = &msg[0];
      {
    oath_alg algorithm = OATH_NONE;
    char ocra_suite[44];
    ocra_suite_t ocra_suite_info;
    rc = oath_retrieve_mode(cfg.usersfile,user,&algorithm,ocra_suite);

    if (rc != OATH_OK)
      {
        DBG (("One-time password not authorized to login as user '%s'", user));
        retval = PAM_AUTH_ERR;
        goto done;
      }

    if(algorithm == OATH_OCRA)
      {
        rc = oath_ocra_parse_suite(ocra_suite,strlen(ocra_suite),&ocra_suite_info);
        if (rc != OATH_OK)
          {
            DBG (("Malformed OCRA suite for user '%s'", user));
            retval = PAM_AUTH_ERR;
            goto done;
          }
        char challenge_string[ocra_suite_info.challenge_length+1];
        oath_ocra_generate_challenge(ocra_suite_info.challenge_type,
                                ocra_suite_info.challenge_length,
                                challenge_string);

        switch(ocra_suite_info.challenge_type) {
            case NUM:
                {
                    unsigned long int num_value = strtoul(challenge_string,NULL,10);
                    char temp[ocra_suite_info.challenge_type];
                    sprintf(temp,"%lX",num_value);
                    oath_hex2bin(temp,NULL,&challenges_length);
                    challenges = malloc(challenges_length);
                    oath_hex2bin(temp,challenges,&challenges_length);
                }
                break;

            case HEX:
                {
                    oath_hex2bin(challenge_string,NULL,&challenges_length);
                    challenges = malloc(challenges_length);
                    oath_hex2bin(challenge_string,challenges,&challenges_length);

                }
                break;

            case ALPHA:
                {
                    challenges_length = strlen(challenge_string);
                    strncpy(challenges,challenge_string,challenges_length);
                }
                break;
        }

	    const char *query_template = "One-time password (OCRA) for `%s' - challenge is \"%s\": ";
        size_t len = strlen (query_template) + strlen (user) + strlen (challenge_string);
	    size_t wrote;

	    query_prompt = malloc (len);
	    if (!query_prompt)
	      {
	        retval = PAM_BUF_ERR;
	        goto done;
	      }

	    wrote = snprintf (query_prompt, len, query_template, user, challenge_string);
	    if (wrote < 0 || wrote >= len)
	      {
	        retval = PAM_BUF_ERR;
	        goto done;
	      }
      }
    else
      {
	    const char *query_template = "One-time password (OATH) for `%s': ";
        size_t len = strlen (query_template) + strlen (user);
	    size_t wrote;

	    query_prompt = malloc (len);
	    if (!query_prompt)
	      {
	        retval = PAM_BUF_ERR;
	        goto done;
	      }
    
    	wrote = snprintf (query_prompt, len, query_template, user);
    	if (wrote < 0 || wrote >= len)
    	  {
    	    retval = PAM_BUF_ERR;
    	    goto done;
    	  }
      }

	msg[0].msg = query_prompt;
      }
      msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
      resp = NULL;

      retval = conv->conv (nargs, (const struct pam_message **) pmsg,
			   &resp, conv->appdata_ptr);

      free (query_prompt);
      query_prompt = NULL;

      if (retval != PAM_SUCCESS)
	{
	  DBG (("conv returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}

      DBG (("conv returned: %s", resp->resp));

      password = resp->resp;
    }

  if (password)
    password_len = strlen (password);
  else
    {
      DBG (("Could not read password"));
      retval = PAM_AUTH_ERR;
      goto done;
    }

  if (password_len < MIN_OTP_LEN)
    {
      DBG (("OTP too short: %s", password));
      retval = PAM_AUTH_ERR;
      goto done;
    }
  else if (cfg.digits != 0 && password_len < cfg.digits)
    {
      DBG (("OTP shorter than digits=%d: %s", cfg.digits, password));
      retval = PAM_AUTH_ERR;
      goto done;
    }
  else if (cfg.digits == 0 && password_len > MAX_OTP_LEN)
    {
      DBG (("OTP too long (and no digits=): %s", password));
      retval = PAM_AUTH_ERR;
      goto done;
    }
  else if (cfg.digits != 0 && password_len > cfg.digits)
    {
      free (onlypasswd);
      onlypasswd = strdup (password);

      /* user entered their system password followed by generated OTP? */

      onlypasswd[password_len - cfg.digits] = '\0';

      DBG (("Password: %s ", onlypasswd));

      memcpy (otp, password + password_len - cfg.digits, cfg.digits);
      otp[cfg.digits] = '\0';

      retval = pam_set_item (pamh, PAM_AUTHTOK, onlypasswd);
      if (retval != PAM_SUCCESS)
	{
	  DBG (("set_item returned error: %s", pam_strerror (pamh, retval)));
	  goto done;
	}
    }
  else
    {
      strcpy (otp, password);
      password = NULL;
    }

  DBG (("OTP: %s", otp ? otp : "(null)"));

  {
    time_t last_otp;

    rc = oath_authenticate_usersfile2 (cfg.usersfile,
				      user,
				      otp, cfg.window, onlypasswd, 
				      challenges, challenges_length,
				      &last_otp);
    DBG (("authenticate rc %d (%s: %s) last otp %s", rc,
	  oath_strerror_name (rc) ? oath_strerror_name (rc) : "UNKNOWN",
	  oath_strerror (rc), ctime (&last_otp)));
  }

  if (rc != OATH_OK)
    {
      DBG (("One-time password not authorized to login as user '%s'", user));
      retval = PAM_AUTH_ERR;
      goto done;
    }

  retval = PAM_SUCCESS;

done:
  oath_done ();
  free (query_prompt);
  free (onlypasswd);
  free (challenges);
  if (cfg.alwaysok && retval != PAM_SUCCESS)
    {
      DBG (("alwaysok needed (otherwise return with %d)", retval));
      retval = PAM_SUCCESS;
    }
  DBG (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_oath_modstruct = {
  "pam_oath",
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};

#endif
