#include <config.h>

#include "oath.h"

#include <ctype.h>

#include <stdio.h>


const struct
{
  oath_ocra_challenge_t type;
  size_t length;
} tv[] =
{
  {
  OATH_OCRA_CHALLENGE_HEX, 8},
  {
  OATH_OCRA_CHALLENGE_NUM, 5},
  {
  OATH_OCRA_CHALLENGE_ALPHA, 10},
  {
  OATH_OCRA_CHALLENGE_HEX, 24},
  {
  OATH_OCRA_CHALLENGE_HEX, 5},
  {
  OATH_OCRA_CHALLENGE_HEX, 64},
  {
  OATH_OCRA_CHALLENGE_NUM, 2},
  {
  OATH_OCRA_CHALLENGE_NUM, 23},
  {
  OATH_OCRA_CHALLENGE_NUM, 64},
  {
  OATH_OCRA_CHALLENGE_ALPHA, 2},
  {
  OATH_OCRA_CHALLENGE_ALPHA, 15},
  {
  OATH_OCRA_CHALLENGE_ALPHA, 64}
};

int
main (void)
{
  int i;
  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      char challenge[tv[i].length + 1];
      char *tmp = challenge;
      int j;
      oath_ocra_generate_challenge (tv[i].type, tv[i].length, challenge);

      printf ("Challenge #%d, length %d:\n", i, tv[i].length);
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
