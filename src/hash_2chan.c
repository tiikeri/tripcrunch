////////////////////////////////////////
// Define //////////////////////////////
////////////////////////////////////////

/** Replacement string length for futallaby salt replace. */
#define FUTA_REPLACE_LEN 14

/** If defined, use multireplace instead of normal replace. */
#define USE_STR_MULTIREPLACE

////////////////////////////////////////
// Include /////////////////////////////
////////////////////////////////////////

#include "tripcrunch.h"

#include "hash_2chan.h"
#include "str_utils.h"

#include <stdlib.h>
#include <string.h>

#include "openssl/des.h"

////////////////////////////////////////
// Global //////////////////////////////
////////////////////////////////////////

/** Search space for strings. */
const char *search_space_2chan =
"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}";

////////////////////////////////////////
// Local ///////////////////////////////
////////////////////////////////////////

/** Futallaby salt replace from. */
static char *futa_fr = ":;<=>?@[\\]^_`";

/** Futallaby salt replace to. */
static char *futa_to = "ABCDEFGabcdef";

////////////////////////////////////////
// Extern //////////////////////////////
////////////////////////////////////////

char* hash_2chan(char *dst, const char *src, size_t srclen)
{
	char salt[3] = { 'H', '.', 0 };

	if(src == NULL)
	{
		return NULL;
	}

	// Need a duplicate for htmlspecialchars.
	size_t slen = srclen;
	char *str = htmlspecialchars((char*)memdup(src, srclen + 1), &slen);

	if(slen <= 0)
	{
		free(str);
		return NULL;
	}

	// Construct base salt.
	if(slen == 2)
	{
		salt[0] = str[1];
		salt[1] = 'H';
	}
	else if(slen > 2)
	{
		salt[0] = str[1];
		salt[1] = str[2];
	}
	// Replace everything not between . and z with .
	for(int ii = 0; (ii < 2); ++ii)
	{
		int cc = salt[ii];

		if((cc < '.') || (cc > 'z'))
		{
			salt[ii] = '.';
		}
	}
	// Perform the larger replacement.
	for(int ii = 0; (ii < 2); ++ii)
	{
		for(int jj = 0; (jj < FUTA_REPLACE_LEN); ++jj)
		{
			if(salt[ii] == futa_fr[jj])
			{
				salt[ii] = futa_to[jj];
				break;
			}
		}
	}

	// Crypt the source and return a clone of essential data.
	char enc[14]; // DES result size is always 13 characters.
	DES_fcrypt(str, salt, enc);
	memcpy(dst, enc + 3, 11); 
	free(str);
	return dst;
}

////////////////////////////////////////
// Extern //////////////////////////////
////////////////////////////////////////

