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

#include "config.h"
#include "hash_2chan.h"
#include "str_utils.h"
#include "tripcrunch.h"

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

char* hash_2chan(char *dst, const char *src)
{
	char salt[3] = { 'H', '.', 0 };

	if(src == NULL)
	{
		return NULL;
	}

	// Need a duplicate for htmlspecialchars.
	char *str = strdup(src);
	str = htmlspecialchars(str);
	size_t slen = strlen(str);

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
	char enc[15]; // Should always be enough.
	DES_fcrypt(str, salt, enc);
	memcpy(dst, enc + (strlen(enc) - 10), 11);
	free(str);
	return dst;
}

////////////////////////////////////////
// Extern //////////////////////////////
////////////////////////////////////////

