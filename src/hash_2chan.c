////////////////////////////////////////
// Define //////////////////////////////
////////////////////////////////////////

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
	// Perform replaces.
	for(int ii = 0; (ii < 2); ++ii)
	{
		int cc = (int)(salt[ii]);

		// Not '.' <-> 'z' => '.'
		if((cc < '.') || (cc > 'z'))
		{
			salt[ii] = '.';
		}
		// :;<=>?@ => ABCDEFG
		else if((cc >= ':') && (cc <= '@'))
		{
			salt[ii] = (char)(cc + ('A' - ':'));
		}
		// [\]^_` => abcdef
		else if((cc >= '[') && (cc <= '`'))
		{
			salt[ii] = (char)(cc + ('a' - '['));
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

