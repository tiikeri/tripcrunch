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
#include "tripcrunch.h"

#include <stdio.h>
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
// Struct //////////////////////////////
////////////////////////////////////////

/** \brief Struct for char replacements.
 */
typedef struct char_replace_struct
{
	/** Source character. */
	char src;

	/** Destination string. */
	const char *dst;

	/** Size of replace string. */
	size_t dstlen;
} char_replace_t;

////////////////////////////////////////
// Local ///////////////////////////////
////////////////////////////////////////

/** Futallaby salt replace from. */
static char *futa_fr = ":;<=>?@[\\]^_`";

/** Futallaby salt replace to. */
static char *futa_to = "ABCDEFGabcdef";

#ifdef USE_STR_MULTIREPLACE

/** \brief String multi-replace.
 *
 * Performs a replace of certain singular characters into other strings.
 *
 * Faster than performing several replaces in sequence, but less versatile.
 *
 * Will free the source string on replace.
 *
 * @param src Input string.
 * @param replacements Replacement structs.
 * @param rnum Replacement table size.
 * @return Modified or the original string.
 */
static char* str_multireplace(char *src, const char_replace_t *replacements,
		size_t rnum)
{
	size_t orig_len = strlen(src),
				 new_len = orig_len;
	int replace_needed = 0;

	for(size_t ii = 0; (ii < orig_len); ++ii)
	{
		char cc = src[ii];

		for(size_t jj = 0; (jj < rnum); ++jj)
		{
			const char_replace_t *rep = replacements + jj;

			if(rep->src == cc)
			{
				new_len += rep->dstlen - 1;
				replace_needed = 1;
				break;
			}
		}
	}

	// Potentially just bail out.
	if(!replace_needed)
	{
		return src;
	}

	char *ret = (char*)malloc(sizeof(char) * (new_len + 1));
	ret[new_len] = 0;

	size_t kk = 0;
	for(size_t ii = 0; (ii < orig_len); ++ii)
	{
		char cc = src[ii];

		int replace_done = 0;
		for(size_t jj = 0; (jj < rnum); ++jj)
		{
			const char_replace_t *rep = replacements + jj;

			if(rep->src == cc)
			{
				size_t dstlen = rep->dstlen;
				memcpy(ret + kk, rep->dst, dstlen);
				kk += dstlen;
				replace_done = 1;
				break;
			}
		}
		if(!replace_done)
		{
			ret[kk++] = cc;
		}
	}

	free(src);
	return ret;
}

#else

/** \brief Perform a string replace.
 *
 * Will search the string for instances of a certain string, will return the
 * same string if not found or a modified string if found.
 *
 * Needle and replacement are not checked for sanity.
 *
 * Will free the source string on replace.
 *
 * @param src Input string.
 * @param needle Needle to search.
 * @param replacement Replacement to use.
 * @return Modified or the original string.
 */
static char* str_replace(char *src, const char *needle, const char *replacement);
static char* str_replace(char *src, const char *needle, const char *replacement)
{
#ifdef TRIPCRUNCH_DEBUG
	printf("Performing replace: %s, %s, %s\n", src, needle, replacement);
#endif

	size_t len = 0,
				 jj = 0,
				 nlen = strlen(needle),
				 rlen = strlen(replacement),
				 nnum = 0;

	for(size_t ii = 0; (src[ii]); ++ii)
	{
		++len;

		if(needle[jj] == src[ii])
		{
			++jj;

			if(jj == nlen)
			{
				jj = 0;
				++nnum;
			}
		}
		else
		{
			jj = 0;
		}
	}

	if(!nnum)
	{
		return src;
	}
	
	char *ret = (char*)malloc(sizeof(char) * len - nlen * nnum + rlen * nnum + 1);

	jj = 0;
	size_t kk = 0;
	for(size_t ii = 0; (ii < len); ++ii)
	{
		char cc = src[ii];

#ifdef TRIPCRUNCH_DEBUG
		printf("cc: %c kk ) %i\n", cc, kk);
#endif

		ret[kk] = cc;

		if(needle[jj] == cc)
		{
			++jj;

			if(jj == nlen)
			{
				for(unsigned ll = 0; (ll < rlen); ++ll)
				{
					ret[kk + 1 - nlen + ll] = replacement[ll];
				}

				jj = 0;
				kk += rlen;
			}
			else
			{
				++kk;
			}
		}
		else
		{
			jj = 0;
			++kk;
		}
	}
	ret[kk] = 0;

	free(src);
#ifdef TRIPCRUNCH_DEBUG
	printf("Result: %s\n", ret);
#endif
	return ret;
}

#endif

/** \brief Perform a htmlspecialchars replace on a source string.
 *
 * @param src Source string.
 * @return String with htmlspecialchars done on it.
 */
static char* htmlspecialchars(char *src);
static char* htmlspecialchars(char *src)
{
#ifdef USE_STR_MULTIREPLACE
	static const char_replace_t htmlspecialchar_replaces[] =
	{
		{ '&', "&amp;", 5 },
		{ '<', "&lt;", 4 },
		{ '>', "&gt;", 4 },
		{ '"', "&quot;", 6 },
		{ '\'', "&39;", 5 }
	};
	static const size_t htmlspecialchar_replace_count = 5;
	return str_multireplace(src,
			htmlspecialchar_replaces,
			htmlspecialchar_replace_count);
#else
	src = str_replace(src, "&", "&amp;");
	src = str_replace(src, "<", "&lt;");
	src = str_replace(src, ">", "&gt;");
	src = str_replace(src, "\"", "&quot;");
	return str_replace(src, "'", "&#39;");
#endif
}

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

