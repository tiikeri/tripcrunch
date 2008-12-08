////////////////////////////////////////
// Define //////////////////////////////
////////////////////////////////////////

/** Maximum ASCII ordinal in search strings. */
#define SEARCH_MAX_ORD 128

////////////////////////////////////////
// Include /////////////////////////////
////////////////////////////////////////

#include "str_utils.h"

#include <stdlib.h>
#include <string.h>

////////////////////////////////////////
// Local variable //////////////////////
////////////////////////////////////////

/** Search space to use. */
static const char *search_space = NULL;

/** Search space size. */
static int search_space_size = 0;

/** Lookup table for transformations. */
static int *search_lookup = NULL;

/** htmlspecialchars replace table. */
static const char_replace_t htmlspecialchars_replaces[] =
{
	{ '&', "&amp;", 5 },
	{ '<', "&lt;", 4 },
	{ '>', "&gt;", 4 },
	{ '"', "&quot;", 6 }
	//{ '\'', "&39;", 5 } // This replace is not used,
};

/** htmlspecialchars replace table size. */
static const size_t htmlspecialchars_replace_count = 4;

////////////////////////////////////////
// Local function //////////////////////
////////////////////////////////////////

/** \brief Get character at a given index in the search space.
 *
 * @param idx Index to fetch from.
 * @return Character found.
 */
static inline char search_lookup_forward(int idx);
static inline char search_lookup_forward(int idx)
{
#ifdef TRIPCRUNCH_DEBUG
	if((idx < 0) || (idx >= search_space_size))
	{
		printf("ERROR, search space index out of range");
		exit(1);
	}
#endif

	return search_space[idx];
}

/** \brief Get the index of a character in the search space.
 *
 * @param cc Character.
 * @return Index of that character in the search space.
 */
static inline int search_lookup_backward(char cc);
static inline int search_lookup_backward(char cc)
{
	int idx = (int)cc;

#ifdef TRIPCRUNCH_DEBUG
	if((idx < 0) || ((unsigned)idx >= SEARCH_MAX_ORD))
	{
		printf("ERROR, search space char out of range");
		exit(1);
	}
#endif

	int ret = search_lookup[idx];
#ifdef TRIPCRUNCH_DEBUG
	if(ret < 0)
	{
		printf("ERROR, invalid search space char: %c", cc);
		exit(1);
	}
#endif
	return ret;
}

/** \brief Append to string.
 *
 * Generates a new string with the given character at the beginning.
 *
 * Deletes previous string.
 *
 * Do not call with an old string that is not initialized.
 *
 * @param old Old string.
 * @param oldlen Old string length.
 * @param chr Character to append.
 * @return New string.
 */
static char* str_prepend(char *old, size_t oldlen, char chr);
static char* str_prepend(char *old, size_t oldlen, char chr)
{
	char *ret = (char*)malloc(sizeof(char) * (oldlen + 2));
	memcpy(ret + 1, old, oldlen + 1);
	free(old);
	ret[0] = chr;
	return ret;
}

////////////////////////////////////////
// Extern //////////////////////////////
////////////////////////////////////////

char* create_safe_cstr_buffer(size_t len)
{
	return (char*)malloc(sizeof(char) * ((len + 2) * 5));
}

int get_search_space_size(void)
{
	return search_space_size;
}

void* memdup(const void *src, size_t len)
{
	void *ret = malloc(len);
	memcpy(ret, src, len);
	return ret;
}

int str_enumcmp(const char *lhs, size_t lhslen, const char *rhs,
		size_t rhslen)
{
	if(lhslen > rhslen)
	{
		return 1;
	}
	else if(lhslen < rhslen)
	{
		return -1;
	}

	char *li = (char*)lhs,
			 *ri = (char*)rhs;
	do {
		int cl = search_lookup_backward(*li),
				cr = search_lookup_backward(*ri);
		if(cl < cr)
		{
			return -1;
		}
		else if(cl > cr)
		{
			return 1;
		}

		++li;
		++ri;
	} while(--lhslen);

	return 0;
}

int str_enumerate_init(const char *sspace)
{
	if(!sspace)
	{
		return -1;
	}

	search_space = sspace;
	search_space_size = (int)strlen(sspace);

	if(search_space_size <= 0)
	{
		return -1;
	}

	search_lookup = (int*)malloc(sizeof(int) * SEARCH_MAX_ORD);

	for(unsigned ii = 0; (ii < SEARCH_MAX_ORD); ++ii)
	{
		if(ii <= 0x20)
		{
			search_lookup[ii] = -1;
		}
		else
		{
			char *ptr = strchr(sspace, (int)ii);
			search_lookup[ii] = ptr ? ((int)(ptr - sspace)) : -1;
		}
#ifdef TRIPCRUNCH_DEBUG
		printf("Search_lookup[%3i] : %c = %i\n", ii, ii, (int)search_lookup[ii]);
#endif
	}

	return 0;
}

void str_enumerate_free(void)
{
	if(search_lookup)
	{
		free(search_lookup);
		search_lookup = NULL;
	}
}

char* str_enumerate_1(char *old, size_t *len)
{
	// Special case, first jump.
	if(!old)
	{
		char *ret = (char*)malloc(sizeof(char) * 2);
		ret[0] = search_lookup_forward(0);
		ret[1] = 0;
		*len = 1;
		return ret;
	}

	size_t oldlen = *len;
	char *iter = old + oldlen - 1;

	while(1)
	{
		int idx = search_lookup_backward(*iter) + 1;

		if(idx < search_space_size)
		{
			*iter = search_lookup_forward(idx);
			return old;
		}
		*iter = search_lookup_forward(0);

		if(iter == old)
		{
			*len = oldlen + 1;
			return str_prepend(old, oldlen, search_lookup_forward(0));
		}
		--iter;
	}
}

char *str_enumerate_fn(char *old, int jump, size_t *len)
{
	size_t oldlen = *len;
	char *iter = old + oldlen - 1;

	while(1)
	{
		int idx = search_lookup_backward(*iter) + jump;
		
		if(idx < search_space_size)
		{
			*iter = search_lookup_forward(idx);
			return old;
		}
		*iter = search_lookup_forward(idx - search_space_size);
		jump = 1;

		if(iter == old)
		{
			*len = oldlen + 1;
			return str_prepend(old, oldlen, search_lookup_forward(0));
		}
		--iter;
	}
}


char* str_enumerate_n(char *old, int jump, size_t *len)
{
	size_t oldlen = *len;

	// Special case, first jump.
	if(!old)
	{
		old = (char*)malloc(sizeof(char) * 2);
		old[0] = search_lookup_forward(jump % search_space_size);
		old[1] = 0;
		oldlen = 1;
		for(jump /= search_space_size;
				(jump);
				jump /= search_space_size)
		{
			char cc = search_lookup_forward(jump % search_space_size);
			old =	str_prepend(old, oldlen, cc);
			++oldlen;
		}
		*len = oldlen;
		return old;
	}

	char *iter = old + oldlen - 1;

	do {
		jump += search_lookup_backward(*iter);
		int rem = jump % search_space_size;

		*iter = search_lookup_forward(rem);
		jump /= search_space_size;

		if(iter == old)
		{
			for(;
					(jump);
					jump /= search_space_size)
			{
				char cc = search_lookup_forward(jump % search_space_size);
				old =	str_prepend(old, oldlen, cc);
				++oldlen;
			}
			*len = oldlen;
			return old;
		}
		--iter;
	} while(jump);

	// No need to update len since it isn't changed.
	return old;
}

char* str_multireplace(char *src, size_t *slen,
		const char_replace_t *replacements,	size_t rnum)
{
	size_t orig_len = *slen,
		 		 new_len = *slen;
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
	*slen = new_len;

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

size_t str_multireplace_fast(char *dst, const char *src, size_t slen,
		const char_replace_t *replacements,	size_t rnum)
{
	size_t ret = slen,
				 kk = 0;

	for(size_t ii = 0; (ii < slen); ++ii)
	{
		char cc = src[ii];

		int replace_done = 0;
		for(size_t jj = 0; (jj < rnum); ++jj)
		{
			const char_replace_t *rep = replacements + jj;

			if(rep->src == cc)
			{
				size_t dstlen = rep->dstlen;
				memcpy(dst + kk, rep->dst, dstlen);
				ret += dstlen - 1;
				kk += dstlen;
				replace_done = 1;
				break;
			}
		}
		if(!replace_done)
		{
			dst[kk++] = cc;
		}
	}

	dst[ret] = 0;
	return ret;
}

char* str_replace(char *src, const char *needle, const char *replacement)
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
	
	char *ret =
		(char*)malloc(sizeof(char) * (len - nlen * nnum + rlen * nnum + 1));

	jj = 0;
	size_t kk = 0;
	for(size_t ii = 0; (ii < len); ++ii)
	{
		char cc = src[ii];

#ifdef TRIPCRUNCH_DEBUG
		printf("cc: %c kk ) %i\n", cc, (int)kk);
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

char* htmlspecialchars(char *src, size_t *slen)
{
	return str_multireplace(src, slen,
			htmlspecialchars_replaces,
			htmlspecialchars_replace_count);
}

size_t htmlspecialchars_fast(char *dst, const char *src, size_t slen)
{
	return str_multireplace_fast(dst, src, slen,
			htmlspecialchars_replaces,
			htmlspecialchars_replace_count);
}

////////////////////////////////////////
// End /////////////////////////////////
////////////////////////////////////////

