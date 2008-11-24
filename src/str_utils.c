////////////////////////////////////////
// Define //////////////////////////////
////////////////////////////////////////

/** Maximum ASCII ordinal in search strings. */
#define SEARCH_MAX_ORD 128

////////////////////////////////////////
// Include /////////////////////////////
////////////////////////////////////////

#include "tripcrunch.h"

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
 * Generates a new string with the given character at the end.
 *
 * Deletes previous string.
 *
 * Do not call with an old string that is not initialized.
 *
 * @param old Old string.
 * @param oldlen Old string length.
 * @param chr ASCII number of character to append.
 * @return New string.
 */
static char* str_append(char *old, size_t oldlen, int chr);
static char* str_append(char *old, size_t oldlen, int chr)
{
	char *ret = (char*)realloc(old,  sizeof(char) * (oldlen + 2));
	ret[oldlen]  = (char)chr;
	ret[oldlen + 1] = 0;
	return ret;
}

////////////////////////////////////////
// Extern //////////////////////////////
////////////////////////////////////////

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

	char *li = (char*)lhs + lhslen,
			 *ri = (char*)rhs + rhslen;
	do {
		--li;
		--ri;

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

	int oldlen = (int)(*len);

	for(int ii = 0;; ++ii)
	{
		char cc = old[ii];
		int idx = search_lookup_backward(cc);

		if(idx + 1 < search_space_size)
		{
			old[ii] = search_lookup_forward(idx + 1);
			return old;
		}
		old[ii] = search_lookup_forward(0);

		if(ii + 1 >= oldlen)
		{
			*len = (size_t)(oldlen + 1);
			return str_append(old, (size_t)oldlen, search_lookup_forward(0));
		}
	}
}

char *str_enumerate_fn(char *old, int jump, size_t *len)
{
	int oldlen = (int)(*len);

	for(int ii = 0; ; ++ii)
	{
		int cc = search_lookup_backward(old[ii]);

		cc += jump;
		if(cc < search_space_size)
		{
			old[ii] = search_lookup_forward(cc);
			return old;
		}
		old[ii] = search_lookup_forward(cc - search_space_size);
		jump = 1;

		if(ii + 1 >= oldlen)
		{
			*len = (size_t)(oldlen + 1);
			return str_append(old, (size_t)oldlen, search_lookup_forward(0));
		}
	}
}


char* str_enumerate_n(char *old, int jump, size_t *len)
{
	// Special case, first jump.
	if(!old)
	{
		int rem = jump % search_space_size;
		old = (char*)malloc(sizeof(char) * 2);
		old[0] = search_lookup_forward(rem);
		old[1] = 0;
		*len = 1;
		jump -= rem;
	}

	size_t oldlen = *len;

	// Advance forward in the search space.
	size_t idx = 0;
	while(jump)
	{
		if(idx >= oldlen)
		{
#ifdef TRIPCRUNCH_DEBUG
			if(jump <= 0)
			{
				printf("ERROR, jump should always be > 0 when appending\n");
				exit(1);
			}
#endif
			int rem = (jump - 1) % search_space_size;
			old = str_append(old, oldlen, search_lookup_forward(rem));
			oldlen += 1;
		}
		else
		{
			jump = jump + search_lookup_backward(old[idx]);
			int rem = jump % search_space_size;
			old[idx] = search_lookup_forward(rem);
		}
		jump = jump / search_space_size;
		++idx;
	}

	// Might be changed, might be not.
	*len = oldlen;
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

////////////////////////////////////////
// End /////////////////////////////////
////////////////////////////////////////

