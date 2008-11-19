////////////////////////////////////////
// Information /////////////////////////
////////////////////////////////////////

/*
 * Copyright (c), Anonymous of Suomus, 2008.
 *
 * BSD Licence.
 */

////////////////////////////////////////
// Define //////////////////////////////
////////////////////////////////////////

/** Maximum length to search. */
#define TRIPMAXLEN 8

/** Maximum ASCII ordinal in search strings. */
#define SEARCH_MAX_ORD 128

////////////////////////////////////////
// Include /////////////////////////////
////////////////////////////////////////

#include "config.h"
#include "hash_2chan.h"
#include "tripcrunch.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

////////////////////////////////////////
// Global //////////////////////////////
////////////////////////////////////////

/** Used to lock critical sections in hash calculations if necessary. */
pthread_mutex_t hash_mutex;

////////////////////////////////////////
// Local ///////////////////////////////
////////////////////////////////////////

/** Usage help string. */
static const char usage[] =
"tripcrunch [options] <desired_tripcode>\n"
"This program will perform a brute-force search for codes producing the\n"
"desired tripcode for use in online image board (or other places).\n\n"
"Command line options without arguments:\n"
"  -2, --2chan                     Search using the 2chan algorithm (default).\n"
"  -h, --help                      Print this help.\n"
"  -l, --enable-leet               Enable leetspeak in comparisons.\n\n"
"Command line options with arguments:\n"
"  -g <pass>, --generate=<pass>    Generate tripcode from password and exit.\n"
"  -n <num>, --nthreads=<num>      Number of threads to use (default: 1).";

/** Used for termination. */
static pthread_cond_t term_cond;

/** Used for termination. */
static pthread_mutex_t term_mutex;

/** Used for termination. */
static int tripcrunch_terminate = 0;

/** Leet flag. */
static int enable_leet = 0;

/** Thread count. */
static long int thread_count = 1;

/** Current thread count. */
static int threads_running = 0;

/** Lookup table for transformations. */
static int *search_lookup;

/** Search space to use. */
static const char *search_space;

/** Search space size. */
static int search_space_size = 0;

/** Current tripcode. */
static char *current_tripcode = NULL;

/** Current tripcode length. */
static size_t current_tripcode_len = 0;

/** Space required for hash space, dependant on the password method. */
static size_t hash_space_required;

/** Desired tripcode to compare into. */
static char *desired_tripcode = NULL;

/** Desired tripcode length. */
size_t desired_tripcode_len = 0;

/** Encrypt function to use. */
char* (*encrypt_function)(char *dst, const char*) = NULL;

/** \brief Signal handler.
 *
 * @param signum Signal acquired.
 */
static void tripcrunch_signal_handler(int signum);
static void tripcrunch_signal_handler(int signum)
{
	switch(signum)
	{
		case SIGTERM:
			puts("Terminated.");
			pthread_cond_signal(&term_cond);
			break;

		case SIGINT:
			puts("Interrupt.");
			pthread_cond_signal(&term_cond);
			break;

		default:
			puts("Unknown signal.");
			pthread_cond_signal(&term_cond);
			break;
	}
}

/** \brief Append to string.
 *
 * Generates a new string with the given character at the end.
 *
 * Deletes previous string if non-null.
 *
 * @param old Old string.
 * @param chr ASCII number of character to append.
 * @return New string.
 */
char* str_append(char *old, int chr);
char* str_append(char *old, int chr)
{
	if(!old)
	{
		char *ret = (char*)malloc(sizeof(char) * 2);
		ret[0] = (char)chr;
		ret[1] = 0;
		return ret;
	}

	size_t len = strlen(old);
	char *ret = (char*)malloc((len + 2) * sizeof(char));
	memcpy(ret, old, len);
	ret[len]  = (char)chr;
	ret[len + 1] = 0;
	free(old);
	return ret;
}

/** \brief Prepare search lookup table.
 *
 * @param space Search space to use.
 */
void prepare_search_lookup(const char *space);
void prepare_search_lookup(const char *space)
{
	search_space = space;
	search_space_size = (int)strlen(space);
	search_lookup = (int*)malloc(sizeof(int) * SEARCH_MAX_ORD);

	for(unsigned ii = 0; (ii < SEARCH_MAX_ORD); ++ii)
	{
		if(ii <= 0x20)
		{
			search_lookup[ii] = -1;
		}
		else
		{
			char *ptr = strchr(space, (int)ii);
			search_lookup[ii] = ptr ? ((int)(ptr - space)) : -1;
		}
#ifdef TRIPCRUNCH_DEBUG
		printf("Search_lookup[%3i] : %c = %i\n", ii, ii, (int)search_lookup[ii]);
#endif
	}
}

/** \brief Get character at a given index in the search space.
 *
 * @param idx Index to fetch from.
 * @return Character found.
 */
char get_char_at_idx(int idx);
char get_char_at_idx(int idx)
{
#ifdef TRIPCRUNCH_DEBUG
	if((idx < 0) || ((unsigned)idx >= search_space_size))
	{
		printf("ERROR, search space index out of range");
		exit(1);
	}
#endif

	return search_space[idx];
}

/** \brief Get the index of a character.
 *
 * @param cc Character.
 * @return Index of that character in the search space.
 */
int get_idx_of_char(char cc);
int get_idx_of_char(char cc)
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

/** \brief Enumerate string.
 *
 * Takes as an input a string and jumps n permutations 'forward' in it.
 *
 * Will free() the old string if it's regenerated. The length pointer will
 * also be replaced in this case.
 *
 * @param old string.
 * @param jump Jump this many characters forward.
 * @param len  Length of the string, potentially replaced.
 * @return New string.
 */
char *enumerate_string(char *old, int jump, size_t *len);
char *enumerate_string(char *old, int jump, size_t *len)
{
	// Special case, first jump.
	if(!old)
	{
		int rem = jump % search_space_size;
		old = str_append(NULL, get_char_at_idx(rem));
		jump -= rem;
		*len = 1; // Initially.
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
			old = str_append(old, get_char_at_idx(rem));
			oldlen += 1;
		}
		else
		{
			jump = jump + get_idx_of_char(old[idx]);
			int rem = jump % search_space_size;
			old[idx] = get_char_at_idx(rem);
		}
		jump = jump / search_space_size;
		++idx;
	}

	// Might be changed, might be not.
	*len = oldlen;
	return old;
}

/** \brief Get a new string in a critical section.
 *
 * This function is used to get a new string, generated from the current one.
 *
 * If dst is too small for the current tripcode, it will be freed and
 * replaced. Note thet dst MUST be reserved when calling this, even if it's
 * length specified in len is 0.
 *
 * If this function returns NULL, the caller should stop searching.
 *
 * @param dst Write the current tripcode here.
 * @param len Length of dst in chars not counting terminating zero.
 * @return NULL if quitting, otherwise the new tripcode.
 */
char* get_next_string(char *dst, size_t *len);
char* get_next_string(char *dst, size_t *len)
{
	if(tripcrunch_terminate)
	{
		return NULL;
	}
	pthread_mutex_lock(&term_mutex);

	current_tripcode =
		enumerate_string(current_tripcode, 1, &current_tripcode_len);
	if((*len) != current_tripcode_len)
	{
		*len = current_tripcode_len;
		free(dst);
		dst = (char*)malloc(sizeof(char) * (current_tripcode_len + 1));
	}
	memcpy(dst, current_tripcode, sizeof(char) * (current_tripcode_len + 1));

	pthread_mutex_unlock(&term_mutex);
	return dst;
}

/** \brief Test for character equals.
 *
 * @param lhs Left-hand-side comparison.
 * @param rhs Right-hand-side comparison.
 * @return 1 if sufficently equal, 0 if not.
 */
int char_equals(char lhs, char rhs);
int char_equals(char lhs, char rhs)
{
	int llhs = tolower(lhs),
			lrhs = tolower(rhs);
	if(llhs == lrhs)
	{
		return 1;
	}

	if(enable_leet &&
			(((llhs == '5') && (lrhs == 's')) ||
			 ((llhs == 's') && (lrhs == '5')) ||
			 ((llhs == '4') && (lrhs == 'a')) ||
			 ((llhs == 'a') && (lrhs == '4')) ||
			 ((llhs == '0') && (lrhs == 'o')) ||
			 ((llhs == 'o') && (lrhs == '0')) ||
			 ((llhs == '7') && (lrhs == 'T')) ||
			 ((llhs == 'T') && (lrhs == '7')) ||
			 ((llhs == '1') && (lrhs == 'i')) ||
			 ((llhs == 'i') && (lrhs == '1')) ||
			 ((llhs == '3') && (lrhs == 'e')) ||
			 ((llhs == 'e') && (lrhs == '3'))))
	{
		return 1;
	}
	
	return 0;
}

/** \brief Trip cruncher thread function.
 *
 * No arguments currently.
 *
 * @param args_not_in_use Not used.
 */
void* threadfunc_tripcrunch(void*);
void* threadfunc_tripcrunch(void *args_not_in_use)
{
	pthread_mutex_lock(&term_mutex);
	++threads_running;
	pthread_mutex_unlock(&term_mutex);

	// Reserve the required space for encryption.
	char *code = (char*)malloc(sizeof(char) * hash_space_required);

	// Faster to skip one check in inner loop.
	char *trip = (char*)malloc(sizeof(char) * 1);
	size_t triplen = 0;

	while(1)
	{
		char *newtrip = get_next_string(trip, &triplen);
		if(!newtrip)
		{
			break;
		}
		trip = newtrip;
		encrypt_function(code, trip);

		size_t len = strlen(code);
		unsigned jj = 0;
		for(unsigned ii = 0; (ii < len); ++ii)
		{
			if(char_equals(code[ii], desired_tripcode[jj]))
			{
				++jj;
				if(jj >= desired_tripcode_len)
				{
					printf("Match: %s encrypts to trip %s\n", trip, code);
					break;
				}
			}
			else
			{
				jj = 0;
			}
		}
		//puts(trip);
	}

	// Code not required anymore.
	free(code);
	free(trip);

	pthread_mutex_lock(&term_mutex);
	--threads_running;
	pthread_cond_signal(&term_cond);
	pthread_mutex_unlock(&term_mutex);
	return 0;
}

////////////////////////////////////////
// Main ////////////////////////////////
////////////////////////////////////////

/** \brief Main function.
 *
 * @param argc Number of arguments from the system.
 * @param argv Arguments from the system.
 * @return Program exit code.
 */
int main(int argc, char **argv)
{
	// Local args.
	char *gentrip = NULL;

	// Parse command line arguments.
	for(int ii = 1; (ii < argc); ++ii)
	{
		char *currarg = argv[ii];
		char *nextarg = NULL;
		if(ii < argc - 1)
		{
			nextarg = argv[ii + 1];
		}

		if(!strcmp(currarg, "-2") || !strcmp(currarg, "--2chan"))
		{
			if(encrypt_function)
			{
				printf("Tripcode algorithm can only be selected once.\n");
				return 1;
			}
			encrypt_function = hash_2chan;
		}
		else if(!strcmp(currarg, "-h") || !strcmp(currarg, "--help"))
		{
			puts(usage);
			return 0;
		}
		else if(!strcmp(currarg, "-l") || !strcmp(currarg, "--enable-leet"))
		{
			enable_leet = 1;
		}
		else if(!strcmp(currarg, "-g"))
		{
			gentrip = nextarg;
			++ii;
			if(!gentrip)
			{
				printf("ERROR, give a valid password to -g\n");
				return 1;
			}
		}
		else if(!strncmp(currarg, "--generate=", 11))
		{
			gentrip = currarg + 11;
			if(strlen(gentrip) <= 0)
			{
				printf("ERROR, give a valid password to --generate=\n");
				return 1;
			}
		}
		else if(!strcmp(currarg, "-n") || !strncmp(currarg, "--nthreads=", 11))
		{
			if(!strcmp(currarg, "-n"))
			{
				thread_count = strtol(nextarg, NULL, 10);
				++ii;
			}
			else
			{
				thread_count = strtol(currarg + 11, NULL, 10);
			}
			if((thread_count == LONG_MAX) || (thread_count == LONG_MIN))
			{
				printf("Invalid thread count: %i\n", (int)thread_count);
				return 1;
			}
		}
		else if(!strcmp(currarg, "-s"))
		{
			current_tripcode = nextarg;
			++ii;
			if(!current_tripcode)
			{
				printf("ERROR, give a valid password to -s\n");
				return 1;
			}
		}
		else if(!strncmp(currarg, "--start-from=", 13))
		{
			current_tripcode = currarg + 13;
			if(strlen(current_tripcode) <= 0)
			{
				printf("ERROR, give a valid password to --start-from=\n");
				return 1;
			}
		}
		else
		{
			if(desired_tripcode)
			{
				printf("Tripcode to search can be only specified once.\n");
				return 1;
			}
			desired_tripcode = currarg;
			desired_tripcode_len = strlen(desired_tripcode);
		}
	}

	// Starting tripcode duplication if specified.
	if(current_tripcode)
	{
		current_tripcode = strdup(current_tripcode);
		current_tripcode_len = strlen(current_tripcode);
	}

	// If no algo selected yet, pick 2chan.
	if(!encrypt_function)
	{
		encrypt_function = hash_2chan;
	}

	// Print used algo.
	printf("Using: ");
	if(encrypt_function == hash_2chan)
	{
		puts("2chan algorithm");
		prepare_search_lookup(search_space_2chan);
		hash_space_required = 11;
	}
	else
	{
		puts("unknown algorithm, aborting");
		return 1;
	}

	// If generate trip requested, do it and exit.
	if(gentrip)
	{
		char *enc = (char*)malloc(sizeof(char) * hash_space_required);
		encrypt_function(enc, gentrip);
		printf("Password %s encrypts to tripcode %s\n", gentrip, enc);
		free(enc);
		return 0;
	}

	// Sanity check for tripcode.
	if(!desired_tripcode)
	{
		printf("Please specify a tripcode to search.\n");
		return 1;
	}
	if(strlen(desired_tripcode) > TRIPMAXLEN)
	{
		printf("Desired tripcode may only be up to %u characters long.\n",
				TRIPMAXLEN);
		return 1;
	}

	signal(SIGINT, tripcrunch_signal_handler);
	signal(SIGTERM, tripcrunch_signal_handler);
	pthread_cond_init(&term_cond, NULL);
	pthread_mutex_init(&hash_mutex, NULL);
	pthread_mutex_init(&term_mutex, NULL);

	pthread_mutex_lock(&term_mutex);

	pthread_t *threads =
		(pthread_t*)malloc(sizeof(pthread_t) * (unsigned)thread_count);
	for(int ii = 0; (ii < thread_count); ++ii)
	{
		int err =
			pthread_create(threads + ii,
					NULL,
					threadfunc_tripcrunch,
					NULL);
		if(err)
		{
			printf("ERROR %s\n", strerror(err));
			return 1;
		}
	}

	pthread_cond_wait(&term_cond, &term_mutex);

	tripcrunch_terminate = 1;
	while(threads_running > 0)
	{
		pthread_cond_wait(&term_cond, &term_mutex);
	}
	
	pthread_mutex_unlock(&term_mutex);

	for(int ii = 0; (ii < thread_count); ++ii)
	{
		pthread_join(threads[ii], NULL);
	}
	free(threads);

	pthread_cond_destroy(&term_cond);
	pthread_mutex_destroy(&hash_mutex);
	pthread_mutex_destroy(&term_mutex);
	free(search_lookup);

	// Current tripcode is not necessarily initialized.
	if(current_tripcode)
	{
		printf("Last search: %s\n", current_tripcode);
		free(current_tripcode);
	}

	return 0;
}

////////////////////////////////////////
// End /////////////////////////////////
////////////////////////////////////////

