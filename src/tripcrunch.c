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

/** Maximum ASCII ordinal in search strings. */
#define SEARCH_MAX_ORD 128

////////////////////////////////////////
// Include /////////////////////////////
////////////////////////////////////////

#include "config.h"
#include "hash_2chan.h"
#include "tripcrunch.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

////////////////////////////////////////
// Global //////////////////////////////
////////////////////////////////////////

/** Used to lock critical sections in hash calculations if necessary. */
pthread_mutex_t hash_mutex;

////////////////////////////////////////
// Struct //////////////////////////////
////////////////////////////////////////

/** \brief Structure for storing tripcodes.
 */
typedef struct tripcode_struct
{
	/** Character string. */
	char *trip;

	/** String length in chars. */
	size_t len;
} tripcode_t;

////////////////////////////////////////
// Local variable //////////////////////
////////////////////////////////////////

/** Usage help string. */
static const char usage[] =
"tripcrunch [options] <desired_tripcodes>\n"
"This program will perform a brute-force search for codes producing the\n"
"desired tripcode for use in online image board (or other places).\n\n"
"Command line options without arguments:\n"
"  -2, --2chan                          Search using the 2chan algorithm.\n"
"                                       (default).\n"
"  -b, --benchmark                      Display rudimentary benchmarks.\n"
"  -c, --enable-case                    Perform tests case sensitive.\n"
"                                       (default: case insensitive).\n"
"  -h, --help                           Print this help.\n"
"  -l, --enable-leet                    Enable leetspeak in comparisons.\n"
"                                       (default: no)\n"
"  -g, --generate                       Generate tripcodes instead of search.\n\n"
"Command line options with arguments:\n"
"  -n <num>, --nthreads=<num>           Number of threads to use.\n"
"                                       (default: 1)\n"
"  -p <file>, --progress-file=<file>    Keep search state in a file.\n"
"                                       (default: no)\n"
"  -s <code>, --start-from=<code>       Start searchies from this tripcode.\n"
"                                       (default: empty)";

/** Used for termination. */
static pthread_cond_t term_cond;

/** Used for termination. */
static pthread_mutex_t term_mutex;

/** Used for benchmark display. */
static int flag_print_benchmarks = 0;

/** Used for termination. */
static int flag_tripcrunch_terminate = 0;

/** Number of tripcodes processed. */
static int64_t benchmark_processed = 0;

/** Benchmark starting time. */
static int64_t benchmark_start;

/** Benchmark starting time. */
static int64_t benchmark_end;

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

/** Table of tripcodes. */
static tripcode_t *search_tripcodes = NULL;

/** Number of searched tripcodes. */
static size_t search_tripcode_count = 0;

/** Progress filename. */
static char *progress_filename = NULL;

/** Encrypt function to use. */
char* (*encrypt_function)(char*, const char*) = NULL;

/** Lowerifier function. */
char (*char_transform)(char) = NULL;

////////////////////////////////////////
// Local function //////////////////////
////////////////////////////////////////

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

/** \brief Read current progress into a trip from a file.
 *
 * Not that the entire file is read for crypto generation, including possible
 * newlines (even ones at the end of file). The user should not modify the
 * progress file by hand.
 *
 * @param filename File to read.
 * @return Tripcode read or NULL.
 */
char* progress_read(const char *filename);
char* progress_read(const char *filename)
{
	FILE *pfile = fopen(filename, "r");
	if(!pfile)
	{
		return NULL;
	}

	size_t len = 0;
	while(1)
	{
		int cc = fgetc(pfile);
		if((cc == '\n') || (cc == EOF) || (cc == 0))
		{
			break;
		}
		++len;
	}

	if(len <= 0)
	{
		fprintf(stderr, "File \"%s\" does not contain a valid tripcode.\n",
				filename);
		fclose(pfile);
		return NULL;
	}

	char *ret = (char*)malloc(sizeof(char) * (len + 1));
	fseek(pfile, 0, SEEK_SET);
	if(fgets(ret, (int)(len + 1), pfile) != ret)
	{
		fprintf(stderr, "Error reading \"%s\": %s\n",
				filename,
				strerror(errno));
		free(ret);
		fclose(pfile);
		return NULL;
	}

	fclose(pfile);
	return ret;
}

/** \brief Get current time as a signed 64-bit integer.
 *
 * @return Current time in microseconds.
 */
int64_t get_current_time_int64(void);
int64_t get_current_time_int64(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (int64_t)(tv.tv_sec) * (int64_t)1000000 + (int64_t)(tv.tv_usec);
}

/** \brief Save progress into file.
 *
 * @param filename File to write.
 * @param trip Tripcode to save.
 */
void progress_save(const char *filename, char *trip);
void progress_save(const char *filename, char *trip)
{
	if(!trip || (strlen(trip) <= 0))
	{
		fputs("Tripcode to be saved is not valid.\n", stderr);
		return;
	}

	FILE *pfile = fopen(filename, "w");
	if(!pfile)
	{
		fprintf(stderr, "Could not save progress into \"%s\": %s\n",
				filename,
				strerror(errno));
		return;
	}

	fprintf(pfile, "%s", current_tripcode);
	fclose(pfile);
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
	if(flag_tripcrunch_terminate)
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

	// The calculation for benchmarks must be in the critical section.
	++benchmark_processed;

	pthread_mutex_unlock(&term_mutex);
	return dst;
}

/** \brief Transform character (case sensitive, no leet).
 *
 * @param src Source character.
 * @return Transformed character.
 */
char char_transform_identity(char src);
char char_transform_identity(char src)
{
	return src;
}

/** \brief Transform character (case insensitive, no leet).
 *
 * @param src Source character.
 * @return Transformed character.
 */
char char_transform_nocase(char src);
char char_transform_nocase(char src)
{
	return (char)tolower(src);
}

/** \brief Transform character (leet).
 *
 * @param src Source character.
 * @return Transformed character.
 */
char char_transform_leet(char src);
char char_transform_leet(char src)
{
	switch(src)
	{
		case '1':
			return 'I';

		case '2':
			return 'Z';

		case '3':
			return 'E';

		case '4':
			return 'A';

		case '5':
			return 'S';

		case '7':
			return 'T';

		case '0':
			return 'O';

		default:
			return src;
	}
}

/** \brief Transform character (case insensitive, leet).
 *
 * @param src Source character.
 * @return Transformed character.
 */
char char_transform_nocase_leet(char src);
char char_transform_nocase_leet(char src)
{
	src = (char)tolower(src);

	switch(src)
	{
		case '1':
			return 'i';

		case '2':
			return 'z';

		case '3':
			return 'e';

		case '4':
			return 'a';

		case '5':
			return 's';

		case '7':
			return 't';

		case '0':
			return 'o';

		default:
			return src;
	}
}

/** \brief Test a tripcode against all searched codes.
 *
 * @param trip Tripcode searched.
 * @param code Space for testing.
 * @param stream Stream to print the match in.
 * @return Number of matches found or zero.
 */
int test_trip(char *trip, char *code, FILE *stream);
int test_trip(char *trip, char *code, FILE *stream)
{
	int ret = 0;

	// Perform the encryption.
	encrypt_function(code, trip);
	
	// Look for matches.
	size_t len = strlen(code);
	for(size_t kk = 0; (kk < search_tripcode_count); ++kk)
	{
		char *desired_tripcode = search_tripcodes[kk].trip;
		size_t desired_tripcode_len = search_tripcodes[kk].len;
		size_t jj = 0;
		for(size_t ii = 0; (ii < len); ++ii)
		{
			if(char_transform(code[ii]) == desired_tripcode[jj])
			{
				++jj;
				if(jj >= desired_tripcode_len)
				{
					fprintf(stream, "Match: %s encrypts to trip %s\n", trip, code);
					break;
				}
			}
			else
			{
				jj = 0;
			}
		}
	}

	return ret;
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
	char *enc = (char*)malloc(sizeof(char) * hash_space_required);

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

		test_trip(trip, enc, stdout);
		//puts(trip);
	}

	// Codes not required anymore.
	free(enc);
	free(trip);

	pthread_mutex_lock(&term_mutex);
	--threads_running;
	pthread_cond_signal(&term_cond);
	pthread_mutex_unlock(&term_mutex);
	return 0;
}

/** \brief Free all reserved global memory.
 */
void exit_cleanup(void);
void exit_cleanup(void)
{
	if(search_tripcodes)
	{
		for(size_t ii = 0; (ii < search_tripcode_count); ++ii)
		{
			free(search_tripcodes[ii].trip);
		}
		free(search_tripcodes);
	}

	if(current_tripcode)
	{
		free(current_tripcode);
	}

	if(progress_filename)
	{
		free(progress_filename);
	}

	if(search_lookup)
	{
		free(search_lookup);
	}
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
	// Option arguments.
	static const struct option opts_long[] =
	{
		{	"2chan", no_argument, NULL, '2' },
		{	"benchmark", no_argument, NULL, 'h' },
		{	"enable-case", no_argument, NULL, 'c' },
		{	"help", no_argument, NULL, 'h' },
		{	"enable-leet", no_argument, NULL, 'l' },
		{	"generate", no_argument, NULL, 'g' },
		{	"nthreads", required_argument, NULL, 'n' },
		{	"progress-file", required_argument, NULL, 'p' },
		{	"start-from", required_argument, NULL, 's' },
		{ NULL, 0, 0, 0 }
	};
	static const char *opts_short = "2cbhlgn:p:s:";

	// Local args.
	int enable_generate = 0,
			enable_leet = 0,
			enable_case = 0;

	while(1)
	{
		int indexptr = 0;
		int opt = getopt_long(argc, argv, opts_short, opts_long, &indexptr);

		if(opt == -1)
		{
			break;
		}

		switch(opt)
		{
			case '2':
				if(encrypt_function)
				{
					fputs("Tripcode algorithm may only be specified once.", stderr);
					exit_cleanup();
					return 1;
				}
				encrypt_function = hash_2chan;
				break;

			case 'b':
				flag_print_benchmarks = 1;
				break;

			case 'c':
				enable_case = 1;
				break;

			case 'h':
				puts(usage);
				exit_cleanup();
				return 0;

			case 'l':
				enable_leet = 1;
				break;

			case 'g':
				enable_generate = 1;
				break;

			case 'n':
				thread_count = strtol(optarg, NULL, 10);
				if((thread_count == LONG_MAX) || (thread_count == LONG_MIN))
				{
					fprintf(stderr, "Invalid thread count: %i\n", (int)thread_count);
					exit_cleanup();
					return 1;
				}
				break;

			case 'p':
				if(progress_filename)
				{
					fputs("Progress file may only be specified once.", stderr);
					exit_cleanup();
					return 1;
				}
				progress_filename = strdup(optarg);
				break;

			case 's':
				if(current_tripcode)
				{
					fputs("Starting code may only be specified once.", stderr);
					exit_cleanup();
					return 1;
				}
				current_tripcode = strdup(optarg);
				current_tripcode_len = strlen(current_tripcode);
				printf("Using starting code: %s\n", current_tripcode);
				break;

			default:
				puts(usage);
				exit_cleanup();
				return 1;
		}
	}

	while(optind < argc)
	{
		char *opt = argv[optind++];
		size_t len = strlen(opt);

		if(len > 0)
		{
			if(!search_tripcodes)
			{
				search_tripcodes = (tripcode_t*)malloc(sizeof(tripcode_t));
				search_tripcode_count = 1;
			}
			else
			{
				search_tripcodes =
					(tripcode_t*)realloc(search_tripcodes,
							sizeof(tripcode_t) * (++search_tripcode_count));
			}
			tripcode_t *trip = search_tripcodes + (search_tripcode_count - 1);
			trip->trip = strdup(opt);
			trip->len = len;
		}
		else
		{
			fputs("Empty string are not valid searching.", stderr);
			return 1;
		}
	}

	// Sanity check for tripcode count.
	if(search_tripcode_count <= 0)
	{
		fprintf(stderr, "Please specify at least one tripcode.\n");
		return 1;
	}

	// If no algo selected yet, pick 2chan.
	if(!encrypt_function)
	{
		encrypt_function = hash_2chan;
	}

	// Print used algo.
	printf("Using algorithm: ");
	if(encrypt_function == hash_2chan)
	{
		puts("2chan / 4chan");
		prepare_search_lookup(search_space_2chan);
		hash_space_required = 11;
	}
	else
	{
		puts("unknown algorithm, aborting");
		return 1;
	}

	// Decide character transform.
	printf("Using character transform: ");
	if(enable_case && enable_leet)
	{
		char_transform = char_transform_leet;
		puts("1337");
	}
	else if(enable_case)
	{
		char_transform = char_transform_identity;
		puts("none");
	}
	else if(enable_leet)
	{
		char_transform = char_transform_nocase_leet;
		puts("case insensitive, 1337");
	}
	else
	{
		char_transform = char_transform_nocase;
		puts("case insensitive");
	}

	// If generate trip requested, do it and exit.
	if(enable_generate)
	{
		char *enc = (char*)malloc(sizeof(char) * hash_space_required);

		for(size_t ii = 0; (ii < search_tripcode_count); ++ii)
		{
			char *trip = search_tripcodes[ii].trip;

			encrypt_function(enc, trip);
			printf("Password %s encrypts to tripcode %s\n", trip, enc);
		}

		free(enc);
		exit_cleanup();
		return 0;
	}

	// Sanity check for tripcode lengths.
	for(size_t ii = 0; (ii < search_tripcode_count); ++ii)
	{
		tripcode_t *trip = search_tripcodes + ii;
		if(trip->len >= hash_space_required)
		{
			fprintf(stderr,
					"Code %s is %u chars long, too much for current algo (%u).\n",
					trip->trip,
					(unsigned)(trip->len),
					(unsigned)(hash_space_required - 1));
			exit_cleanup();
			return 1;
		}

		// Perform case transform in precalc!
		for(size_t jj = 0; (jj < trip->len); ++jj)
		{
			trip->trip[jj] = char_transform(trip->trip[jj]);
		}
	}

	// Only read current tripcode if it's not yet specified.
	if(progress_filename)
	{
		char *prog = progress_read(progress_filename);

		if(prog)
		{
			if(current_tripcode)
			{
				fprintf(stderr, "Not overwriting starting code from file: %s\n",
						prog);
				free(prog);
			}
			else
			{
				printf("Using starting code from file: %s\n", prog);
				current_tripcode = prog;
				current_tripcode_len = strlen(prog);
			}
		}
	}

	// Try the initial tripcode if it has been specified.
	if(current_tripcode)
	{
		char *enc = (char*)malloc(sizeof(char) * hash_space_required);
		test_trip(current_tripcode, enc, stdout);
		free(enc);
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
			fprintf(stderr, "ERROR %s\n", strerror(err));
			return 1;
		}
	}

	benchmark_start = get_current_time_int64();
	pthread_cond_wait(&term_cond, &term_mutex);
	benchmark_end = get_current_time_int64();

	flag_tripcrunch_terminate = 1;
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

	// Must save progress beforew other cleanup.
	if(progress_filename)
	{
		progress_save(progress_filename, current_tripcode);
	}

	// Current tripcode is not necessarily initialized.
	if(current_tripcode)
	{
		printf("Last search: %s\n", current_tripcode);
	}
	exit_cleanup();

	// Only print benchmarks if requested.
	if(flag_print_benchmarks)
	{
		double trips = (double)benchmark_processed,
		 			 secs = (double)(benchmark_end - benchmark_start) / 1000000.0;

		printf("Benchmark: %.0f trips / %.2f secs -> %.2f trips/sec\n",
				trips,
				secs,
				trips / secs);
	}

	return 0;
}

////////////////////////////////////////
// End /////////////////////////////////
////////////////////////////////////////

