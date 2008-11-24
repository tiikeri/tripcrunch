////////////////////////////////////////
// Define //////////////////////////////
////////////////////////////////////////

#define _MULTI_THREADED

////////////////////////////////////////
// Include /////////////////////////////
////////////////////////////////////////

#include "tripcrunch.h"

#include "hash_2chan.h"
#include "str_utils.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <pthread.h>

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

/** \brief Structure for current thread execution position.
 */
typedef struct thread_info_struct
{
	/** Current tripcode. */
	tripcode_t trip;

	/** Calculations done. */
	int64_t count;
} thread_info_t;

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

/** Number of threads in use. */
static long int thread_count = 1;

/** Encrypt function to use. */
char* (*encrypt_function)(char*, const char*, size_t) = NULL;

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
			break;

		case SIGINT:
			puts("Interrupt.");
			break;

		default:
			puts("Unknown signal.");
			break;
	}

	// All signals that have not explicitly returned, terminate the execution.
	pthread_mutex_lock(&term_mutex);
	pthread_cond_signal(&term_cond);
	pthread_mutex_unlock(&term_mutex);
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
static char* progress_read(const char *filename);
static char* progress_read(const char *filename)
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
static int64_t get_current_time_int64(void);
static int64_t get_current_time_int64(void)
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
static void progress_save(const char *filename, char *trip);
static void progress_save(const char *filename, char *trip)
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

/** \brief Transform character (case sensitive, no leet).
 *
 * @param src Source character.
 * @return Transformed character.
 */
static char char_transform_identity(char src);
static char char_transform_identity(char src)
{
	return src;
}

/** \brief Transform character (case insensitive, no leet).
 *
 * @param src Source character.
 * @return Transformed character.
 */
static char char_transform_nocase(char src);
static char char_transform_nocase(char src)
{
	return (char)tolower(src);
}

/** \brief Transform character (leet).
 *
 * @param src Source character.
 * @return Transformed character.
 */
static char char_transform_leet(char src);
static char char_transform_leet(char src)
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
static char char_transform_nocase_leet(char src);
static char char_transform_nocase_leet(char src)
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
 * @param triplen Length of the tripcode to examine.
 * @param code Space for testing.
 * @param stream Stream to print the match in.
 * @return Number of matches found or zero.
 */
static int test_trip(char *trip, size_t triplen, char *code, FILE *stream);
static int test_trip(char *trip, size_t triplen, char *code, FILE *stream)
{
	int ret = 0;

	// Perform the encryption.
	encrypt_function(code, trip, triplen);
	
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
 * The arguments passed are a pointer to a thread info struct.
 *
 * @param args Thread information.
 */
static void* threadfunc_tripcrunch(void *args);
static void* threadfunc_tripcrunch(void *args)
{
	// Read the current index and calculate initial string according to them.
	thread_info_t *tinfo = (thread_info_t*)args;
	char *trip = tinfo->trip.trip;
	size_t triplen = tinfo->trip.len;
	int jump = (int)thread_count;
	int64_t count = 0;

	// Reserve the required space for encryption.
	char *enc = (char*)malloc(sizeof(char) * hash_space_required);

	// The threads may not begin execution before they're all created.
	pthread_mutex_lock(&term_mutex);
	pthread_mutex_unlock(&term_mutex);

	for(; (!flag_tripcrunch_terminate); ++count)
	{
		test_trip(trip, triplen, enc, stdout);
		trip = str_enumerate_fn(trip, jump, &triplen);
		//puts(trip);
	}

	// Encryption space not required anymore.
	free(enc);

	// Return thread information.
	tinfo->trip.trip = trip;
	tinfo->trip.len = triplen;
	tinfo->count = count;
	return tinfo;
}

/** \brief Free all reserved global memory.
 */
static void exit_cleanup(void);
static void exit_cleanup(void)
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

	str_enumerate_free();
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
				current_tripcode_len = strlen(optarg);
				current_tripcode = memdup(optarg, current_tripcode_len + 1);
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
			trip->trip = (char*)memdup(opt, len + 1);
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
		str_enumerate_init(search_space_2chan);
		hash_space_required = 11;
	}
	else
	{
		puts("unknown algorithm, aborting");
		return 1;
	}

	// Thread cap based on search space size.
	{
		long int sspacesize = get_search_space_size();
		if(sspacesize < thread_count)
		{
			printf("WARNING: current search space limits to %i threads\n",
					(int)sspacesize);
			thread_count = sspacesize;
		}
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
			tripcode_t *trip = search_tripcodes + ii;
			encrypt_function(enc, trip->trip, trip->len);
			printf("Password %s encrypts to tripcode %s\n", trip->trip, enc);
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
		test_trip(current_tripcode, current_tripcode_len, enc, stdout);
		free(enc);
	}

	pthread_cond_init(&term_cond, NULL);
	pthread_mutex_init(&term_mutex, NULL);
	signal(SIGINT, tripcrunch_signal_handler);
	signal(SIGTERM, tripcrunch_signal_handler);

	// Enter critical section and create all threads.
	pthread_mutex_lock(&term_mutex);
	pthread_t *threads =
		(pthread_t*)malloc(sizeof(pthread_t) * (unsigned)thread_count);
	for(int ii = 0; (ii < thread_count); ++ii)
	{
		// Reserve the thread info for passing to the threads.
		thread_info_t *tinfo = (thread_info_t*)malloc(sizeof(thread_info_t));

		// Give the next tripcode to the string.
		current_tripcode =
			str_enumerate_1(current_tripcode, &current_tripcode_len);
		tinfo->trip.trip = memdup(current_tripcode, current_tripcode_len + 1);
		tinfo->trip.len = current_tripcode_len;
		int err =
			pthread_create(threads + ii, NULL, threadfunc_tripcrunch, tinfo);
		if(err)
		{
			fprintf(stderr, "ERROR %s\n", strerror(err));
			return 1; // Should never happen, okay to not clean up.
		}
	}

	// Wait for exit, then leave critical section.
	int64_t benchmark_start = get_current_time_int64();
	pthread_cond_wait(&term_cond, &term_mutex);
	int64_t benchmark_end = get_current_time_int64();
	flag_tripcrunch_terminate = 1;
	pthread_mutex_unlock(&term_mutex);

	// Process the return information from the threads.
	int64_t benchmark_processed = 0;
	for(int ii = 0; (ii < thread_count); ++ii)
	{
		thread_info_t *tinfo;
		pthread_join(threads[ii], (void**)(&tinfo));

		char *trip = tinfo->trip.trip;
		size_t len = tinfo->trip.len;
		int64_t count = tinfo->count;
		printf("Thread %i: %s (%.0f trips)\n", ii, tinfo->trip.trip,
				(double)(tinfo->count));
		benchmark_processed += count;

		int cmp = str_enumcmp(current_tripcode, current_tripcode_len, trip, len);
		if((cmp > 0) || ((ii <= 0) && count))
		{
			free(current_tripcode);
			current_tripcode = memdup(trip, len + 1);
			current_tripcode_len = len;
		}

		free(trip);
		free(tinfo);
	}
	free(threads);

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

	pthread_cond_destroy(&term_cond);
	pthread_mutex_destroy(&term_mutex);
	return 0;
}

////////////////////////////////////////
// End /////////////////////////////////
////////////////////////////////////////

