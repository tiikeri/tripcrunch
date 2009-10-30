////////////////////////////////////////
// Define //////////////////////////////
////////////////////////////////////////

#define _MULTI_THREADED

////////////////////////////////////////
// Include /////////////////////////////
////////////////////////////////////////

#include "hash_2chan.h"
#include "str_utils.h"

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
"  -g, --generate                       Generate tripcodes instead of search.\n"
"  -w, --enable-wildcard                Allow wildcard ? in tests. Disables\n"
"                                       searching for an actual ? character.\n\n"
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

/** Table of tripcodes. */
static tripcode_t *search_tripcodes = NULL;

/** Number of searched tripcodes. */
static size_t search_tripcode_count = 0;

/** Progress filename. */
static char *progress_filename = NULL;

/** Number of threads in use. */
static long int thread_count = 1;

/** Encryption info used. */
static encrypt_info_t einfo = { NULL, NULL, 0, NULL, NULL };

/** Character transform function. */
static char (*char_transform_func)(char) = NULL;

/** String search function. */
static int (*strstr_func)(const char*, size_t, const char*, size_t);

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
	flag_tripcrunch_terminate = 1;
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

	// The threads may not begin execution before they're all created.
	pthread_mutex_lock(&term_mutex);
	pthread_mutex_unlock(&term_mutex);

	while(!flag_tripcrunch_terminate)
	{
		count += einfo.test_function(trip, triplen, stdout);
		trip = str_enumerate_fn(trip, jump, &triplen);
		//puts(trip);
	}

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
// Global function /////////////////////
////////////////////////////////////////

int trip_compare(const char *trip, const char *result, const char *compare,
		size_t len, FILE *stream)
{
	for(size_t jj = 0; (jj < search_tripcode_count); ++jj)
	{
		tripcode_t *trip_struct = search_tripcodes + jj;
		if(strstr_func(trip_struct->trip, trip_struct->len, compare, len) >= 0)
		{
			fprintf(stream, "Match: %s encrypts to trip %s\n", trip, result);
			return 1;
		}
	}

	return 0;
}

void trip_transform(char *dst, const char *src, size_t len)
{
	char *srciter = (char*)src;
	do {
		*dst = char_transform_func(*srciter);
		++dst;
		++srciter;
	} while(--len);
	*dst = 0;
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
		{	"wildcard", no_argument, NULL, 'w' },
		{ NULL, 0, 0, 0 }
	};
	static const char *opts_short = "2cbhlgn:p:s:w";

	// Local args.
	uint8_t enable_generate = 0,
					enable_leet = 0,
					enable_case = 0,
					enable_wildcard = 0;
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
				if(einfo.name)
				{
					fputs("Tripcode algorithm may only be specified once.", stderr);
					exit_cleanup();
					return 1;
				}
				einfo = encrypt_info_2chan;
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

			case 'w':
				enable_wildcard = 1;
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
	if(!einfo.name)
	{
		einfo = encrypt_info_2chan;
	}
	printf("Using algorithm: %s\n", einfo.name);
	str_enumerate_init(einfo.search_space);

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
	if(!enable_generate)
	{
		char_transform_func = char_transform_identity;
		strstr_func = strstr_normal;
		printf("Using character transform: ");
		if(enable_case && !enable_leet && !enable_wildcard)
		{
			puts("none");
		}
		else
		{
			unsigned flag_line = 0;
			if(enable_case)
			{
				if(enable_leet)
				{
					flag_line = fprint_list_spacing(stdout, flag_line);
					printf("1337");
					char_transform_func = char_transform_leet;
				}
			}
			else
			{
				flag_line = fprint_list_spacing(stdout, flag_line);
				printf("case_insensitive");
				char_transform_func = char_transform_nocase;
				if(enable_leet)
				{
					flag_line = fprint_list_spacing(stdout, flag_line);
					printf("1337");
					char_transform_func = char_transform_nocase_leet;
				}
			}
			if(enable_wildcard)
			{
				flag_line = fprint_list_spacing(stdout, flag_line);
				printf("wildcard");
				strstr_func = strstr_wildcard;
			}
			puts("");
		}
	}

	// If generate trip requested, do it and exit.
	if(enable_generate)
	{
		for(size_t ii = 0; (ii < search_tripcode_count); ++ii)
		{
			tripcode_t *trip = search_tripcodes + ii;
			char *enc = einfo.encrypt_function(trip->trip, trip->len);
			printf("Password %s encrypts to tripcode %s\n",
					trip->trip,
					enc);
			free(enc);
		}

		exit_cleanup();
		return 0;
	}

	// Sanity check for tripcode lengths.
	for(size_t ii = 0; (ii < search_tripcode_count); ++ii)
	{
		tripcode_t *trip = search_tripcodes + ii;
		if(trip->len > einfo.max_code_length)
		{
			fprintf(stderr,
					"Code %s is %u chars long, too much for current algo (%u).\n",
					trip->trip,
					(unsigned)(trip->len),
					(unsigned)(einfo.max_code_length - 1));
			exit_cleanup();
			return 1;
		}

		// Perform case transform in precalc!
		for(size_t jj = 0; (jj < trip->len); ++jj)
		{
			trip->trip[jj] = char_transform_func(trip->trip[jj]);
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
	int64_t benchmark_processed = 0;
	if(current_tripcode)
	{
		benchmark_processed +=
			einfo.test_function(current_tripcode, current_tripcode_len, stdout);
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
	pthread_mutex_unlock(&term_mutex);

	// Immediately start joining the threads.
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

	// All threads have been joined, time to end the benchmark and free the
	// thread table.
	int64_t benchmark_end = get_current_time_int64();
	free(threads);

	// Must save progress before other cleanup.
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

