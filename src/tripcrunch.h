#ifndef TRIPCRUNCH_H_INCLUDE
#define TRIPCRUNCH_H_INCLUDE

/** \file Tripcrunch main header.
 *
 * This file must be included first to all tripcrunch files to declare
 * essential definitions.
 */

#include "config.h"

#define _MULTI_THREADED
#include <pthread.h>

#include <stdio.h>

/** \brief Encryption essentials.
 *
 * A type that contains the essential encryption information.
 */
typedef struct encrypt_info_struct
{
	/** Name of this encryption info. */
	const char *name;

	/** Search space used in this encryption. */
	const char *search_space;

	/** Maximum code length in this encryption. */
	unsigned max_code_length;

	/** \brief Implementation of encrypt function.
	 *
	 * @param src Source chars.
	 * @param srclen Length of source in chars.
	 * @return Newly allocated encrypted string.
	 */
	char* (*encrypt_function)(const char *src, size_t srclen);

	/** \brief Test function.
	 *
	 * @param src Source chars.
	 * @param srclen Length of source in chars.
	 * @param print File to print into.
	 * @return Number of tests done.
	 */
	int (*test_function)(const char *src, size_t srclen, FILE *print);
} encrypt_info_t;

/** \brief Test a tripcode against all searched codes.
 *
 * @param trip Tripcode tested.
 * @param code Encryption result.
 * @param len Length of the result.
 * @param stream Stream to print the match in.
 * @return Number of matches found or zero.
 */
extern int tripcrunch_test(const char *trip, const char *code, size_t len,
		FILE *stream);

#endif
