#ifndef STR_UTILS_H_INCLUDE
#define STR_UTILS_H_INCLUDE

#include <stdio.h>

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

/** \brief Initialize string enumeration.
 *
 * Prepare the string enumeration for str_enumerate calls.
 *
 * @param sspace Search space to use.
 * @return Zero on success, nonzero on failure.
 */
extern int str_enumerate_init(const char *sspace);

/** \brief Free search space if it was reserved.
 */
extern void str_enumerate_free(void);

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
char *str_enumerate_n(char *old, int jump, size_t *len);

/** \brief String multi-replace.
 *
 * Performs a replace of certain singular characters into other strings.
 *
 * Faster than performing several replaces in sequence, but less versatile.
 *
 * Will free the source string if it's modified.
 *
 * @param src Input string.
 * @param replacements Replacement structs.
 * @param rnum Replacement table size.
 * @return Modified or the original string.
 */
extern char* str_multireplace(char *src, const char_replace_t *replacements,
		size_t rnum);

/** \brief Perform a string replace.
 *
 * Will search the string for instances of a certain string, will return the
 * same string if not found or a modified string if found.
 *
 * Needle and replacement are not checked for sanity.
 *
 * Will free the source string if it's modified.
 *
 * @param src Input string.
 * @param needle Needle to search.
 * @param replacement Replacement to use.
 * @return Modified or the original string.
 */
extern char* str_replace(char *src, const char *needle,
		const char *replacement);

/** \brief Perform a htmlspecialchars replace on a source string.
 *
 * Will free the source string if it's modified.
 *
 * @param src Source string.
 * @return String with htmlspecialchars done on it.
 */
extern char* htmlspecialchars(char *src);

#endif
