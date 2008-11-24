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

/** \brief Get the size of the current search space.
 *
 * @return Current search space size.
 */
extern int get_search_space_size(void);

/** \brief Duplicate a memory segment with a given length.
 *
 * @param src Memory segment to duplicate.
 * @param len Length of the segment.
 */
extern void* memdup(const void *src, size_t len);

/** \brief Compare two strings as per their enumeration order.
 *
 * Note that due to the operation order of the enumeration functions, this
 * actually happens from the end to the beginning.
 *
 * Longer string is always enumerationally greater.
 *
 * @param lhs Left-hand size operand.
 * @param lhslen Length of left-hand-side operand.
 * @param rhs Right-hand size operand.
 * @param rhslen Length of right-hand-side operand.
 * @return -1 if lhs < rhs, 1 if lhs > rhs, 0 if equal.
 */
extern int str_enumcmp(const char *lhs, size_t lhslen, const char *rhs,
		size_t rhslen);

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

/** \brief Enumerate string forward in search space by n permutations.
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
extern char *str_enumerate_n(char *old, int jump, size_t *len);

/** \brief Enumerate string forward in search space by n permutations.
 *
 * Takes as an input a string and jumps n permutations 'forward' in it.
 *
 * Will free() the old string if it's regenerated. The length pointer will
 * also be replaced in this case.
 *
 * This version has restrictions when compared to
 * str_enumerate_1(char*, size_t), and str_enumerate_n(char*, int, size_t).
 * Namely, the old string may not be null and the jump value may not be
 * larger than the search space used.
 *
 * @param old string.
 * @param jump Jump this many characters forward.
 * @param len  Length of the string, potentially replaced.
 * @return New string.
 */
extern char *str_enumerate_fn(char *old, int jump, size_t *len);

/** \brief Enumerate string forward in search space by one permutation.
 *
 * This is analogous to calling str_enumerate_n with a jump value of one,
 * but faster.
 *
 * @param old string.
 * @param len  Length of the string, potentially replaced.
 * @return New string.
 */
extern char *str_enumerate_1(char *old, size_t *len);

/** \brief String multi-replace.
 *
 * Performs a replace of certain singular characters into other strings.
 *
 * Faster than performing several replaces in sequence, but less versatile.
 *
 * Will free the source string if it's modified.
 *
 * @param src Input string.
 * @param slen Input string size pointer.
 * @param replacements Replacement structs.
 * @param rnum Replacement table size.
 * @return Modified or the original string.
 */
extern char* str_multireplace(char *src, size_t *slen,
		const char_replace_t *replacements, size_t rnum);

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
 * @param slen Input string size pointer.
 * @return String with htmlspecialchars done on it.
 */
extern char* htmlspecialchars(char *src, size_t *slen);

#endif
