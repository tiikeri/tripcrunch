#ifndef HASH_2CHAN_H_INCLUDE
#define HASH_2CHAN_H_INCLUDE

/** Search space for strings. */
extern const char *search_space_2chan;

/** \brief Encrypt a tripcode using the 2chan method.
 *
 * @param dst Destination chars.
 * @param src Source chars.
 * @return Zero on success, nonzero on failure.
 */
extern char* hash_2chan(const char *src);

#endif
