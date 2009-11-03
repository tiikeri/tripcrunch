////////////////////////////////////////
// Include /////////////////////////////
////////////////////////////////////////

#include "hash_2chan.h"
#include "str_utils.h"

#include <stdlib.h>
#include <string.h>

#include "openssl/des.h"

////////////////////////////////////////
// Local ///////////////////////////////
////////////////////////////////////////

/** \brief Generate salt and fix the source string.
 *
 * Note that the source length must NOT be zero.
 *
 * @param salt Destination space for salt.
 * @param buf Destination space for string.
 * @param src Source string.
 * @param slen Length slot of source string.
 * @return New string length.
 */
static size_t generate_salt(char *salt, char *buf, const char *src,
		size_t slen)
{
	// Need a duplicate for htmlspecialchars.
	size_t ret = htmlspecialchars_fast(buf, src, slen);

	// Construct base salt.
	switch(ret)
	{
		case 1:
			salt[0] = 'H';
			salt[1] = '.';
			break;

		case 2:
			salt[0] = buf[1];
			salt[1] = 'H';
			break;

		default:
			salt[0] = buf[1];
			salt[1] = buf[2];
			break;
	}
	salt[2] = 0;

	// Perform replaces.
	for(int ii = 0; (ii < 2); ++ii)
	{
		int cc = (int)(salt[ii]);

		// Not '.' <-> 'z' => '.'
		if((cc < '.') || (cc > 'z'))
		{
			salt[ii] = '.';
		}
		// :;<=>?@ => ABCDEFG
		else if((cc >= ':') && (cc <= '@'))
		{
			salt[ii] = (char)(cc + ('A' - ':'));
		}
		// [\]^_` => abcdef
		else if((cc >= '[') && (cc <= '`'))
		{
			salt[ii] = (char)(cc + ('a' - '['));
		}
	}

	// Return the previously reserved string.
	return ret;
}

/** \brief Implementation of encrypt function.
 *
 * @param src Source chars.
 * @param srclen Length of source in chars.
 * @return Newly allocated encrypted string.
 */
static char* encrypt_2chan(const char *src, size_t srclen)
{
	char salt[3], enc[14],
			 *str = create_safe_cstr_buffer(srclen);

	generate_salt(salt, str, src, srclen);

	DES_fcrypt(str, salt, enc);
	free(str);
	return memdup(enc + 3, 11);
}

/** \brief Implementation of the test function.
 *
 * @param src Source chars.
 * @param srclen Length of source in chars.
 * @param print File to print into.
 * @return Number of tests done.
 */
static int test_2chan(const char *src, size_t srclen, FILE *print)
{
	char salt[3],
			 enc[14],
			 cmp[11],
			 *str = create_safe_cstr_buffer(srclen);

	generate_salt(salt, str, src, srclen);

	DES_fcrypt(str, salt, enc);
	trip_transform(cmp, enc + 3, 10);
	trip_compare(src, enc + 3, cmp, 10, print);
	free(str);
	return 1;
}

////////////////////////////////////////
// Global //////////////////////////////
////////////////////////////////////////

/** Search space for strings. */
const encrypt_info_t encrypt_info_2chan =
{
	"2chan / 4chan",
	"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}",
	10,
	encrypt_2chan,
	test_2chan
};

////////////////////////////////////////
// Extern //////////////////////////////
////////////////////////////////////////

