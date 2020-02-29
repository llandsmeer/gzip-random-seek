/*
 * tinflate - tiny inflate
 *
 * Copyright (c) 2003-2019 Joergen Ibsen
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented; you must
 *      not claim that you wrote the original software. If you use this
 *      software in a product, an acknowledgment in the product
 *      documentation would be appreciated but is not required.
 *
 *   2. Altered source versions must be plainly marked as such, and must
 *      not be misrepresented as being the original software.
 *
 *   3. This notice may not be removed or altered from any source
 *      distribution.
 */

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <execinfo.h>
#include <ctype.h>

#define TINF_VER_STRING "1.3.0-streaming"
#define OUTPUT_BUFFER_SIZE (32*1024) //32 kb

#define static

#if defined(UINT_MAX) && (UINT_MAX) < 0xFFFFFFFFUL
#  error "tinf requires unsigned int to be at least 32-bit"
#endif

// TODO: check asserts?

/* -- Internal data structures -- */

typedef enum {
    TINF_OK         = 0,  /**< Success */
    TINF_DATA_ERROR = -3, /**< Input error */
    TINF_BUF_ERROR  = -5, /**< Not enough room for output */
    TINF_IO_ERROR   = -7, /**< File error or eof reached preliminary */
    TINF_NON_PRINT  = -9, /**< Trying to emit non-printable character */
    TINF_STOP       =-12  /**< Stop due to user condition */
} tinf_error_code;

struct tinf_tree {
    unsigned short counts[16]; /* Number of codes with a given length */
    unsigned short symbols[288]; /* Symbols sorted by code */
    int max_sym;
};

struct tinf_data {
    FILE *fsource;
    unsigned int tag;
    int bitcount;
    int overflow;

    struct {
        unsigned char sym;
        unsigned char is_known;
    } output_buffer[OUTPUT_BUFFER_SIZE];
    int output_buffer_ptr;

    struct tinf_tree ltree; /* Literal/length tree */
    struct tinf_tree dtree; /* Distance tree */
};

/* -- Utility functions -- */

void data_error(int line) {
    return;
    printf("TINF_DATA_ERROR at line %d\n", line);

    void *array[10];
    size_t size;

    size = backtrace(array, 10);

    backtrace_symbols_fd(array, size, 2);}


static unsigned int read_le16(const unsigned char *p)
{
    return ((unsigned int) p[0])
         | ((unsigned int) p[1] << 8);
}

/* Build fixed Huffman trees */
static void tinf_build_fixed_trees(struct tinf_tree *lt, struct tinf_tree *dt)
{
    int i;

    /* Build fixed literal/length tree */
    for (i = 0; i < 16; ++i) {
        lt->counts[i] = 0;
    }

    lt->counts[7] = 24;
    lt->counts[8] = 152;
    lt->counts[9] = 112;

    for (i = 0; i < 24; ++i) {
        lt->symbols[i] = 256 + i;
    }
    for (i = 0; i < 144; ++i) {
        lt->symbols[24 + i] = i;
    }
    for (i = 0; i < 8; ++i) {
        lt->symbols[24 + 144 + i] = 280 + i;
    }
    for (i = 0; i < 112; ++i) {
        lt->symbols[24 + 144 + 8 + i] = 144 + i;
    }

    lt->max_sym = 285;

    /* Build fixed distance tree */
    for (i = 0; i < 16; ++i) {
        dt->counts[i] = 0;
    }

    dt->counts[5] = 32;

    for (i = 0; i < 32; ++i) {
        dt->symbols[i] = i;
    }

    dt->max_sym = 29;
}

/* Given an array of code lengths, build a tree */
static int tinf_build_tree(struct tinf_tree *t, const unsigned char *lengths,
                           unsigned int num)
{
    unsigned short offs[16];
    unsigned int i, num_codes, available;

    assert(num <= 288);

    for (i = 0; i < 16; ++i) {
        t->counts[i] = 0;
    }

    t->max_sym = -1;

    /* Count number of codes for each non-zero length */
    for (i = 0; i < num; ++i) {
        assert(lengths[i] <= 15);

        if (lengths[i]) {
            t->max_sym = i;
            t->counts[lengths[i]]++;
        }
    }

    /* Compute offset table for distribution sort */
    for (available = 1, num_codes = 0, i = 0; i < 16; ++i) {
        unsigned int used = t->counts[i];

        /* Check length contains no more codes than available */
        if (used > available) {
            data_error(__LINE__);
            return TINF_DATA_ERROR;
        }
        available = 2 * (available - used);

        offs[i] = num_codes;
        num_codes += used;
    }

    /*
     * Check all codes were used, or for the special case of only one
     * code that it has length 1
     */
    if ((num_codes > 1 && available > 0)
     || (num_codes == 1 && t->counts[1] != 1)) {
        data_error(__LINE__);
        return TINF_DATA_ERROR;
    }

    /* Fill in symbols sorted by code */
    for (i = 0; i < num; ++i) {
        if (lengths[i]) {
            t->symbols[offs[lengths[i]]++] = i;
        }
    }

    /*
     * For the special case of only one code (which will be 0) add a
     * code 1 which results in a symbol that is too large
     */
    if (num_codes == 1) {
        t->counts[1] = 2;
        t->symbols[1] = t->max_sym + 1;
    }

    return TINF_OK;
}

/* -- Decode functions -- */

static void tinf_refill(struct tinf_data *d, int num)
{
    assert(num >= 0 && num <= 32);

    /* Read bytes until at least num bits available */
    while (d->bitcount < num) {
        unsigned char buf;
        if (!feof(d->fsource)) {
            size_t res = fread(&buf, 1, 1, d->fsource);
            if (res != 1) {
                exit(1); // ERROR read error
            }
            d->tag |= (unsigned int) buf << d->bitcount;
        }
        else {
            d->overflow = 1;
        }
        d->bitcount += 8;
    }

    assert(d->bitcount <= 32);
}

static unsigned int tinf_getbits_no_refill(struct tinf_data *d, int num)
{
    unsigned int bits;

    assert(num >= 0 && num <= d->bitcount);

    /* Get bits from tag */
    bits = d->tag & ((1UL << num) - 1);

    /* Remove bits from tag */
    d->tag >>= num;
    d->bitcount -= num;

    return bits;
}

/* Get num bits from source stream */
static unsigned int tinf_getbits(struct tinf_data *d, int num)
{
    tinf_refill(d, num);
    return tinf_getbits_no_refill(d, num);
}

/* Read a num bit value from stream and add base */
static unsigned int tinf_getbits_base(struct tinf_data *d, int num, int base)
{
    return base + (num ? tinf_getbits(d, num) : 0);
}

/* Given a data stream and a tree, decode a symbol */
static int tinf_decode_symbol(struct tinf_data *d, const struct tinf_tree *t)
{
    int base = 0, offs = 0;
    int len;

    /*
     * Get more bits while code index is above number of codes
     *
     * Rather than the actual code, we are computing the position of the
     * code in the sorted order of codes, which is the index of the
     * corresponding symbol.
     *
     * Conceptually, for each code length (level in the tree), there are
     * counts[len] leaves on the left and internal nodes on the right.
     * The index we have decoded so far is base + offs, and if that
     * falls within the leaves we are done. Otherwise we adjust the range
     * of offs and add one more bit to it.
     */
    for (len = 1; ; ++len) {
        offs = 2 * offs + tinf_getbits(d, 1);

        assert(len <= 15);

        if (offs < t->counts[len]) {
            break;
        }

        base += t->counts[len];
        offs -= t->counts[len];
    }

    assert(base + offs >= 0 && base + offs < 288);

    return t->symbols[base + offs];
}

/* Given a data stream, decode dynamic trees from it */
static int tinf_decode_trees(struct tinf_data *d, struct tinf_tree *lt,
                             struct tinf_tree *dt)
{
    unsigned char lengths[288 + 32];

    /* Special ordering of code length codes */
    static const unsigned char clcidx[19] = {
        16, 17, 18, 0,  8, 7,  9, 6, 10, 5,
        11,  4, 12, 3, 13, 2, 14, 1, 15
    };

    unsigned int hlit, hdist, hclen;
    unsigned int i, num, length;
    int res;

    /* Get 5 bits HLIT (257-286) */
    hlit = tinf_getbits_base(d, 5, 257);

    /* Get 5 bits HDIST (1-32) */
    hdist = tinf_getbits_base(d, 5, 1);

    /* Get 4 bits HCLEN (4-19) */
    hclen = tinf_getbits_base(d, 4, 4);

    /*
     * The RFC limits the range of HLIT to 286, but lists HDIST as range
     * 1-32, even though distance codes 30 and 31 have no meaning. While
     * we could allow the full range of HLIT and HDIST to make it possible
     * to decode the fixed trees with this function, we consider it an
     * error here.
     *
     * See also: https://github.com/madler/zlib/issues/82
     */
    if (hlit > 286 || hdist > 30) {
        data_error(__LINE__);
        return TINF_DATA_ERROR;
    }

    for (i = 0; i < 19; ++i) {
        lengths[i] = 0;
    }

    /* Read code lengths for code length alphabet */
    for (i = 0; i < hclen; ++i) {
        /* Get 3 bits code length (0-7) */
        unsigned int clen = tinf_getbits(d, 3);

        lengths[clcidx[i]] = clen;
    }

    /* Build code length tree (in literal/length tree to save space) */
    res = tinf_build_tree(lt, lengths, 19);

    if (res != TINF_OK) {
        return res;
    }

    /* Check code length tree is not empty */
    if (lt->max_sym == -1) {
        data_error(__LINE__);
        return TINF_DATA_ERROR;
    }

    /* Decode code lengths for the dynamic trees */
    for (num = 0; num < hlit + hdist; ) {
        int sym = tinf_decode_symbol(d, lt);

        if (sym > lt->max_sym) {
            data_error(__LINE__);
            return TINF_DATA_ERROR;
        }

        switch (sym) {
        case 16:
            /* Copy previous code length 3-6 times (read 2 bits) */
            if (num == 0) {
                data_error(__LINE__);
                return TINF_DATA_ERROR;
            }
            sym = lengths[num - 1];
            length = tinf_getbits_base(d, 2, 3);
            break;
        case 17:
            /* Repeat code length 0 for 3-10 times (read 3 bits) */
            sym = 0;
            length = tinf_getbits_base(d, 3, 3);
            break;
        case 18:
            /* Repeat code length 0 for 11-138 times (read 7 bits) */
            sym = 0;
            length = tinf_getbits_base(d, 7, 11);
            break;
        default:
            /* Values 0-15 represent the actual code lengths */
            length = 1;
            break;
        }

        if (length > hlit + hdist - num) {
            data_error(__LINE__);
            return TINF_DATA_ERROR;
        }

        while (length--) {
            lengths[num++] = sym;
        }
    }

    /* Check EOB symbol is present */
    if (lengths[256] == 0) {
        data_error(__LINE__);
        return TINF_DATA_ERROR;
    }

    /* Build dynamic trees */
    res = tinf_build_tree(lt, lengths, hlit);

    if (res != TINF_OK) {
        return res;
    }

    res = tinf_build_tree(dt, lengths + hlit, hdist);

    if (res != TINF_OK) {
        return res;
    }

    return TINF_OK;
}

/* -- Block inflate functions -- */

long emit_print = 0;
long emit_max = 0;
static int emit(struct tinf_data *d, unsigned char c) {
    if (emit_max == 0) {
        return TINF_STOP;
    }
    emit_max -= 1;
    if (!(isprint(c) || isspace(c))) {
        return TINF_NON_PRINT;
    }
    if (emit_print) {
        printf("%c", c);
        emit_print--;
    }
    d->output_buffer[d->output_buffer_ptr].sym = c;
    d->output_buffer[d->output_buffer_ptr].is_known = 1;
    d->output_buffer_ptr = (d->output_buffer_ptr+1) % OUTPUT_BUFFER_SIZE;
    return TINF_OK;
}

static int emit_copy(struct tinf_data *d, int offs) {
    if (emit_max == 0) {
        return TINF_STOP;
    }
    emit_max -= 1;
    int idx = (d->output_buffer_ptr-offs+OUTPUT_BUFFER_SIZE) % OUTPUT_BUFFER_SIZE;
    unsigned char c = d->output_buffer[idx].sym;
    if (emit_print) {
        printf("%c", d->output_buffer[idx].is_known ? c : '#');
        emit_print--;
    }
    d->output_buffer[d->output_buffer_ptr] = d->output_buffer[idx];
    d->output_buffer_ptr = (d->output_buffer_ptr+1) % OUTPUT_BUFFER_SIZE;
    return TINF_OK;
}

/* Given a stream and two trees, inflate a block of data */
static int tinf_inflate_block_data(struct tinf_data *d, struct tinf_tree *lt,
                                   struct tinf_tree *dt)
{
    /* Extra bits and base tables for length codes */
    static const unsigned char length_bits[30] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
        1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
        4, 4, 4, 4, 5, 5, 5, 5, 0, 127
    };

    static const unsigned short length_base[30] = {
         3,  4,  5,   6,   7,   8,   9,  10,  11,  13,
        15, 17, 19,  23,  27,  31,  35,  43,  51,  59,
        67, 83, 99, 115, 131, 163, 195, 227, 258,   0
    };

    /* Extra bits and base tables for distance codes */
    static const unsigned char dist_bits[30] = {
        0, 0,  0,  0,  1,  1,  2,  2,  3,  3,
        4, 4,  5,  5,  6,  6,  7,  7,  8,  8,
        9, 9, 10, 10, 11, 11, 12, 12, 13, 13
    };

    static const unsigned short dist_base[30] = {
           1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
          33,   49,   65,   97,  129,  193,  257,   385,   513,   769,
        1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
    };

    int res;

    for (;;) {
        int sym = tinf_decode_symbol(d, lt);

        /* Check for overflow in bit reader */
        if (d->overflow) {
            data_error(__LINE__);
            return TINF_DATA_ERROR;
        }

        if (sym < 256) {
            res = emit(d, sym);
            if (res != TINF_OK) {
                return res;
            }
        }
        else {
            int length, dist, offs;
            int i;

            /* Check for end of block */
            if (sym == 256) {
                return TINF_OK;
            }

            /* Check sym is within range and distance tree is not empty */
            if (sym > lt->max_sym || sym - 257 > 28 || dt->max_sym == -1) {
                data_error(__LINE__);
                return TINF_DATA_ERROR;
            }

            sym -= 257;

            /* Possibly get more bits from length code */
            length = tinf_getbits_base(d, length_bits[sym],
                                       length_base[sym]);

            dist = tinf_decode_symbol(d, dt);

            /* Check dist is within range */
            if (dist > dt->max_sym || dist > 29) {
                data_error(__LINE__);
                return TINF_DATA_ERROR;
            }

            /* Possibly get more bits from distance code */
            offs = tinf_getbits_base(d, dist_bits[dist],
                                     dist_base[dist]);

            /* Copy match */
            for (i = 0; i < length; ++i) {
                res = emit_copy(d, offs);
                if (res != TINF_OK) {
                    return res;
                }
            }
        }
    }
}

/* Inflate an uncompressed block of data */
static int tinf_inflate_uncompressed_block(struct tinf_data *d)
{
    unsigned int length, invlength, nmemb;
    unsigned char buf[4];

    nmemb = fread(buf, 1, 4, d->fsource);
    if (nmemb != 4) {
        return TINF_IO_ERROR;
    }

    /* Get length */
    length = read_le16(buf);

    /* Get one's complement of length */
    invlength = read_le16(buf + 2);

    /* Check length */
    if (length != (~invlength & 0x0000FFFF)) {
        data_error(__LINE__);
        return TINF_DATA_ERROR;
    }

    /* Copy block */
    while (length--) {
        nmemb = fread(buf, 1, 1, d->fsource);
        if (nmemb != 1) {
            return TINF_IO_ERROR;
        }
        emit(d, buf[0]);
    }

    /* Make sure we start next block on a byte boundary */
    d->tag = 0;
    d->bitcount = 0;

    return TINF_OK;
}

/* Inflate a block of data compressed with fixed Huffman trees */
static int tinf_inflate_fixed_block(struct tinf_data *d)
{
    /* Build fixed Huffman trees */
    tinf_build_fixed_trees(&d->ltree, &d->dtree);

    /* Decode block using fixed trees */
    return tinf_inflate_block_data(d, &d->ltree, &d->dtree);
}

/* Inflate a block of data compressed with dynamic Huffman trees */
static int tinf_inflate_dynamic_block(struct tinf_data *d)
{
    /* Decode trees from stream */
    int res = tinf_decode_trees(d, &d->ltree, &d->dtree);

    if (res != TINF_OK) {
        return res;
    }

    /* Decode block using decoded trees */
    return tinf_inflate_block_data(d, &d->ltree, &d->dtree);
}

/* -- Public functions -- */

/* Initialize global (static) data */
void tinf_init(void)
{
    return;
}

/* Inflate stream from source to dest */
int tinf_uncompress(FILE * fsource, long seek_offset, int bitoffset)
{
    struct tinf_data d;
    int bfinal;

    /* Initialise data */
    d.fsource = fsource;
    d.tag = 0;
    d.bitcount = 0;
    d.overflow = 0;
    d.output_buffer_ptr = 0;
    for (int i = 0; i < OUTPUT_BUFFER_SIZE; i++) {
        d.output_buffer[i].sym = 0;
        d.output_buffer[i].is_known = 0;
    }

    fseek(fsource, seek_offset, SEEK_SET);
    if (bitoffset != 0) {
        tinf_getbits(&d, bitoffset);
    }

    do {
        unsigned int btype;
        int res;

        /* Read final block flag */
        bfinal = tinf_getbits(&d, 1);

        /* Read block type (2 bits) */
        btype = tinf_getbits(&d, 2);

        /* Decompress block */
        switch (btype) {
        case 0:
            /* Decompress uncompressed block */
            res = tinf_inflate_uncompressed_block(&d);
            break;
        case 1:
            /* Decompress block with fixed Huffman trees */
            res = tinf_inflate_fixed_block(&d);
            break;
        case 2:
            /* Decompress block with dynamic Huffman trees */
            res = tinf_inflate_dynamic_block(&d);
            break;
        default:
            res = TINF_DATA_ERROR;
            break;
        }

        if (res != TINF_OK) {
            return res;
        }
    } while (!bfinal);

    /* Check for overflow in bit reader */
    if (d.overflow) {
        data_error(__LINE__);
        return TINF_DATA_ERROR;
    }

    return TINF_OK;
}

/* crc32.c */


static const unsigned int tinf_crc32tab[16] = {
    0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190,
    0x6B6B51F4, 0x4DB26158, 0x5005713C, 0xEDB88320, 0xF00F9344,
    0xD6D6A3E8, 0xCB61B38C, 0x9B64C2B0, 0x86D3D2D4, 0xA00AE278,
    0xBDBDF21C
};

unsigned int tinf_crc32(const void *data, unsigned int length)
{
    const unsigned char *buf = (const unsigned char *) data;
    unsigned int crc = 0xFFFFFFFF;
    unsigned int i;

    if (length == 0) {
        return 0;
    }

    for (i = 0; i < length; ++i) {
        crc ^= buf[i];
        crc = tinf_crc32tab[crc & 0x0F] ^ (crc >> 4);
        crc = tinf_crc32tab[crc & 0x0F] ^ (crc >> 4);
    }

    return crc ^ 0xFFFFFFFF;
}

/* tinfgzip.c */


typedef enum {
    FTEXT    = 1,
    FHCRC    = 2,
    FEXTRA   = 4,
    FNAME    = 8,
    FCOMMENT = 16
} tinf_gzip_flag;

int tinf_gzip_uncompress(FILE * fin, const void *header, unsigned int headerLen)
{
    const unsigned char *headerSrc = (const unsigned char *) header;
    int start = 0;
    int res;
    unsigned char flg;

    /* -- Check header -- */

    /* Check room for at least 10 byte header and 8 byte trailer */
    if (headerLen < 18) {
        data_error(__LINE__);
        return TINF_DATA_ERROR;
    }

    /* Check id bytes */
    if (headerSrc[0] != 0x1F || headerSrc[1] != 0x8B) {
        data_error(__LINE__);
        return TINF_DATA_ERROR;
    }

    /* Check method is deflate */
    if (headerSrc[2] != 8) {
        data_error(__LINE__);
        return TINF_DATA_ERROR;
    }

    /* Get flag byte */
    flg = headerSrc[3];

    /* Check that reserved bits are zero */
    if (flg & 0xE0) {
        data_error(__LINE__);
        return TINF_DATA_ERROR;
    }

    /* -- Find start of compressed data -- */

    /* Skip base header of 10 bytes */
    start = 10;

    /* Skip extra data if present */
    if (flg & FEXTRA) {
        unsigned int xlen = read_le16(headerSrc + start);

        if (xlen > headerLen - 12) {
            data_error(__LINE__);
            return TINF_DATA_ERROR;
        }

        start += xlen + 2;
    }

    /* Skip file name if present */
    if (flg & FNAME) {
        do {
            if (start >= headerLen) {
                data_error(__LINE__);
                return TINF_DATA_ERROR;
            }
        } while (headerSrc[start++]);
    }

    /* Skip file comment if present */
    if (flg & FCOMMENT) {
        do {
            if (start >= headerLen) {
                data_error(__LINE__);
                return TINF_DATA_ERROR;
            }
        } while (headerSrc[start++]);
    }

    /* Check header crc if present */
    if (flg & FHCRC) {
        unsigned int hcrc;

        if (start > headerLen - 2) {
            data_error(__LINE__);
            return TINF_DATA_ERROR;
        }

        hcrc = read_le16(headerSrc + start);

        if (hcrc != (tinf_crc32(headerSrc, start) & 0x0000FFFF)) {
            data_error(__LINE__);
            return TINF_DATA_ERROR;
        }

        start += 2;
    }

    /* -- Decompress data -- */

    res = tinf_uncompress(fin, start, 0);

    if (res != TINF_OK) {
        return TINF_DATA_ERROR;
    }

    return TINF_OK;
}

/* cli */

static void printf_error(const char *fmt, ...)
{
    va_list arg;

    fputs("tgunzip: ", stderr);

    va_start(arg, fmt);
    vfprintf(stderr, fmt, arg);
    va_end(arg);

    fputs("\n", stderr);
}

int main_old(int argc, char *argv[])
{
    FILE *fin = NULL;
    unsigned char header[1024];
    int len, res, retval = EXIT_FAILURE;

    printf("tgunzip " TINF_VER_STRING " - example from the tiny inflate library (www.ibsensoftware.com)\n\n");

    if (argc != 2) {
        fputs("usage: tgunzip INFILE\n\n", stderr);
        return EXIT_FAILURE;
    }

    tinf_init();

    /* -- Open files -- */

    if ((fin = fopen(argv[1], "rb")) == NULL) {
        printf_error("unable to open input file '%s'", argv[1]);
        goto out;
    }

    /* -- Read source -- */

    fseek(fin, 0, SEEK_END);

    len = ftell(fin);

    fseek(fin, 0, SEEK_SET);

    if (len < 18) {
        printf_error("input too small to be gzip");
        goto out;
    }

    if (fread(header, 1, sizeof(header), fin) != sizeof(header)) {
        printf_error("error reading input header");
        goto out;
    }

    /* -- Decompress data -- */

    res = tinf_gzip_uncompress(fin, header, sizeof(header));

    if ((res != TINF_OK)) {
        printf_error("decompression failed");
        goto out;
    }

    retval = EXIT_SUCCESS;

out:
    if (fin != NULL) {
        fclose(fin);
    }

    return retval;
}

int main(int argc, char ** argv) {
    int res;
    FILE *fsource = NULL;
    if ((fsource = fopen(argv[1], "rb")) == NULL) {
        printf_error("unable to open input file '%s'", argv[1]);
    }

    fseek(fsource, 0, SEEK_END);
    int filesize = ftell(fsource);

    for (long offset = 0; offset < filesize-1; offset++) {
        if (offset % 10000 == 0) {
            printf("# %ld ====\n", offset);
        }
        for (int bit = 0; bit < 8; bit++) {
            emit_max = 100000;
            emit_print = 0;
            res = tinf_uncompress(fsource, offset, bit);
            if (res == TINF_STOP) {
                printf("# ==== %ld:%d %d ==== #\n", offset, bit, res);
                emit_print = 20000;
                emit_max = 1000;
                tinf_uncompress(fsource, offset, bit);
                puts("");
            }
            //if (offset == 10+55550) { break; }
        }
    }

}
