# gzip-random-seek

This is an experiment in random-seeking in DEFLATE (gzip/zip) streams, with the goal of
being able to perform [a binary search over gzip compressed sorted bioinformatics data](https://blog.llandsmeer.com/tech/2019/12/28/search-sorted.html).
To do this, it tries to reconstruct the neccesary 64kb of state to decompress the file,
starting from the file offset input by the user.

I started from [tinf](https://github.com/jibsen/tinf), and adapted it to:

 - Work on iostreams instead of memory
 - Stripped out all non-deflate related things.
 - Then, after getting a start positions by the user, step through the file bit by bit,
   and try to decompress it as a DEFLATE block
 - As soon as there is a data error (DEFLATE has very little
   data integrity checks, but they do exists),
   or if decompression outputs something non-printable (most likely stopping case),
   abort reading the block.
 - If we can decompress some (100000 by default) printable characters, start decompression
   from that byte+bit location and start printing to console.

While not useful for meaningful data, it is able to
decompress with random access for simple test cases like the output of `seq 100000000 | gz`.
For more complex files, like the UK Biobank CAD GWAS, it is unable to recover
the full 64kb of state starting from a random location.
This problem is mostly due to the fact that
a lot of state if generated in the first few kb's of data, and used throughout the entire file.
That is a solvable problem, although not an easy one. The next big problem is that sometimes
single bytes at random location are reused 100's of megabytes away from their definition, which
makes the problem unsolvable in general...

Anyway, it is still useful for decompressing DEFLATE streams in unknown/broken container formats,
or as a general purpose DEFLATE decompressor.


```
$ make
gcc -Wall -g -rdynamic -O3 tinflate.c -o gzip-random-seek

$ ./gzip-random-seek
usage: ./gzip-random-seek <where> <filename>
    where       number from 0 to 100 (in file-size %)
    filename    deflate container like gzip
```

I think that, if there is any lesson to be learned here, that
`gzip`-ing your sorted files really makes things unnecessarily
hard for efficient data analysis. Something like `bzip2`, `bgzip` or
a modified gzip that resets its internal state every few MB's
would be a lot better.

