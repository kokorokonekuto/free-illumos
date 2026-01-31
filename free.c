/* cc -o free -O3 -s -lkstat -lm free.c */

/* This is to public nanosleep function prototype,
   and we can't set _POSIX_C_SOURCE as it breaks
   timeval structure. */
#define __EXTENSIONS__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <err.h>
#include <math.h>
#include <sys/swap.h>
#include <string.h>
#include <kstat.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <libgen.h>

#ifndef MIN
# define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

/* This is used by the longbar. */
#define BAR_LENGTH     35.0
#define COLOR_RED      "\x1b[1;91m"
#define COLOR_GREEN    "\x1b[1;92m"
#define COLOR_END      "\x1b[0m"

/* Memory information. */
struct memory_info {
        uint64_t total;
	uint64_t used;
	uint64_t free;
};

/* Swap information. */
struct swap_info {
	uint64_t total;
	uint64_t used;
	uint64_t free;
};

/* ZFS ARC information. */
struct zfs_arc_info {
        uint64_t arc_meta_max;
	uint64_t arc_meta_min;
	uint64_t arc_meta_used;
	uint64_t arc_meta_limit;
};

/* Anon cache information. */
struct anon_cache {
        uint64_t buf_avail;
	uint64_t buf_inuse;
	uint64_t buf_max;
	uint64_t buf_total;
};

/* Array list of swap devices. */
struct array_list {
	struct swap_info **swap;
	size_t total_swaps;
	size_t alloc_ntimes;
};

struct longbar_buffer {
	char *pused;
	char *pfree;
};

/* Structure holding configurations. */
struct cfg_output {
	uint8_t show_all_swaps;
	uint8_t show_arc_info;
	uint8_t only_show_mem_info;
	uint8_t only_show_swap_info;
	uint8_t only_show_arc_info;
	uint8_t unit_type;
	uint8_t is_pretty;
	uint8_t is_si;
	uint8_t only_show_anon_cache;
	uint8_t is_longbar;
};

/* Can't go beyond exbi, as we'll reach beyond what
   int64_t can hold. */ 
enum unit_type {
	UNIT_BYTE,
	UNIT_KIBI,
	UNIT_MEBI,
	UNIT_GIBI,
	UNIT_TEBI,
	UNIT_PEBI,
	UNIT_EXBI,

	UNIT_KILO,
	UNIT_MEGA,
	UNIT_GIGA,
	UNIT_TERA,
	UNIT_PETA,
	UNIT_EXA,
};

/* utilities. */
static void array_list_do_init(struct array_list *alist)
{
	alist->swap = NULL;
	alist->total_swaps = 0;
	alist->alloc_ntimes = 1;
}

static void array_list_do_push(struct array_list *alist, struct swap_info *swap)
{
	if ((alist->swap = realloc(alist->swap, sizeof(struct swap_info) *
				   alist->alloc_ntimes)) == NULL)
		err(1, "realloc");

	alist->swap[alist->total_swaps++] = swap;
	alist->alloc_ntimes++;
}

static uint32_t conv_to_u32_from_p(const char *s)
{
	char *eptr;
	long long val;

	val = strtoll(s, &eptr, 10);
	if (eptr == s)
	        errx(1, "error: invalid digit was provided");
	if (errno == ERANGE)
		err(1, "strtoll");
	if (val > UINT32_MAX)
		errx(1, "error: provided digit is larger than UINT32_MAX");
	else if (val < 0)
		errx(1, "error: provided digit is smaller than 0");

	return ((uint32_t)val);
}

static void collect_memory_info(struct memory_info *mem)
{
	int64_t psz, phys_pages, avphys_pages;

	if ((psz = (int64_t)sysconf(_SC_PAGESIZE)) == -1)
		err(1, "sysconf");
        if ((phys_pages = (int64_t)sysconf(_SC_PHYS_PAGES)) == -1)
		err(1, "sysconf");
	if ((avphys_pages = (int64_t)sysconf(_SC_AVPHYS_PAGES)) == -1)
		err(1, "sysconf");

	mem->total = (uint64_t)((uint64_t)phys_pages * psz);
	mem->used = (uint64_t)((uint64_t)mem->total - avphys_pages * psz);
	mem->free = (uint64_t)(avphys_pages * psz);
}

static int should_collect_swap_info(struct swap_info *swap,
				    struct array_list *alist, int collect_each)
{
	struct swaptable *st;
	struct swapent *swapent;
	struct swap_info *swap_i;
        long entries, page_size, i;
	char *path, *p;

	if ((entries = swapctl(SC_GETNSWP, NULL)) == -1)
		err(1, "swapctl");
	/* Number of swap devices configured. */
	if (entries == 0)
		return (0);

	if ((st = malloc(entries * sizeof(struct swapent) + sizeof(int))) == NULL)
		err(1, "malloc");
	if ((path = malloc(entries * MAXPATHLEN)) == NULL)
		err(1, "malloc");

	/* ste_path's are required to be initialized before
	   querying for the list of swap devices. */
	swapent = st->swt_ent;
        for (p = path, i = 0; i < entries; i++) {
		swapent[i].ste_path = p;
		p += MAXPATHLEN;
	}

	st->swt_n = entries;
	if ((entries = swapctl(SC_LIST, st)) == -1)
		err(1, "swapctl");

	/* swapent = st->swt_ent; */
	if ((page_size = sysconf(_SC_PAGESIZE)) == -1)
		err(1, "sysconf");

	/* page_size = 1024; */
	if (!collect_each) {
	        for (i = 0; i < entries; i++) {	
			swap->total += (uint64_t)(swapent[i].ste_pages) * page_size;
			swap->free += (uint64_t)(swapent[i].ste_free) * page_size;
			swap->used += ((uint64_t)(swapent[i].ste_pages) * page_size) -
			        ((uint64_t)(swapent[i].ste_free) * page_size);
		}
	} else {
		for (i = 0; i < entries; i++) {
			if ((swap_i = malloc(sizeof(struct swap_info))) == NULL)
				err(1, "malloc");
			
			swap_i->total = (uint64_t)(swapent[i].ste_pages) * page_size;
			swap_i->free = (uint64_t)(swapent[i].ste_free) * page_size;
			swap_i->used = ((uint64_t)(swapent[i].ste_pages) * page_size) -
				((uint64_t)(swapent[i].ste_free) * page_size);
		        array_list_do_push(alist, swap_i);
		}
	}

	free(path);
	free(st);
	return (1);
}

static void free_swap_entries(struct array_list *alist)
{
	size_t i;

        for (i = 0; i < alist->total_swaps; i++)
		free(alist->swap[i]);
	free(alist->swap);
}

static unsigned int collect_anon_cache(struct anon_cache *anon_cache)
{
	kstat_ctl_t *ks;
	kstat_t *kchain;
	kstat_named_t *kstat_n;
	unsigned n, found_entry;

	if ((ks = kstat_open()) == NULL)
		err(1, "kstat_open");

	found_entry = 0;
	for (kchain = ks->kc_chain; kchain->ks_next != NULL;
	     kchain = kchain->ks_next) {
		if (kstat_read(ks, kchain, NULL) == -1)
			err(1, "kstat_read");
	        if (strcmp(kchain->ks_name, "anon_cache") == 0) {
			/* Only check whether the kstat entry exists or not,
			   anything else related to this entry is default
			   initialized. */
			found_entry = 1;
			n = kchain->ks_ndata;
			kstat_n = kchain->ks_data;
			/* Data type we receive from kstat_n->data_type
			   is ui64 (4) for buf_inuse. */
			for (; n > 0; n--, kstat_n++) {
				if (strcmp(kstat_n->name, "buf_avail") == 0)
				        anon_cache->buf_avail = kstat_n->value.ui64;
				else if (strcmp(kstat_n->name, "buf_inuse") == 0)
				        anon_cache->buf_inuse = kstat_n->value.ui64;
				else if (strcmp(kstat_n->name, "buf_max") == 0)
					anon_cache->buf_max = kstat_n->value.ui64;
				else if (strcmp(kstat_n->name, "buf_total") == 0)
					anon_cache->buf_total = kstat_n->value.ui64;
			}
			break;
		}
	}

	kstat_close(ks);
	return (found_entry);
}

static void collect_zfs_arc_info(struct zfs_arc_info *arc_info)
{
	kstat_ctl_t *ks;
	kstat_t *kchain;
	unsigned int n, found_arc_stats;
	kstat_named_t *kstat_n;

	if ((ks = kstat_open()) == NULL)
		err(1, "kstat_open");

	found_arc_stats = 0;
	/* Go through the list until kchain->ks_next exhausted. */
	for (kchain = ks->kc_chain; kchain->ks_next != NULL;
	     kchain = kchain->ks_next) {
		if (kstat_read(ks, kchain, NULL) == -1)
			err(1, "kstat_read");

		/* Name of the kstat entry */
		if (strcmp(kchain->ks_name, "arcstats") == 0) {
			found_arc_stats = 1;
		        n = kchain->ks_ndata;
		        kstat_n = kchain->ks_data;
			for (; n > 0; n--, kstat_n++) {
				if (strcmp(kstat_n->name, "arc_meta_max") == 0)
					arc_info->arc_meta_max = kstat_n->value.ui64;
				else if (strcmp(kstat_n->name, "arc_meta_min") == 0)
					arc_info->arc_meta_min = kstat_n->value.ui64;
				else if (strcmp(kstat_n->name, "arc_meta_used") == 0)
					arc_info->arc_meta_used = kstat_n->value.ui64;
				else if (strcmp(kstat_n->name, "arc_meta_limit") == 0)
					arc_info->arc_meta_limit = kstat_n->value.ui64;					
			}
			break;
		}
	}

	/* This should not happen as (most) illumos distributions
	   doesn't use file-systems other than ZFS as default
	   (maybe except tribblix). */
	if (!found_arc_stats)
		errx(1,
		     "error: kernel statistics doesn't holds arcstats entry.\n"
		     "Are you using UFS?");

	kstat_close(ks);
}

/* Taken from: https://github.com/banyan/rust-pretty-bytes/blob/master/src/converter.rs */
static char *pretty_bytes(double bytes, unsigned int is_si)
{
	char *buf, tbuf[10];
	const char **units;
	double abs_bytes, expo, delim, size;
	size_t units_len, len;

	if (bytes == 0.0)
		return ("0B");

	/* We can't accept negative size. */
	assert(bytes > 0.0);
	static const char *binary_units[] = {
		"B", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei"};
	static const char *decimal_units[] = {
		"B", "k", "M", "G", "T", "P", "E"};

	units = is_si ? decimal_units : binary_units;
	/* This is to ensure not to have size mismatch. */	  
	assert(sizeof(binary_units)/sizeof(*binary_units) ==
	       sizeof(decimal_units)/sizeof(*decimal_units));
        units_len = sizeof(binary_units)/sizeof(*binary_units);

	abs_bytes = fabs(bytes);
	delim = is_si ? 1000.0 : 1024.0;
	expo = MIN(floor(log(abs_bytes) / log(delim)), (double)(units_len - 1));

	if ((buf = calloc(20, sizeof(char))) == NULL)
		err(1, "calloc");

        size = abs_bytes / pow(delim, expo);
	snprintf(tbuf, sizeof(tbuf), "%.2lf", size);
        len = strlen(tbuf);
	
	if (tbuf[len - 2] != '0' && tbuf[len - 1] == '0')
		tbuf[len - 1] = '\0';
	/* Exclude suffix containing trailing bytes
	   e.g. 1024.00MB is being replaced to 1024MB */
	else if (tbuf[len - 2] == '0' && tbuf[len - 1] == '0')
		tbuf[len - 3] = '\0';

	snprintf(buf, 20, "%s%s", tbuf, units[(size_t)expo]);
	return (buf);
}

/* TODO: fix this */
static struct longbar_buffer *format_longbar(double percent)
{	
        size_t total_alloc;
	double total_free;
	struct longbar_buffer *longbar;

        total_free = percent > 50.0 ?
		floor((double)(BAR_LENGTH * (percent / 100.0))) :
	        ceil((double)(BAR_LENGTH * (percent / 100.0)));
        total_alloc = (size_t)(BAR_LENGTH - total_free);

	if ((longbar = malloc(sizeof(struct longbar_buffer))) == NULL)
		err(1, "malloc");

	/* format string including nul-termination (36 bytes) and
	   ASCII color codes (11 bytes, 7 bytes without COLOR_END). */
	if ((longbar->pfree = calloc(40, sizeof(char))) == NULL)
		err(1, "malloc");
	if ((longbar->pused = calloc(47, sizeof(char))) == NULL)
		err(1, "malloc");

	/* Memory that's currently in used. */
	memcpy(longbar->pused, COLOR_RED, strlen(COLOR_RED));
	memset(longbar->pused + strlen(COLOR_RED), '%', total_alloc);
	longbar->pused[total_alloc + strlen(COLOR_RED) + 1] = '\0';

	/* Memory that's currently free. */
	memcpy(longbar->pfree, COLOR_GREEN, strlen(COLOR_GREEN));
	memset(longbar->pfree + strlen(COLOR_GREEN), '#', (size_t)(total_free));
	memcpy(longbar->pfree + (size_t)total_free + strlen(COLOR_GREEN),
	       COLOR_END, strlen(COLOR_END));
	longbar->pfree[(size_t)total_free + strlen(COLOR_GREEN) + strlen(COLOR_END)] = '\0';
	return (longbar);
}

static void free_format_longbar(struct longbar_buffer *longbar)
{
	free(longbar->pused);
	free(longbar->pfree);
	free(longbar);
}

static void print_default_info(const struct cfg_output *cfg)
{
	size_t i;
	struct memory_info mem;
        struct swap_info swap;
	struct array_list alist;
	struct zfs_arc_info arc_info;
	struct anon_cache anon_cache;
	int64_t d;
	char *ptotal, *pused, *pfree;
	char *buf_avail, *buf_inuse, *buf_max, *buf_total;			
        struct longbar_buffer *longbar;
	double avail;
	
	if (cfg->is_longbar) {
		if (!cfg->only_show_swap_info) {
			/* Memory information. */
			memset(&mem, '\0', sizeof(struct memory_info));
			collect_memory_info(&mem);
			avail = ((double)mem.free / (double)mem.total) * 100.0;
			longbar = format_longbar(avail);
			fprintf(stdout, "Mem:   %s%s (used: %.2lf%%, avail: %.2lf%%)\n",
				longbar->pused, longbar->pfree,
				((double)mem.used / (double)mem.total) * 100.0, avail);
			free_format_longbar(longbar);
			if (cfg->only_show_mem_info)
				return;
		}

		/* Swap information. */
		memset(&swap, '\0', sizeof(struct swap_info));
	        if (should_collect_swap_info(&swap, &alist, 0)) {
			avail = ((double)swap.free / (double)swap.total) * 100.0;
		        longbar = format_longbar(avail);
			fprintf(stdout, "Swap:  %s%s (used: %.2lf%%, avail: %.2lf%%)\n",
				longbar->pused, longbar->pfree,
				((double)swap.used / (double)swap.total) * 100.0, avail);
			free_format_longbar(longbar);
		}
	        return;
	}
	
	switch (cfg->unit_type) {
	case UNIT_KIBI: d = 1024; break;
	case UNIT_MEBI: d = 1024*1024; break;
	case UNIT_GIBI: d = 1024*1024*1024; break;
	case UNIT_TEBI: d = 1024LL*1024LL*1024LL*1024LL; break;
	case UNIT_PEBI: d = 1024LL*1024LL*1024LL*1024LL*1024LL; break;
	case UNIT_EXBI: d = 1024LL*1024LL*1024LL*1024LL*1024LL*1024LL; break;
	case UNIT_KILO: d = 1000; break;
	case UNIT_MEGA: d = 1000*1000; break;
	case UNIT_GIGA: d = 1000*1000*1000; break;
	case UNIT_TERA: d = 1000LL*1000LL*1000LL*1000LL; break;
	case UNIT_PETA: d = 1000LL*1000LL*1000LL*1000LL*1000LL; break;
	case UNIT_EXA:  d = 1000LL*1000LL*1000LL*1000LL*1000LL*1000LL; break;
        default:        d = 1;
	}

	/* Print this when we are not only printing the ARC information. */
	if (!cfg->only_show_arc_info && !cfg->only_show_anon_cache)
		fprintf(stdout, "              total            used            free\n");

	/* Only when we're requesting to every information, and not
	   just a sigular one (includes swap and ARC) but not memory
	   information. */
	if (!cfg->only_show_swap_info && !cfg->only_show_arc_info &&
	    !cfg->only_show_anon_cache) {
		memset(&mem, '\0', sizeof(struct memory_info));
		collect_memory_info(&mem);

		if (cfg->is_pretty) {
			ptotal = pretty_bytes((double)mem.total, cfg->is_si);
			pused = pretty_bytes((double)mem.used, cfg->is_si);
			pfree = pretty_bytes((double)mem.free, cfg->is_si);
			fprintf(stdout, "Mem:  %13s %15s %15s\n",
				ptotal, pused, pfree);
			free(ptotal);
			free(pused);
			free(pfree);
		}
		else
			fprintf(stdout, "Mem:  %13ld %15ld %15ld\n", mem.total / d,
				mem.used / d, mem.free / d);
		if (cfg->only_show_mem_info)
			return;
	}

	if (!cfg->only_show_arc_info && !cfg->only_show_anon_cache) {
		memset(&swap, '\0', sizeof(struct swap_info));
		array_list_do_init(&alist);
		/* Collect swap information and based on the config
		   show individual swap devices (their total, used,
		   and free), or a single one that calculates the
		   total of all the swap devices. */
		if (should_collect_swap_info(&swap, &alist, cfg->show_all_swaps)) {
			if (cfg->show_all_swaps) {
				for (i = 0; i < alist.total_swaps; i++) {
					if (cfg->is_pretty) {
						ptotal = pretty_bytes((double)alist.swap[i]->total, cfg->is_si);
						pused = pretty_bytes((double)alist.swap[i]->used, cfg->is_si);
						pfree = pretty_bytes((double)alist.swap[i]->free, cfg->is_si);
						fprintf(stdout,
							"Swap: %13s %15s %15s\n", ptotal, pused, pfree);
						free(ptotal);
						free(pused);
						free(pfree);
					} else {
						fprintf(stdout,
							"Swap: %13ld %15ld %15ld\n", alist.swap[i]->total/d,
							alist.swap[i]->used/d, alist.swap[i]->free/d);
					}
				}
				free_swap_entries(&alist);
			} else {
				if (cfg->is_pretty) {
					ptotal = pretty_bytes((double)swap.total, cfg->is_si);
					pused = pretty_bytes((double)swap.used, cfg->is_si);
					pfree = pretty_bytes((double)swap.free, cfg->is_si);

					fprintf(stdout,
						"Swap: %13s %15s %15s\n", ptotal, pused, pfree);
					free(ptotal);
					free(pused);
					free(pfree);
				} else {
					fprintf(stdout, "Swap: %13ld %15ld %15ld\n", swap.total/d,
						swap.used/d, swap.free/d);
				}
			}
		}
		if (cfg->only_show_swap_info)
			return;
	}

	if (cfg->show_arc_info || cfg->only_show_arc_info) {
		memset(&arc_info, '\0', sizeof(struct zfs_arc_info));
		collect_zfs_arc_info(&arc_info);
		if (cfg->show_arc_info)
			fputc('\n', stdout);
		fprintf(stdout, "           meta_max       meta_used        meta_min\n");
		if (cfg->is_pretty) {
			ptotal = pretty_bytes((double)arc_info.arc_meta_max, cfg->is_si);
			pused = pretty_bytes((double)arc_info.arc_meta_used, cfg->is_si);
			pfree = pretty_bytes((double)arc_info.arc_meta_min, cfg->is_si);
			fprintf(stdout, "ARC: %14s %15s %15s\n", ptotal, pused, pfree);

			free(ptotal);
			free(pused);
			free(pfree);			
		} else {
			fprintf(stdout, "ARC: %14lu %15lu %15lu\n", arc_info.arc_meta_max,
				arc_info.arc_meta_used, arc_info.arc_meta_min);
		}
	}
	
	if (cfg->only_show_anon_cache) {
		memset(&anon_cache, '\0', sizeof(struct anon_cache));
		collect_anon_cache(&anon_cache);

		fprintf(stdout, "         buf_avail      buf_inuse      buf_max      buf_total\n");
		if (cfg->is_pretty) {
			buf_avail = pretty_bytes((double)anon_cache.buf_avail, cfg->is_si);
			buf_inuse = pretty_bytes((double)anon_cache.buf_inuse, cfg->is_si);
			buf_max = pretty_bytes((double)anon_cache.buf_max, cfg->is_si);
			buf_total = pretty_bytes((double)anon_cache.buf_total, cfg->is_si);
			fprintf(stdout, "Cache: %11s %14s %12s %14s\n", buf_avail, buf_inuse,
				buf_max, buf_total);
			free(buf_avail);
			free(buf_inuse);
			free(buf_max);
			free(buf_total);
		} else {
			fprintf(stdout, "Cache: %11lu %14lu %12lu %14lu\n",
				anon_cache.buf_avail, anon_cache.buf_inuse,
				anon_cache.buf_max, anon_cache.buf_total);
		}
	}

}

static void print_help(int status)
{
	fprintf(stdout,
		"free\n"
		" [-b/--bytes]   -- print output in bytes\n"
		" [-k/--kibi]    -- print output in kibibytes\n"
		" [-m/--mebi]    -- print output in mebibytes\n"
		" [--gibi]       -- print output in gibibytes\n"
		" [--tebi]       -- print output in tebibytes\n"
		" [--pebi]       -- print output in pebibytes\n"
		" [--exbi]       -- print output in exbibytes\n"
		" [--kilo]       -- print output in kilobytes\n"
		" [--mega]       -- print output in megabytes\n"
		" [--giga]       -- print output in gigabytes\n"
		" [--tera]       -- print output in terabytes\n"
		" [--peta]       -- print output in petabytes\n"
		" [--exa]        -- print output in exabytes\n"
		" [-p/--pretty]  -- print output in pretty format\n"
		" [--zarc]       -- print output of zone ARC size\n"
		" [--zarconly]   -- only print output of zone ARC size\n"
		" [--memonly]    -- only print output of memory\n"
		" [--swaponly]   -- only print output of swap\n"
		" [--swapdevs]   -- print output of all swap devices individually\n"
		" [--anoncache]  -- print output of anon_cache\n"
		" [--si]         -- format size in decimal unit\n"
		" [--bar]        -- print output of memory and swap in colored bars\n"
		" [--times]      -- print output for specified times\n"
		" [--sleep]      -- delay/sleep between collecting and printing output\n"
		" [--help]       -- print this help message\n");
	exit(status);
}

int main(int argc, char **argv)
{
        struct cfg_output cfg;
	static struct option long_opts[] = {
		{ "bytes",     no_argument,  NULL, 'b' },
		{ "kibi",      no_argument,  NULL, 'k' },
		{ "mebi",      no_argument,  NULL, 'm' },
		{ "gibi",      no_argument,  NULL, 'g' },
		{ "tebi",      no_argument,  NULL,  1 },
		{ "pebi",      no_argument,  NULL,  2 },
		{ "exbi",      no_argument,  NULL,  3 },
		{ "kilo",      no_argument,  NULL,  4 },
		{ "mega",      no_argument,  NULL,  5 },
		{ "giga",      no_argument,  NULL,  6 },
		{ "tera",      no_argument,  NULL,  7 },
		{ "peta",      no_argument,  NULL,  8 },
		{ "exa",       no_argument,  NULL,  9 },
		{ "pretty",    no_argument,  NULL,  'p' },
		{ "zarc",      no_argument,  NULL,  10 },
		{ "zarconly",  no_argument,  NULL,  11 },
		{ "memonly",   no_argument,  NULL,  12 },
		{ "swaponly",  no_argument,  NULL,  13 },
 		{ "swapdevs",  no_argument,  NULL,  14 },
		{ "anoncache", no_argument,  NULL,  15 },
		{ "si",        no_argument,  NULL,  16 },
		{ "bar",       no_argument,  NULL,  17 },
		{ "times",     required_argument, NULL, 18 },
		{ "sleep",     required_argument, NULL, 19 },
		{ "help",      no_argument,  NULL,  'h' },
	        { NULL,     0,            NULL,  0 },
	};
	int opt;
	struct timespec ts;
        uint32_t times;

	memset(&cfg, '\0', sizeof(struct cfg_output));
	memset(&ts, '\0', sizeof(struct timespec));
	times = 1;
	while ((opt = getopt_long(argc, argv, "bkmgph", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'b':  cfg.unit_type = UNIT_BYTE;     break;
		case 'k':  cfg.unit_type = UNIT_KIBI;     break;
		case 'm':  cfg.unit_type = UNIT_MEBI;     break;
		case 'g':  cfg.unit_type = UNIT_GIBI;     break;
		case 1:    cfg.unit_type = UNIT_TEBI;     break;
		case 2:    cfg.unit_type = UNIT_PEBI;     break;
		case 3:    cfg.unit_type = UNIT_EXBI;     break;
		case 4:    cfg.unit_type = UNIT_KILO;     break;
		case 5:    cfg.unit_type = UNIT_MEGA;     break;
		case 6:    cfg.unit_type = UNIT_GIGA;     break;
		case 7:    cfg.unit_type = UNIT_TERA;     break;
		case 8:    cfg.unit_type = UNIT_PETA;     break;
		case 9:    cfg.unit_type = UNIT_EXA;      break;
		case 10:   cfg.show_arc_info = 1;         break;
		case 11:   cfg.only_show_arc_info = 1;    break;
		case 12:   cfg.only_show_mem_info = 1;    break;
		case 13:   cfg.only_show_swap_info = 1;   break;
		case 14:   cfg.show_all_swaps = 1;        break;
		case 15:   cfg.only_show_anon_cache = 1;  break;
		case 16:   cfg.is_si = 1;                 break;
		case 17:   cfg.is_longbar = 1;            break;
		case 18:   times = conv_to_u32_from_p(optarg); break;
		case 19:   ts.tv_sec = conv_to_u32_from_p(optarg); break;
		case 'p':  cfg.is_pretty = 1;             break;
		case 'h':  print_help(0); /* fallthrough */
		case '?':
		default:
			fprintf(stderr,
				"type %s --help for more information\n", basename(*argv));
			exit(1);
		}
	}

	/* --bar only accepts --memonly or --swaponly, not anything else. */
	if (cfg.is_longbar && (cfg.is_pretty || cfg.is_si || cfg.only_show_anon_cache ||
			       cfg.only_show_arc_info || cfg.show_all_swaps))
		errx(1, "error: cannot combine them with long bar.");

	/* Three match (--memonly, --swaponly, --anoncache) */
	if ((cfg.only_show_mem_info && cfg.only_show_swap_info && cfg.only_show_anon_cache) ||
	    (cfg.only_show_mem_info && cfg.only_show_swap_info && cfg.only_show_arc_info) ||

	    /* two match ([--memonly, --swaponly], [--memonly, --zarconly],
	       [--memonly, --anoncache]). */
	    (cfg.only_show_mem_info && cfg.only_show_swap_info) ||
	    (cfg.only_show_mem_info && cfg.only_show_arc_info) ||
	    (cfg.only_show_mem_info && cfg.only_show_anon_cache) ||

	    /* two match ([--swaponly, --zarconly], [--swaponly, --zarconly],
	       [--swaponly, --anoncache]). */
	    (cfg.only_show_swap_info && cfg.only_show_arc_info) ||
	    (cfg.only_show_swap_info && cfg.only_show_anon_cache))
		errx(1, "error: cannot combine \"*-only\" arguments.");

	while (times-- > 0) {
		print_default_info(&cfg);
		if (times > 0)
			fputc('\n', stdout);
		if (ts.tv_sec > 0) {
			if (nanosleep(&ts, NULL) == -1)
				err(1, "nanosleep");
		}
	}
}
