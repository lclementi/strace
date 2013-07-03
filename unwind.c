/*
 * Copyright (c) 2013 Luca Clementi <luca.clementi@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "defs.h"

#include <libunwind.h>


extern unw_addr_space_t libunwind_as;
/*
 * caching of /proc/ID/maps for each process to speed up stack tracing
 *
 * The cache must be refreshed after some syscall: mmap, mprotect, munmap, execve
 */
void
alloc_mmap_cache(struct tcb* tcp)
{
	/* start with a small dynamically-allocated array and then expand it */
	int cur_array_size = 10;
	char filename[sizeof ("/proc/0123456789/maps")];
	struct mmap_cache_t* cache_head = malloc(cur_array_size * sizeof(*cache_head));
	if (!cache_head)
		die_out_of_memory();

	sprintf(filename, "/proc/%d/maps", tcp->pid);

	FILE* f = fopen(filename, "r");
	if (!f)
		perror_msg_and_die("Can't open %s", filename);
	char s[300];
	while (fgets(s, sizeof(s), f) != NULL) {
		unsigned long start_addr, end_addr, mmap_offset;
		char binary_path[512];
		binary_path[0] = '\0'; // 'reset' it just to be paranoid

		sscanf(s, "%lx-%lx %*c%*c%*c%*c %lx %*x:%*x %*d %[^\n]", &start_addr,
			&end_addr, &mmap_offset, binary_path);

		/* ignore special 'fake files' like "[vdso]", "[heap]", "[stack]", */
		if (binary_path[0] == '[') {
			continue;
		}

		if (binary_path[0] == '\0') {
			continue;
		}

		if(end_addr < start_addr)
			perror_msg_and_die("Unrecognized maps file format %s", filename);
		
		struct mmap_cache_t* cur_entry = &cache_head[tcp->mmap_cache_size];
		cur_entry->start_addr = start_addr;
		cur_entry->end_addr = end_addr;
		cur_entry->mmap_offset = mmap_offset;
		cur_entry->binary_filename = strdup(binary_path);

		/* sanity check to make sure that we're storing non-overlapping regions in
		 * ascending order
		 */
		if (tcp->mmap_cache_size > 0) {
			struct mmap_cache_t* prev_entry = &cache_head[tcp->mmap_cache_size - 1];
			if (prev_entry->start_addr >= cur_entry->start_addr)
				perror_msg_and_die("Overlaying memory region in %s", filename);
			if (prev_entry->end_addr > cur_entry->start_addr)
				perror_msg_and_die("Overlaying memory region in %s", filename);
		}
		tcp->mmap_cache_size++;

		/* resize doubling its size */
		if (tcp->mmap_cache_size >= cur_array_size) {
			cur_array_size *= 2;
			cache_head = realloc(cache_head, cur_array_size * sizeof(*cache_head));
			if (!cache_head)
				die_out_of_memory();
		}
	}
	fclose(f);
	tcp->mmap_cache = cache_head;
}

/* deleting the cache */
void
delete_mmap_cache(struct tcb* tcp)
{
	int i;
	for (i = 0; i < tcp->mmap_cache_size; i++) {
		free(tcp->mmap_cache[i].binary_filename);
	}
	free(tcp->mmap_cache);
	tcp->mmap_cache = NULL;
	tcp->mmap_cache_size = 0;
}



/*
 * use libunwind to unwind the stack and print a backtrace
 *
 * Pre-condition: tcp->mmap_cache is already initialized
 */
void
print_stacktrace(struct tcb* tcp)
{
	unw_word_t ip;
	unw_cursor_t cursor;
	unw_word_t function_off_set;
	int stack_depth = 0, ret_val;
	
	/* these are used for the binary search through the mmap_chace */
	int lower, upper, mid;

	int symbol_name_size = 40;
	char * symbol_name;
	struct mmap_cache_t* cur_mmap_cache;
	unsigned long true_offset;

	symbol_name = malloc(symbol_name_size);
	if (!symbol_name)
		die_out_of_memory();

	if (unw_init_remote(&cursor, libunwind_as, tcp->libunwind_ui) < 0)
		perror_msg_and_die("Can't initiate libunwind");

	do {
		/* looping on the stack frame */
		if (unw_get_reg(&cursor, UNW_REG_IP, &ip) < 0)
			perror_msg_and_die("Can't walk the stack of process %d",
				tcp->pid);

		lower = 0;
		upper = tcp->mmap_cache_size - 1;


		while (lower <= upper) {
			/* find the mmap_cache and print the stack frame */
			mid = (int)((upper + lower) / 2);
			cur_mmap_cache = &tcp->mmap_cache[mid];
			
			if (ip >= cur_mmap_cache->start_addr &&
				ip < cur_mmap_cache->end_addr) {
			
				do {
					symbol_name[0] = '\0';
					ret_val = unw_get_proc_name(&cursor, symbol_name,
						symbol_name_size, &function_off_set);
					if ( ret_val != -UNW_ENOMEM )
						break;
					symbol_name_size *= 2;
					symbol_name = realloc(symbol_name, symbol_name_size);
					if ( !symbol_name )
						die_out_of_memory();
				} while (1);
				
				true_offset = ip - cur_mmap_cache->start_addr + cur_mmap_cache->mmap_offset;
				if (symbol_name[0]) {
					/*
					 * we want to keep the format used by backtrace_symbols from the glibc
					 *
					 * ./a.out() [0x40063d]
					 * ./a.out() [0x4006bb]
					 * ./a.out() [0x4006c6]
					 * /lib64/libc.so.6(__libc_start_main+0xed) [0x7fa2f8a5976d]
					 * ./a.out() [0x400569]
					 */
					tprintf(" > %s(%s+0x%lx) [0x%lx]\n", cur_mmap_cache->binary_filename,
						symbol_name, function_off_set, true_offset);
					line_ended();
				}
				else{
					tprintf(" > %s() [0x%lx]\n", cur_mmap_cache->binary_filename, true_offset);
					line_ended();
				}

				break; /* stack frame printed */
			}
			else if (ip < cur_mmap_cache->start_addr)
				upper = mid - 1;

			else
				lower = mid + 1;

		}
		if (lower > upper){
			tprintf(" > Unmapped_memory_area:0x%lx\n", ip);
			line_ended();
		}

		ret_val = unw_step(&cursor);

		if (++stack_depth > 255) {
			/* guard against bad unwind info in old libraries... */
			perror_msg("libunwind warning: too deeply nested---assuming bogus unwind\n");
			break;
		}
	} while (ret_val > 0);
}
