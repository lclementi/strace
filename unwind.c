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
#include <limits.h>
#include <libunwind-ptrace.h>

#define DPRINTF(F, A, ...) if (debug_flag) fprintf(stderr, "[unwind:" A " {" F "}]\n", __VA_ARGS__);

/*
 * Кeep a sorted array of cache entries,
 * so that we can binary search through it.
 */
static unsigned int mmap_cache_generation;
struct mmap_cache_t {
	/**
	 * example entry:
	 * 7fabbb09b000-7fabbb09f000 r--p 00179000 fc:00 1180246 /lib/libc-2.11.1.so
	 *
	 * start_addr  is 0x7fabbb09b000
	 * end_addr    is 0x7fabbb09f000
	 * mmap_offset is 0x179000
	 * binary_filename is "/lib/libc-2.11.1.so"
	 */
	unsigned long start_addr;
	unsigned long end_addr;
	unsigned long mmap_offset;
	char *binary_filename;
};

/*
 * Keep a captured stracktrace.
 */
struct call_t {
	struct call_t* next;
	char *output_line;
};

struct queue_t {
	struct call_t *tail;
	struct call_t *head;
};
typedef void (*call_action_fn)(void *data,
			       char *binary_filename,
			       char *symbol_name,
			       unw_word_t function_off_set,
			       unsigned long true_offset);
typedef void (*error_action_fn)(void *data,
				const char *error,
				unsigned long true_offset);

static unw_addr_space_t libunwind_as;

static void
init_unwind_addr_space(void)
{
	libunwind_as = unw_create_addr_space(&_UPT_accessors, 0);
	if (!libunwind_as)
		error_msg_and_die("failed to create address space for stack tracing");
}

static void
init_libunwind_ui(struct tcb *tcp)
{
	tcp->libunwind_ui = _UPT_create(tcp->pid);
	if (!tcp->libunwind_ui)
		die_out_of_memory();
}

static void
free_libunwind_ui(struct tcb *tcp)
{
	_UPT_destroy(tcp->libunwind_ui);
	tcp->libunwind_ui = NULL;
}

/*
 * caching of /proc/ID/maps for each process to speed up stack tracing
 *
 * The cache must be refreshed after some syscall: mmap, mprotect, munmap, execve
 */
/* deleting the cache */
static void
delete_mmap_cache(struct tcb *tcp, const char* caller)
{
	unsigned int i;

	DPRINTF("gen=%u, GEN=%u, tcp=%p, cache=%p, at=%s", "delete",
		tcp->mmap_cache_generation,
		mmap_cache_generation,
		tcp, tcp->mmap_cache, caller);

	for (i = 0; i < tcp->mmap_cache_size; i++) {
		free(tcp->mmap_cache[i].binary_filename);
		tcp->mmap_cache[i].binary_filename = NULL;
	}
	free(tcp->mmap_cache);
	tcp->mmap_cache = NULL;
	tcp->mmap_cache_size = 0;
}

static void
build_mmap_cache(struct tcb *tcp)
{
	unsigned long start_addr, end_addr, mmap_offset;
	char filename[sizeof ("/proc/0123456789/maps")];
	char buffer[PATH_MAX + 80];
	char binary_path[PATH_MAX];
	size_t blen;
	struct mmap_cache_t *cur_entry, *prev_entry;
	/* start with a small dynamically-allocated array and then expand it */
	size_t cur_array_size = 10;
	struct mmap_cache_t *cache_head;
	FILE *fp;

	sprintf(filename, "/proc/%d/maps", tcp->pid);
	fp = fopen(filename, "r");
	if (!fp) {
		perror_msg("fopen: %s", filename);
		return;
	}

	cache_head = calloc(cur_array_size, sizeof(*cache_head));
	if (!cache_head)
		die_out_of_memory();

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		binary_path[0] = '\0'; // 'reset' it just to be paranoid

		sscanf(buffer, "%lx-%lx %*c%*c%*c%*c %lx %*x:%*x %*d %[^\n]",
		       &start_addr, &end_addr, &mmap_offset, binary_path);

		/* ignore special 'fake files' like "[vdso]", "[heap]", "[stack]", */
		if (binary_path[0] == '[')
			continue;

		if (binary_path[0] == '\0')
			continue;

		/* ignore deleted file. */
		blen = strlen(binary_path);
		if (blen >= 10 && strcmp(binary_path + blen - 10, " (deleted)") == 0)
			continue;

		if (end_addr < start_addr)
			perror_msg_and_die("%s: unrecognized maps file format",
					   filename);

		cur_entry = &cache_head[tcp->mmap_cache_size];
		cur_entry->start_addr = start_addr;
		cur_entry->end_addr = end_addr;
		cur_entry->mmap_offset = mmap_offset;
		cur_entry->binary_filename = strdup(binary_path);

		/*
		 * sanity check to make sure that we're storing
		 * non-overlapping regions in ascending order
		 */
		if (tcp->mmap_cache_size > 0) {
			prev_entry = &cache_head[tcp->mmap_cache_size - 1];
			if (prev_entry->start_addr >= cur_entry->start_addr)
				perror_msg_and_die("Overlaying memory region in %s",
						   filename);
			if (prev_entry->end_addr > cur_entry->start_addr)
				perror_msg_and_die("Overlaying memory region in %s",
						   filename);
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
	fclose(fp);
	tcp->mmap_cache = cache_head;
	tcp->mmap_cache_generation = mmap_cache_generation;

	DPRINTF("gen=%u, GEN=%u, tcp=%p, cache=%p", "build",
		tcp->mmap_cache_generation,
		mmap_cache_generation,
		tcp, tcp->mmap_cache);
}

static bool
is_mmap_cache_available(struct tcb *tcp, const char *caller)
{
	if ((tcp->mmap_cache_generation != mmap_cache_generation)
	    && tcp->mmap_cache)
		delete_mmap_cache(tcp, caller);

	if (!tcp->mmap_cache)
		build_mmap_cache(tcp);

	if (!tcp->mmap_cache || !tcp->mmap_cache_size)
		return false;
	else
		return true;
}


/*
 * stack entry formatter
 */
#define STACK_ENTRY_SYMBOL_FMT			\
	" > %s(%s+0x%lx) [0x%lx]\n",		\
	binary_filename,			\
	symbol_name,				\
	function_off_set,			\
	true_offset
#define STACK_ENTRY_NOSYMBOL_FMT		\
	" > %s() [0x%lx]\n",			\
	binary_filename, true_offset
#define STACK_ENTRY_BUG_FMT			\
	" > BUG IN %s\n"
#define STACK_ENTRY_ERROR_WITH_OFFSET_FMT	\
	" > %s [0x%lx]\n", error, true_offset
#define STACK_ENTRY_ERROR_FMT			\
	" > %s [0x%lx]\n", error, true_offset

#define OUTPUT_LINE_BUFLEN 128
static char*
sprint_call_or_error(char *binary_filename,
		     char *symbol_name,
		     unw_word_t function_off_set,
		     unsigned long true_offset,
		     const char *error)
{
	int n;
	char *output_line;
	unsigned int buflen;

	n = (OUTPUT_LINE_BUFLEN - 1);
	output_line = NULL;

	do {
		buflen = n + 1;
		output_line = realloc(output_line, buflen);
		if (!output_line)
			die_out_of_memory();

		if (symbol_name)
			n = snprintf(output_line, buflen, STACK_ENTRY_SYMBOL_FMT);
		else if (binary_filename)
			n = snprintf(output_line, buflen, STACK_ENTRY_NOSYMBOL_FMT);
		else if (error)
			n = true_offset
				? snprintf(output_line, buflen, STACK_ENTRY_ERROR_WITH_OFFSET_FMT)
				: snprintf(output_line, buflen, STACK_ENTRY_ERROR_FMT);
		else
			n = snprintf(output_line, buflen, STACK_ENTRY_BUG_FMT, __FUNCTION__);

		if (n < 0)
			error_msg_and_die("error in snrpintf");
	} while(n >= buflen);

	return output_line;
}

static void
print_call(char *binary_filename,
	   char *symbol_name,
	   unw_word_t function_off_set,
	   unsigned long true_offset)
{
	if (symbol_name)
		tprintf(STACK_ENTRY_SYMBOL_FMT);
	else if (binary_filename)
		tprintf(STACK_ENTRY_NOSYMBOL_FMT);
	else
		tprintf(STACK_ENTRY_BUG_FMT, __FUNCTION__);

	line_ended();
}

static void
print_error(const char *error,
	    unsigned long true_offset)
{
	if (true_offset)
		tprintf(STACK_ENTRY_ERROR_WITH_OFFSET_FMT);
	else
		tprintf(STACK_ENTRY_ERROR_FMT);

	line_ended();
}

/*
 * Queue releated functions
 */
static void
queue_put(struct queue_t *queue,
	  char *binary_filename,
	  char *symbol_name,
	  unw_word_t function_off_set,
	  unsigned long true_offset,
	  const char *error)
{
	struct call_t *call;

	call = malloc(sizeof(*call));
	if (!call)
		die_out_of_memory();

	call->output_line = sprint_call_or_error(binary_filename,
						 symbol_name,
						 function_off_set,
						 true_offset,
						 error);
	call->next = NULL;

	if (!queue->head) {
		queue->head = call;
		queue->tail = call;
	} else {
		queue->tail->next = call;
		queue->tail = call;
	}
}

static void
queue_put_call(void *queue,
	       char *binary_filename,
	       char *symbol_name,
	       unw_word_t function_off_set,
	       unsigned long true_offset)
{
	queue_put(queue,
		  binary_filename,
		  symbol_name,
		  function_off_set,
		  true_offset,
		  NULL);
}

static void
queue_put_error(void *queue,
		const char *error,
		unw_word_t ip)
{
	queue_put(queue, NULL, NULL, 0, ip, error);
}

static void
queue_free(struct queue_t *queue,
	  void (* callback)(const char *output_line))
{
	struct call_t *call, *tmp;

	queue->tail = NULL;
	call = queue->head;
	queue->head = NULL;
	while (call) {
		tmp = call;
		call = call->next;

		if (callback)
			callback(tmp->output_line);

		free(tmp->output_line);
		tmp->output_line = NULL;
		tmp->next = NULL;
		free(tmp);
	}
}

static void
queue_printline(const char *output_line)
{
	tprints(output_line);
	line_ended();
}

static void
queue_print_and_free(struct tcb *tcp)
{

	DPRINTF("tcp=%p, queue=%p", "queueprint", tcp, tcp->queue->head);
	queue_free(tcp->queue, queue_printline);
}

static void
stacktrace_walk(struct tcb *tcp,
		call_action_fn call_action,
		error_action_fn error_action,
		void *data)
{
	unw_word_t ip;
	unw_cursor_t cursor;
	unw_word_t function_off_set;
	int stack_depth = 0, ret_val;
	/* these are used for the binary search through the mmap_chace */
	unsigned int lower, upper, mid;
	size_t symbol_name_size = 40;
	char *symbol_name;
	struct mmap_cache_t *cur_mmap_cache;
	unsigned long true_offset;


	symbol_name = malloc(symbol_name_size);
	if (!symbol_name)
		die_out_of_memory();

	if (unw_init_remote(&cursor, libunwind_as, tcp->libunwind_ui) < 0)
		perror_msg_and_die("Can't initiate libunwind");

	do {
		/* looping on the stack frame */
		if (unw_get_reg(&cursor, UNW_REG_IP, &ip) < 0) {
			perror_msg("Can't walk the stack of process %d", tcp->pid);
			break;
		}

		lower = 0;
		upper = tcp->mmap_cache_size - 1;

		while (lower <= upper) {
			/* find the mmap_cache and print the stack frame */
			mid = (upper + lower) / 2;
			cur_mmap_cache = &tcp->mmap_cache[mid];

			if (ip >= cur_mmap_cache->start_addr &&
			    ip < cur_mmap_cache->end_addr) {
				for (;;) {
					symbol_name[0] = '\0';
					ret_val = unw_get_proc_name(&cursor, symbol_name,
						symbol_name_size, &function_off_set);
					if (ret_val != -UNW_ENOMEM)
						break;
					symbol_name_size *= 2;
					symbol_name = realloc(symbol_name, symbol_name_size);
					if (!symbol_name)
						die_out_of_memory();
				}

				true_offset = ip - cur_mmap_cache->start_addr +
					cur_mmap_cache->mmap_offset;
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
					call_action(data,
						    cur_mmap_cache->binary_filename,
						    symbol_name,
						    function_off_set,
						    true_offset);
				} else {
					call_action(data,
						    cur_mmap_cache->binary_filename,
						    symbol_name,
						    0,
						    true_offset);
				}
				break; /* stack frame printed */
			}
			else if (mid == 0) {
				if(ip)
					error_action(data,
						     "backtracing_error", 0);
				goto ret;
			}
			else if (ip < cur_mmap_cache->start_addr)
				upper = mid;
			else
				lower = mid + 1;

		}
		if (lower > upper) {
			error_action(data,
				     "backtracing_error", ip);
			goto ret;
		}

		ret_val = unw_step(&cursor);

		if (++stack_depth > 255) {
			error_action(data,
				     "too many stack frames", 0);
			break;
		}
	} while (ret_val > 0);
ret:
	free(symbol_name);
}

static void
stacktrace_capture(struct tcb *tcp)
{
	stacktrace_walk(tcp, queue_put_call, queue_put_error,
			tcp->queue);
}


static void
print_call_cb(void *dummy,
	      char *binary_filename,
	      char *symbol_name,
	      unw_word_t function_off_set,
	      unsigned long true_offset)
{
	print_call(binary_filename,
		   symbol_name,
		   function_off_set,
		   true_offset);
}

static void
print_error_cb(void *dummy,
	       const char *error,
	       unsigned long true_offset)
{
	print_error(error, true_offset);
}

static void
stacktrace_print(struct tcb *tcp)
{
	DPRINTF("tcp=%p, queue=%p", "stackprint", tcp, tcp->queue->head);
	stacktrace_walk(tcp, print_call_cb, print_error_cb, NULL);
}

/*
 *  Exported functions
 *  use libunwind to unwind the stack and print a backtrace
 */
void
unwind_init(void)
{
	init_unwind_addr_space();
}

void
unwind_tcb_init(struct tcb *tcp)
{
	init_libunwind_ui(tcp);
	tcp->queue = malloc(sizeof(*tcp->queue));
	if (!tcp->queue)
		die_out_of_memory();
	tcp->queue->head = NULL;
	tcp->queue->tail = NULL;
}

void
unwind_tcb_fin(struct tcb *tcp)
{
	if ((tcp->s_ent != NULL) && (tcp->s_ent->sys_flags & STACKTRACE_CAPTURE_IN_ENTERING))
		queue_print_and_free(tcp);
	else
		queue_free(tcp->queue, NULL);
	free(tcp->queue);
	tcp->queue = NULL;

	delete_mmap_cache(tcp, __FUNCTION__);
	free_libunwind_ui(tcp);

}

void
unwind_cache_invalidate(struct tcb *tcp)
{
	mmap_cache_generation++;
	DPRINTF("gen=%u, GEN=%u, tcp=%p, cache=%p", "increment",
		tcp->mmap_cache_generation,
		mmap_cache_generation,
		tcp,
		tcp->mmap_cache);
}

void
unwind_stacktrace_capture(struct tcb *tcp)
{
	queue_free(tcp->queue, NULL);

	if (is_mmap_cache_available(tcp, __FUNCTION__)) {
		stacktrace_capture(tcp);
		DPRINTF("tcp=%p, queue=%p", "captured", tcp, tcp->queue->head);
	}
}

void
unwind_stacktrace_print(struct tcb *tcp)
{
	if (tcp->s_ent->sys_flags & STACKTRACE_CAPTURE_IN_ENTERING)
		queue_print_and_free(tcp);
	else if (is_mmap_cache_available(tcp, __FUNCTION__))
		stacktrace_print(tcp);
}
