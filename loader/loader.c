/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <fcntl.h> // FOR open()
#include <unistd.h> // FOR close()
#include <signal.h> 
#include <sys/mman.h>
#include <sys/stat.h>

#include "exec_parser.h"

static so_exec_t *exec;
static int fd;
static int size;
static int sad; 

// Data is represented by marking maped pages.
static int* my_data;


int my_min(int a, int b) {
	return (a < b)? a : b;
}

/* Handler used for SIGSEGV signal (DEFAULT ACTIONS FOR SEGMENTATION FAULT SIGNAL)
	sig = number of signal which caused handler invocation
	info = pointer to siginfo_t structure which contains further signal info (check man)
	ucontext = pointer to ucontext_t structures, casted to void*, represents user context */

void segv_handler(int sig, siginfo_t *info, void *ucontext) {

	/* Default page fault handler case for other signals, exit(179) causes normal process termination */
	if(sig != SIGSEGV){
		exit(139);
		return;
	}

	// Iterating through segments in ELF file
	for(int i = 0; i < exec->segments_no; i++) {
		so_seg_t *s = &exec->segments[i]; 		// current segment
		int sig_address = (int)info->si_addr; 	// adress which causes signal
		int page_size = getpagesize(); 

		// Verify if signal is not within a segment of the executable
		sad = 1;
		if (sig_address > s->mem_size + s->vaddr || sig_address < s->vaddr)
				sad = 0;

		else
		{
			// s->vaddr = beggining address of segment
			int page_number = (sig_address - s->vaddr) / page_size; 

			if(s->data == NULL)
				s->data = calloc(s->mem_size / page_size + 1, 4); // calloc makes every value in data 0

			my_data = (int*)(s->data);

			// If page is already mapped, we run default handler (no access permision)
			if(my_data[page_number] == 1)
					exit(139);

			int align_down = ALIGN_DOWN((uintptr_t)sig_address, page_size) - s->vaddr;
			int align_up = align_down + page_size;

			/* Set memory in VAS with writing permissions. Later, we change page permissions to segment permissions with mprotect.
			Creates link between VAS and physical space. We also initialize everything with 0 with memset. */
			char *mmap_ret = mmap((int*)(align_down + s->vaddr), page_size, PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANON, 0, 0);	
			memset(mmap_ret, 0, page_size);


			// Mark mapped page
			my_data[page_number] = 1;
				
			/* BSS CASE: If what we read from file does not reach page size, 
						we fill the rest with 0 until the page is full or until mem_size. */

			size = 0;
			if((int)align_down < s->file_size)
				{
					if(align_up > s->file_size)
						size = s->file_size - (int)align_down;
					else 
						size = page_size;
					//size = my_min(s->file_size - align_down, page_size);
				}

			for(int i = size; i < page_size - size; i++)
				my_data[i] = 0;

			// Set offset to current page. 
			lseek(fd, s->offset + (int)align_down, SEEK_SET);
			
			// Read data from a certain segment portion
			read(fd, (void*) mmap_ret, size);
			// Set page permissions from writing permissions to segment permissions.
			mprotect(mmap_ret, page_size, s->perm);
			return;
		}
	}
	// Runs default handler case in case signal is outside segment
	if(sad == 0) exit(139);
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	fd = open(path, O_RDONLY);
	if(fd == -1)
		return -1;
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);
	close(fd);
	return -1;
}
