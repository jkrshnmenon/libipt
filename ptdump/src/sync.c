#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/shm.h>
#include "intel-pt.h"
#include "afl_hash.h"

#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define FORKSRV_FD          198
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

#define CRASH_EXITCODE		"AFL_CRASH_EXITCODE"
int crash_exitcode = 0;

void fuzzme() {
        char buf[10];
        read(0, buf, 10);
        printf("%s\n", buf);
        return;
}

char dummy[MAP_SIZE] = {}
char *trace_map = &dummy;
unsigned int prev_id = 0;
size_t afl_prev_loc = 0;


int map_shm() {
	char *shm_env_var = getenv(SHM_ENV_VAR);
	if (shm_env_var == NULL) {
		printf("SHM_ENV_VAR not set\n");
		return -1;
	}
	int shm_id = atoi(shm_env_var);
	trace_map = (char*)shmat(shm_id, NULL, 0);

	if(trace_map == (char*)-1) {
		perror("shmat_attach");
		return -1;
	}

	char *exit_codestr = getenv(CRASH_EXITCODE);
	if ( exit_codestr != NULL ) {
		crash_exitcode = atoi(exit_codestr);
	}
	return 0;
}


int init_trace_map() {
	int i = 0, n = 0;
	int __afl_temp_data = 0;
	pid_t __afl_fork_pid = getpid();
	for ( i = 0; i < 2; i++) {

		n = read(FORKSRV_FD,&__afl_temp_data,4);
		if(n != 4) {
			perror("Error reading fork server\n");
			return -1;
		}

		if ( i % 2 == 0) 
			trace_map[MAP_SIZE-1]++;
		else
			trace_map[MAP_SIZE-1]--;

		n = write(FORKSRV_FD+1,&__afl_fork_pid, 4);
		n = write(FORKSRV_FD+1,&__afl_temp_data,4);
	}
	return 0;
}


int wakeup() {
	int __afl_temp_data = 0;

	int n = write(FORKSRV_FD+1, &__afl_temp_data,4);
	if(n != 4) {
		return -1;
	}
}


pt_export int syn() {
	int __afl_temp_data = 0;
	int n = read(FORKSRV_FD,&__afl_temp_data,4);
	if ( n != 4 ) {
		perror("Error reading fork server\n");
		return -1;
	}
	return 0;
}


pt_export int ack(int crash) {
	int __afl_temp_data = 0;
	if ( crash == 1 ) {
		__afl_temp_data = crash_exitcode;
	}

	pid_t __afl_fork_pid = getpid();
	int n = write(FORKSRV_FD+1,&__afl_fork_pid, 4);

	n = write(FORKSRV_FD+1,&__afl_temp_data,4);
	return 0;
}

pt_export void update_bb(size_t cur_loc) {
	cur_loc = (uintptr_t)(afl_hash_ip((uint64_t)cur_loc));
	cur_loc &= (MAP_SIZE - 1);

	uintptr_t afl_idx = cur_loc ^ afl_prev_loc;
	trace_map[afl_idx]++;

	afl_prev_loc = cur_loc >> 1;
}

pt_export int logbb(unsigned int id) {
	trace_map[prev_id ^ id]++;
	prev_id = id >> 1;
	return 0;
}



pt_export int initialize() {
	if (map_shm() == -1)
		return -1;
	if (wakeup() == -1)
		return -1;
	if (init_trace_map() == -1)
		return -1;

	return 0;
}

/*
void sync_maps() {
	sync_bitmap(trace_map);
}

int wrapper_do_main(char *filename) {
	do_main(filename);
}
*/
