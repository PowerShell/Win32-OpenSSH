#include <Windows.h>

/* child processes */
#define MAX_CHILDREN 50
struct _children {
	/* 
	 * array of handles and process_ids. 
	 * intial (num_children - num_zombies) are alive 
	 * rest are zombies 
	 */
	HANDLE handles[MAX_CHILDREN];
	DWORD process_id[MAX_CHILDREN];
	/* total children */
	DWORD num_children;
	/* #zombies */
	/* (num_children - zombies) are live children */
	DWORD num_zombies;
};


int sw_initialize();
int register_child(HANDLE child, DWORD pid);
int sw_remove_child_at_index(DWORD index);
int sw_child_to_zombie(DWORD index);
void sw_cleanup_child_zombies();

struct _timer_info {
	HANDLE timer;
	ULONGLONG ticks_at_start; /* 0 if timer is not live */
	__int64 run_time_sec; /* time in seconds, timer is set to go off from ticks_at_start */
};
int sw_init_timer();
