#include <Windows.h>
#include "inc\defs.h"


int sw_initialize();
sighandler_t sw_signal(int signum, sighandler_t handler);
int sw_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int sw_raise(int sig);
int sw_kill(int pid, int sig);

/* child processes */
#define MAX_CHILDREN 50
struct _children {
	HANDLE handles[MAX_CHILDREN];
	DWORD process_id[MAX_CHILDREN];
	/* total children */
	DWORD num_children;
	/* #zombies */
	/* (num_chileren - zombies) are live children */
	DWORD num_zombies;
};

int sw_add_child(HANDLE child, DWORD pid);
int sw_remove_child_at_index(DWORD index);
int sw_child_to_zombie(DWORD index);
int sw_remove_child(HANDLE child);
void sw_cleanup_child_zombies();

struct _timer_info {
	HANDLE timer;
	ULONGLONG ticks_at_start; /* 0 if timer is not live */
	__int64 run_time_sec; /* time in seconds, timer is set to go off from ticks_at_start */
};
int sw_init_timer();
unsigned int sw_alarm(unsigned int seconds);