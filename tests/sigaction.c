#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

static void handle_signal(int no)
{
	_exit(128 + no);
}

int
main(void)
{
	struct sigaction sa, sa1, sa2, sa3;

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGHUP);
	sigaddset(&sa.sa_mask, SIGINT);
	sa.sa_flags = SA_RESTART;
	assert(!sigaction(SIGUSR2, &sa, &sa1));

	sa.sa_handler = handle_signal;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGQUIT);
	sigaddset(&sa.sa_mask, SIGTERM);
	sa.sa_flags = SA_SIGINFO;
	assert(!sigaction(SIGUSR2, &sa, &sa2));

	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	assert(!sigaction(SIGUSR2, &sa, &sa3));

	return 0;
}
