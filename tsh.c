/*
 * tsh - A tiny shell program with job control
 *
 * <Wang, Chen 16307110064>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

/* Misc manifest constants */
#define MAXLINE    1024   /* max line size */
#define MAXARGS     128   /* max args on a command line */
#define MAXJOBS      16   /* max jobs at any point in time */
#define MAXJID    1<<16   /* max job ID */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

/*
 * Jobs states: FG (foreground), BG (background), ST (stopped)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

/* Global variables */
/*
 * A customized variable fg_stop_or_exit is defined here as a
 * global variable. Meanwhile, it is declared as volatile sig_atomic_t,
 * whose usage is according to the GUIDELINES 4&5 in the Safe signal handling
 * subsection in section 8.5.5 of the textbook.
 * The use of this variable is to determine whether the signal that caused the stopping
 * is a foreground process or not and this variable is used in sigchld_handler function.
 * */
extern char **environ;      /* defined in libc */
char prompt[] = "tsh> ";    /* command line prompt (DO NOT CHANGE) */
int verbose = 0;            /* if true, print additional output */
int nextjid = 1;            /* next job ID to allocate */
char sbuf[MAXLINE];         /* for composing sprintf messages */

struct job_t {              /* The job struct */
    pid_t pid;              /* job PID */
    int jid;                /* job ID [1, 2, ...] */
    int state;              /* UNDEF, BG, FG, or ST */
    char cmdline[MAXLINE];  /* command line */
};
struct job_t jobs[MAXJOBS]; /* The job list */
volatile sig_atomic_t fg_stop_or_exit;
/* End global variables */


/* Function prototypes */

/* Here are the functions that you will implement */
void eval(char *cmdline);

int builtin_cmd(char **argv);

void do_bgfg(char **argv);

void waitfg(pid_t pid);

void sigchld_handler(int sig);

void sigtstp_handler(int sig);

void sigint_handler(int sig);

/* Here are helper routines that we've provided for you */
int parseline(const char *cmdline, char **argv);

void sigquit_handler(int sig);

void clearjob(struct job_t *job);

void initjobs(struct job_t *jobs);

int maxjid(struct job_t *jobs);

int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);

int deletejob(struct job_t *jobs, pid_t pid);

pid_t fgpid(struct job_t *jobs);

struct job_t *getjobpid(struct job_t *jobs, pid_t pid);

struct job_t *getjobjid(struct job_t *jobs, int jid);

int pid2jid(pid_t pid);

void listjobs(struct job_t *jobs);

void usage(void);

void unix_error(char *msg);

void app_error(char *msg);

typedef void handler_t(int);

handler_t *Signal(int signum, handler_t *handler);

/*
 * main - The shell's main routine
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE];
    int emit_prompt = 1; /* emit prompt (default) */

    /* Redirect stderr to stdout (so that driver will get all output
     * on the pipe connected to stdout) */
    dup2(1, 2);

    /* Parse the command line */
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
            case 'h':             /* print help message */
                usage();
                break;
            case 'v':             /* emit additional diagnostic info */
                verbose = 1;
                break;
            case 'p':             /* don't print a prompt */
                emit_prompt = 0;  /* handy for automatic testing */
                break;
            default:
                usage();
        }
    }

    /* Install the signal handlers */

    /* These are the ones you will need to implement */
    Signal(SIGINT, sigint_handler);   /* ctrl-c */
    Signal(SIGTSTP, sigtstp_handler);  /* ctrl-z */
    Signal(SIGCHLD, sigchld_handler);  /* Terminated or stopped child */

    /* This one provides a clean way to kill the shell */
    Signal(SIGQUIT, sigquit_handler);

    /* Initialize the job list */
    initjobs(jobs);

    /* Execute the shell's read/eval loop */
    while (1) {

        /* Read command line */
        if (emit_prompt) {
            printf("%s", prompt);
            fflush(stdout);
        }
        if ((fgets(cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
            app_error("fgets error");
        if (feof(stdin)) { /* End of file (ctrl-d) */
            fflush(stdout);
            exit(0);
        }

        /* Evaluate the command line */
        eval(cmdline);
        fflush(stdout);
        fflush(stdout);
    }

    exit(0); /* control never reaches here */
}

/*
 * eval - Evaluate the command line that the user has just typed in
 *
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.
*/
void eval(char *cmdline) {
/*
 * Variable Initialization, the first four variables are defined
 * according to the textbook and the last collection is used for
 * signal blocking
 * */
    char *argv[MAXARGS];   /* argv for execve() */
    char buf[MAXLINE];     /* Holds modified command line */
    int bg;                /* should the job run in bg or fg? */
    pid_t pid;        /* process id */
    sigset_t mask_all, mask_one, mask_prev;

    /*Sets the blocking collection*/
    sigemptyset(&mask_one);
    sigaddset(&mask_one, SIGCHLD);
    sigfillset(&mask_all);

    /*Get the bg/fg status and the modified argv*/
    strcpy(buf, cmdline);
    bg = parseline(buf, argv) ? BG : FG;

    /*Built in command */
    if (!builtin_cmd(argv)) {
        /*
         * This part should be skipped if it is a built-in command, otherwise 
         * the signal should be blocked and then execute the executable file.
         * */
        sigprocmask(SIG_BLOCK, &mask_one, &mask_prev);
        if ((pid = fork()) == 0) {

            /* In the child process */
            sigprocmask(SIG_SETMASK, &mask_prev, NULL);

            /* Change the group id of the child process. The second argument 0
             * enables the child process to have a group id different from the 
             * shell process.*/
            setpgid(0, 0);

            if (execve(argv[0], argv, environ) < 0)
                printf("%s: Command not found.\n", argv[0]);

            /* Exit the child process. */
            exit(0);
        }

        /* Blocking signal is necessary during the process of add job to 
         * successfully add the job into the list.*/
        sigprocmask(SIG_BLOCK, &mask_all, NULL);
        addjob(jobs, pid, bg, cmdline);
        sigprocmask(SIG_SETMASK, &mask_one, NULL);

        /* Wait for foreground tasks or put tasks into background*/
        if (bg == FG)
            waitfg(pid);
        else {
            /* Print the info of background tasks*/
            sigprocmask(SIG_BLOCK, &mask_all, NULL);
            struct job_t *currentBgProcess = getjobpid(jobs, pid);
            printf("[%d] (%d) %s", currentBgProcess->jid, currentBgProcess->pid, currentBgProcess->cmdline);
        }

        /* Remove the blocks*/
        sigprocmask(SIG_SETMASK, &mask_prev, NULL);
    }
}

/*
 * parseline - Parse the command line and build the argv array.
 *
 * Characters enclosed in single quotes are treated as a single
 * argument.  Return true if the user has requested a BG job, false if
 * the user has requested a FG job.
 */
int parseline(const char *cmdline, char **argv) {
    static char array[MAXLINE]; /* holds local copy of command line */
    char *buf = array;          /* ptr that traverses command line */
    char *delim;                /* points to first space delimiter */
    int argc;                   /* number of args */
    int bg;                     /* background job? */

    strcpy(buf, cmdline);
    buf[strlen(buf) - 1] = ' ';  /* replace trailing '\n' with space */
    while (*buf && (*buf == ' ')) /* ignore leading spaces */
        buf++;

    /* Build the argv list */
    argc = 0;
    if (*buf == '\'') {
        buf++;
        delim = strchr(buf, '\'');
    } else {
        delim = strchr(buf, ' ');
    }

    while (delim) {
        argv[argc++] = buf;
        *delim = '\0';
        buf = delim + 1;
        while (*buf && (*buf == ' ')) /* ignore spaces */
            buf++;

        if (*buf == '\'') {
            buf++;
            delim = strchr(buf, '\'');
        } else {
            delim = strchr(buf, ' ');
        }
    }
    argv[argc] = NULL;

    if (argc == 0)  /* ignore blank line */
        return 1;

    /* should the job run in the background? */
    if ((bg = (*argv[argc - 1] == '&')) != 0) {
        argv[--argc] = NULL;
    }
    return bg;
}

/*
 * builtin_cmd - If the user has typed a built-in command then execute
 *    it immediately.
 */
int builtin_cmd(char **argv) {

    /* Mask initialization */
    sigset_t mask_all, mask_prev;
    sigfillset(&mask_all);

    if (!strcmp(argv[0], "quit")) /* quit command */
        exit(0);
    else if (strcmp(argv[0], "fg") == 0 || strcmp(argv[0], "bg") == 0) {
        do_bgfg(argv);
        return 1;
    } else if (!strcmp(argv[0], "jobs")) {

        /* Block signal before reading global variables*/
        sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
        listjobs(jobs);
        sigprocmask(SIG_SETMASK, &mask_prev, NULL);
        return 1;
    }
    return 0;     /* not a builtin command */
}

/*
 * do_bgfg - Execute the builtin bg and fg commands
 */
void do_bgfg(char **argv) {
    int pid, jid;
    struct job_t *requestedJob;
    char *cmd = argv[0];
    sigset_t mask_all, mask_prev;
    if (!strcmp(cmd, "bg")) {
        /* ignore command if no argument */
        if (argv[1] == NULL) {
            printf("bg command requires PID or %%jobid argument\n");
            return;
        }
        if (argv[1][0] == '%') {
            jid = (int) strtol(&(argv[1][1]), NULL, 10);
            if (jid == 0) {
                printf("bg: argument must be a PID or %%jobid\n");
                fflush(stdout);
                return;
            }
            if (getjobjid(jobs, jid) == NULL) {
                printf("%%%d: No such job\n", jid);
                return;
            }
            pid = getjobjid(jobs, jid)->pid;
        } else {
            pid = (int) strtol(argv[1], NULL, 10);
            if (pid == 0) {
                printf("bg: argument must be a PID or %%jobid\n");
                fflush(stdout);
                return;
            }
        }

        sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
        if ((requestedJob = getjobpid(jobs, pid)) != NULL)
            switch (requestedJob->state) {
                case ST:
                    /* Change the state in the job list and send the signal to
                     * the child process. */
                    requestedJob->state = BG;
                    kill(-(requestedJob->pid), SIGCONT);
                    printf("[%d] (%d) %s", requestedJob->jid, requestedJob->pid, requestedJob->cmdline);
                    break;
                case BG:
                    /* Ignore the command if the child process is already in BG */
                    break;
                default:
                    unix_error("bg process error\n");
            }
        else
            printf("(%d): No such process\n", pid);
        sigprocmask(SIG_SETMASK, &mask_prev, NULL);

    } else {

        /* ignore command if no argument */
        if (argv[1] == NULL) {
            printf("fg command requires PID or %%jobid argument\n");
            return;
        }

        if (argv[1][0] == '%') {
            jid = (int) strtol(&(argv[1][1]), NULL, 10);
            if (jid == 0) {
                printf("fg: argument must be a PID or %%jobid\n");
                fflush(stdout);
                return;
            }
            if (getjobjid(jobs, jid) == NULL) {
                printf("%%%d: No such job\n", jid);
                return;
            }
            pid = getjobjid(jobs, jid)->pid;
        } else {
            pid = (int) strtol(argv[1], NULL, 10);
            if (pid == 0) {
                printf("fg: argument must be a PID or %%jobid\n");
                fflush(stdout);
                return;
            }
        }

        sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
        if ((requestedJob = getjobpid(jobs, pid)) != NULL)
            switch (requestedJob->state) {
                /* Continue the process if it is in stop mode. */
                case ST:
                    requestedJob->state = FG;
                    kill(-(requestedJob->pid), SIGCONT);
                    waitfg(requestedJob->pid);
                    break;
                    /* Bring the process to foreground if the process is in BG */
                case BG:
                    requestedJob->state = FG;
                    waitfg(requestedJob->pid);
                    break;
                default:
                    unix_error("fg process error\n");
            }
        else
            printf("(%d): No such process\n", pid);
        sigprocmask(SIG_SETMASK, &mask_prev, NULL);

    }
}

/*
 * waitfg - Block until process pid is no longer the foreground process
 */
void waitfg(pid_t pid) {
    //注意到，进来之间阻塞了SIGCHLD信号
    sigset_t mask;
    sigemptyset(&mask);
    //前台进程的pid和挂起标志
    //FGPID = 0;
    fg_stop_or_exit = 0;
    //让SIGCHLD信号处理程序处理任何子进程传回来的SIGCHLD信号，注意子进程挂起或者终止都会返回这个信号，所以信号处理程序需要区分，处理不同的情况
    //只有发出这个信号的子进程是前台进程才设置fg_stop_or_exit标志。
    while (!fg_stop_or_exit) {
        sigsuspend(&mask);
    }
}

/*****************
 * Signal handlers
 *****************/

/*
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, mask_prev;
    pid_t gc_pid;
    struct job_t *gc_job;
    int status;

    sigfillset(&mask_all);
    //尽可能的回收子进程,同时使用WNOHANG选项使得如果当前进程都没有终止时，直接返回，而不是挂起该回收进程。这样可能会阻碍无法两个短时间结束的后台进程
    //即trace05.txt
    while ((gc_pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
        gc_job = getjobpid(jobs, gc_pid);
        if (gc_pid == fgpid(jobs)) {
            fg_stop_or_exit = 1;
        }
        if (WIFSTOPPED(status)) {
            //子进程停止引起的waitpid函数返回,再判断该进程是否是前台进程
            //struct job_t* stop_job = getjobpid(jobs, gc_pid);
            gc_job->state = ST;
            printf("Job [%d] (%d) stopped by signal %d\n", gc_job->jid, gc_job->pid, WSTOPSIG(status));
        } else {
            //子进程终止引起的返回,判断是否是前台进程
            //并且判断该信号是否是未捕获的信号
            if (WIFSIGNALED(status)) {
                //struct job_t* gc_job = getjobpid(jobs, gc_pid);
                printf("Job [%d] (%d) terminated by signal %d\n", gc_job->jid, gc_job->pid, WTERMSIG(status));
            }
            //终止的进程直接回收
            deletejob(jobs, gc_pid);
        }
        fflush(stdout);
        sigprocmask(SIG_SETMASK, &mask_prev, NULL);
    }
    errno = olderrno;
}
/*
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.
 */
/*
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, mask_prev;
    pid_t curr_fg_pid;

    sigfillset(&mask_all);
    //访问全局结构体数组，阻塞信号
    sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
    curr_fg_pid = fgpid(jobs);
    sigprocmask(SIG_SETMASK, &mask_prev, NULL);

    if (curr_fg_pid != 0) {
        kill(-curr_fg_pid, SIGINT);
    }
    errno = olderrno;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, mask_prev;
    pid_t curr_fg_pid;

    sigfillset(&mask_all);

    sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
    curr_fg_pid = fgpid(jobs);
    sigprocmask(SIG_SETMASK, &mask_prev, NULL);

    if (curr_fg_pid != 0) {
        /* 臃肿的代码，保留了我调试的过程。
        fg_stop_or_exit = 1;
        sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
        struct job_t* stop_fgjob = getjobpid(jobs, curr_fg_pid);
        printf("Job [%d] (%d) stopped by signal 20\n", stop_fgjob->jid, stop_fgjob->pid);
        stop_fgjob->state = ST;
        sigprocmask(SIG_SETMASK, &mask_prev, NULL);
        */
        kill(-curr_fg_pid, SIGTSTP);
    }

    errno = olderrno;
}

/*********************
 * End signal handlers
 *********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job) {
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
        clearjob(&jobs[i]);
}

/* maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs) {
    int i, max = 0;

    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].jid > max)
            max = jobs[i].jid;
    return max;
}

/* addjob - Add a job to the job list */
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline) {
    int i;

    if (pid < 1)
        return 0;

    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid == 0) {
            jobs[i].pid = pid;
            jobs[i].state = state;
            jobs[i].jid = nextjid++;
            if (nextjid > MAXJOBS)
                nextjid = 1;
            strcpy(jobs[i].cmdline, cmdline);
            if (verbose) {
                printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
            }
            return 1;
        }
    }
    printf("Tried to create too many jobs\n");
    return 0;
}

/* deletejob - Delete a job whose PID=pid from the job list */
int deletejob(struct job_t *jobs, pid_t pid) {
    int i;

    if (pid < 1)
        return 0;

    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid == pid) {
            clearjob(&jobs[i]);
            nextjid = maxjid(jobs) + 1;
            return 1;
        }
    }
    return 0;
}

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].state == FG)
            return jobs[i].pid;
    return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid) {
    int i;

    if (pid < 1)
        return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid)
            return &jobs[i];
    return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid) {
    int i;

    if (jid < 1)
        return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].jid == jid)
            return &jobs[i];
    return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid) {
    int i;

    if (pid < 1)
        return 0;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid) {
            return jobs[i].jid;
        }
    return 0;
}

/* listjobs - Print the job list */
void listjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid != 0) {
            printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
            switch (jobs[i].state) {
                case BG:
                    printf("Running ");
                    break;
                case FG:
                    printf("Foreground ");
                    break;
                case ST:
                    printf("Stopped ");
                    break;
                default:
                    printf("listjobs: Internal error: job[%d].state=%d ",
                           i, jobs[i].state);
            }
            printf("%s", jobs[i].cmdline);
        }
    }
}
/******************************
 * end job list helper routines
 ******************************/


/***********************
 * Other helper routines
 ***********************/

/*
 * usage - print a help message
 */
void usage(void) {
    printf("Usage: shell [-hvp]\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("   -p   do not emit a command prompt\n");
    exit(1);
}

/*
 * unix_error - unix-style error routine
 */
void unix_error(char *msg) {
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

/*
 * app_error - application-style error routine
 */
void app_error(char *msg) {
    fprintf(stdout, "%s\n", msg);
    exit(1);
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler) {
    struct sigaction action, old_action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    action.sa_flags = SA_RESTART; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0)
        unix_error("Signal error");
    return (old_action.sa_handler);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 */
void sigquit_handler(int sig) {
    printf("Terminating after receipt of SIGQUIT signal\n");
    exit(1);
}