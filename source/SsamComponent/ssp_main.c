/*****************************************************************************
 * Copyright 2021 Liberty Global B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ****************************************************************************/

#ifdef __GNUC__
#if (!defined _NO_EXECINFO_H_)
#include <execinfo.h>
#endif
#endif

#include <semaphore.h>
#include <fcntl.h>
#include "ssp_global.h"
#include "stdlib.h"
#include "ccsp_dm_api.h"
#include "safec_lib_common.h"
#include "cosa_apis_ssamagentplugin.h"

#define DEBUG_INI_NAME "/etc/debug.ini"

extern char *pComponentName;
extern ANSC_HANDLE bus_handle;

char g_Subsystem[32] = { 0 };
static sem_t *sem;

int cmd_dispatch(int command)
{
    switch (command) {
        case 'e':
            {
                char CName[256];
                CcspTraceInfo(("Connect to bus daemon...\n"));
                sprintf(CName, "%s%s", g_Subsystem, CCSP_COMPONENT_ID_SSAMAGENT);
                ssp_Mbi_MessageBusEngage(CName, CCSP_MSG_BUS_CFG, CCSP_COMPONENT_PATH_SSAMAGENT);
                ssp_create();
                ssp_engage();
            }
            break;

        case 'm':
            AnscPrintComponentMemoryTable(pComponentName);
            break;

        case 't':
            AnscTraceMemoryTable();
            break;

        case 'c':
            ssp_cancel();
            break;

        default:
            break;
    }

    return 0;
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#if (!defined _NO_EXECINFO_H_)
    void *tracePtrs[100];
    char **funcNames = NULL;
    int i, count = 0;

    count = backtrace(tracePtrs, 100);
    backtrace_symbols_fd(tracePtrs, count, 2);

    funcNames = backtrace_symbols(tracePtrs, count);

    if (funcNames) {
        // Print the stack trace
        for (i = 0; i < count; i++)
            printf("%s\n", funcNames[i]);

        // Free the string pointers
        free(funcNames);
    }
#endif
#endif
}

static void daemonize(void)
{
    int fd;

    /* initialize semaphores for shared processes */
    sem = sem_open("pSemSsam", O_CREAT | O_EXCL, 0644, 0);
    if (SEM_FAILED == sem) {
        AnscTrace("Failed to create semaphore %d - %s\n", errno, strerror(errno));
        _exit(1);
    }
    /* name of semaphore is "pSemSsam", semaphore is reached using this name */
    sem_unlink("pSemSsam");
    /* unlink prevents the semaphore existing forever */
    /* if a crash occurs during the execution         */
    AnscTrace("Semaphore initialization Done!!\n");

    switch (fork()) {
        case 0:
            break;
        case -1:
            CcspTraceInfo(("Error daemonizing (fork)! %d - %s\n", errno, strerror(errno)));
            exit(0);
            break;
        default:
            sem_wait(sem);
            sem_close(sem);
            _exit(0);
    }

    if (setsid() < 0) {
        CcspTraceInfo(("Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
        exit(0);
    }

#ifndef _DEBUG
    fd = open("/dev/null", O_RDONLY);
    if (fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) {
        dup2(fd, 2);
        close(fd);
    }
#endif
}

void sig_handler(int sig)
{
    if (sig == SIGINT) {
        signal(SIGINT, sig_handler);    /* reset it to this function */
        CcspTraceInfo(("SIGINT received!\n"));
        exit(0);
    } else if (sig == SIGUSR1) {
        signal(SIGUSR1, sig_handler);   /* reset it to this function */
        CcspTraceInfo(("SIGUSR1 received!\n"));
    } else if (sig == SIGUSR2) {
        CcspTraceInfo(("SIGUSR2 received!\n"));
    } else if (sig == SIGCHLD) {
        signal(SIGCHLD, sig_handler);   /* reset it to this function */
        CcspTraceInfo(("SIGCHLD received!\n"));
    } else if (sig == SIGPIPE) {
        signal(SIGPIPE, sig_handler);   /* reset it to this function */
        CcspTraceInfo(("SIGPIPE received!\n"));
    } else {
        /* get stack trace first */
        _print_stack_backtrace();
        CcspTraceInfo(("Signal %d received, exiting!\n", sig));
        exit(0);
    }
}

int main(int argc, char *argv[])
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    BOOL bRunAsDaemon = TRUE;
    int idx = 0;
    FILE *fd = NULL;

    char *subSys = NULL;
    DmErr_t err;
    int ind = -1;

    // Buffer characters till newline for stdout and stderr
    setlinebuf(stdout);
    setlinebuf(stderr);

    for (idx = 1; idx < argc; idx++) {
        if (strcmp(argv[idx], "-subsys") == 0) {
            if (idx + 1 < argc) {
                size_t len = strlen(argv[idx + 1]);
                if (len >= sizeof(g_Subsystem)) {
                    return ANSC_STATUS_FAILURE;
                }
                memcpy(g_Subsystem, argv[idx + 1], len + 1);
            } else {
                fprintf(stderr, "Option -subsys requires an argument\n");
                return ANSC_STATUS_FAILURE;
            }
        }
        else if (strcmp(argv[idx], "-c") == 0) {
            bRunAsDaemon = FALSE;
        }
    }

    pComponentName = CCSP_COMPONENT_NAME_SSAMAGENT;

    if (bRunAsDaemon)
        daemonize();

    fd = fopen("/var/tmp/ssam_agent.pid", "w+");
    if (!fd) {
        CcspTraceWarning(("Create /var/tmp/ssam_agent.pid error. \n"));
        return 1;
    }

    fprintf(fd, "%d", getpid());
    fclose(fd);

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    /*signal(SIGCHLD, sig_handler); */
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGKILL, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGHUP, sig_handler);

    cmd_dispatch('e');

    ssam_start();

#ifdef _COSA_SIM_
    subSys = "";        /* PC simu use empty string as subsystem */
#else
    subSys = NULL;      /* use default sub-system */
#endif
    err = Cdm_Init(bus_handle, subSys, NULL, NULL, pComponentName);
    if (err != CCSP_SUCCESS) {
        fprintf(stderr, "Cdm_Init: %s\n", Cdm_StrError(err));
        exit(1);
    }

#ifdef FEATURE_SUPPORT_RDKLOG
    RDK_LOGGER_INIT();
#endif

    system("touch /tmp/ssamagent_initialized");

    if (bRunAsDaemon) {
        sem_post(sem);
        sem_close(sem);
        while (1) {
            sleep(30);
        }
    } else {
        int cmdChar = 0;
        while (cmdChar != 'q') {
            cmdChar = getchar();
            cmd_dispatch(cmdChar);
        }
    }

    err = Cdm_Term();
    if (err != CCSP_SUCCESS) {
        fprintf(stderr, "Cdm_Term: %s\n", Cdm_StrError(err));
        exit(1);
    }

    ssp_cancel();

    return 0;
}
