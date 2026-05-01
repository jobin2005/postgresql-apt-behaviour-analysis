/* -------------------------------------------------------------------------
 * apt_guard.c
 * -----------
 * A PostgreSQL extension that implements a "Security Brain" for APT 
 * detection. 
 *
 * This extension:
 * 1. Hooks into the query executor to capture SQL event sequences.
 * 2. Launches a Background Worker (BGW) to run the DQL monitor.
 * 3. Bridges the DB Session with the Linux Process Descriptor (task_struct).
 * -------------------------------------------------------------------------
 */

#include "postgres.h"
#include "fmgr.h"
#include "executor/executor.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "utils/guc.h"
#include "miscadmin.h"

PG_MODULE_MAGIC;

void _PG_init(void);
void _PG_fini(void);

/* Hook for query execution */
static ExecutorRun_hook_type prev_ExecutorRun = NULL;

static void
apt_ExecutorRun(QueryDesc *queryDesc,
                ScanDirection direction,
                uint64 count,
                bool execute_once)
{
    /* 
     * TOP POINT IMPLEMENTATION:
     * Capture the Query and the current Process PID to send to 
     * the DQL Behavioral Agent.
     */
    int pid = MyProcPid;
    const char *query = queryDesc->sourceText;

    /* VERIFICATION LOG: This will show up in your PostgreSQL server logs */
    if (query != NULL) {
        elog(INFO, "[APT-GUARD] Intercepted Query (PID: %d): %s", pid, query);
    }

    if (prev_ExecutorRun)
        prev_ExecutorRun(queryDesc, direction, count, execute_once);
    else
        standard_ExecutorRun(queryDesc, direction, count, execute_once);
}

void
_PG_init(void)
{
    BackgroundWorker worker;

    /* Register the hook */
    prev_ExecutorRun = ExecutorRun_hook;
    ExecutorRun_hook = (ExecutorRun_hook_type) apt_ExecutorRun;

    /* 
     * Launch Background Worker (APT DQL Monitor)
     */
    memset(&worker, 0, sizeof(worker));
    sprintf(worker.bgw_name, "APT Guard Monitor");
    worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
    worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
    worker.bgw_restart_time = BGW_NEVER_RESTART;
    sprintf(worker.bgw_library_name, "apt_guard");
    sprintf(worker.bgw_function_name, "apt_main");
    worker.bgw_notify_pid = 0;

    RegisterBackgroundWorker(&worker);
}

void
_PG_fini(void)
{
    ExecutorRun_hook = prev_ExecutorRun;
}
