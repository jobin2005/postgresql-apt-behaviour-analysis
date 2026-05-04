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
#include "executor/spi.h"
#include "utils/builtins.h"
#include "lib/stringinfo.h"

PG_MODULE_MAGIC;

static bool in_logger = false;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;

void _PG_init(void);
void _PG_fini(void);

static void
apt_ExecutorRun(QueryDesc *queryDesc,
                ScanDirection direction,
                uint64 count,
                bool execute_once)
{
    /* 
     * Capture the Query and the current Process PID.
     */
    int pid = MyProcPid;
    const char *query = queryDesc->sourceText;

    /* RECURSION GUARD: Don't log our own logging queries! */
    if (query != NULL && !in_logger) 
    {
        in_logger = true;

        PG_TRY();
        {
            int ret;
            StringInfoData buf;

            /* SPI LOGGING */
            if ((ret = SPI_connect()) == SPI_OK_CONNECT)
            {
                initStringInfo(&buf);
                
                /* Construct the internal logging query */
                appendStringInfo(&buf, 
                    "INSERT INTO apt_events (session_id, command_type, rows_affected, query_hash, duration_ms) "
                    "VALUES (1, '%s', %llu, 'hash_placeholder', 0.1);",
                    (queryDesc->operation == CMD_SELECT ? "SELECT" : 
                     queryDesc->operation == CMD_INSERT ? "INSERT" :
                     queryDesc->operation == CMD_UPDATE ? "UPDATE" :
                     queryDesc->operation == CMD_DELETE ? "DELETE" : "OTHER"),
                    (unsigned long long) count
                );

                ret = SPI_execute(buf.data, false, 0);
                
                SPI_finish();
                pfree(buf.data);
            }
        }
        PG_CATCH();
        {
            /* If an error occurs, we must ensure in_logger is reset */
            in_logger = false;
            PG_RE_THROW();
        }
        PG_END_TRY();

        in_logger = false;
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
     * NOTE: Currently disabled because apt_main is not yet defined.
     */
    /*
    memset(&worker, 0, sizeof(worker));
    sprintf(worker.bgw_name, "APT Guard Monitor");
    worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
    worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
    worker.bgw_restart_time = BGW_NEVER_RESTART;
    sprintf(worker.bgw_library_name, "apt_guard");
    sprintf(worker.bgw_function_name, "apt_main");
    worker.bgw_notify_pid = 0;

    RegisterBackgroundWorker(&worker);
    */
}

void
_PG_fini(void)
{
    ExecutorRun_hook = prev_ExecutorRun;
}
