/* -------------------------------------------------------------------------
 * apt_guard.c
 * -----------
 * Infallible version for APT Detection.
 * -------------------------------------------------------------------------
 */

#define _GNU_SOURCE
#include "postgres.h"
#include "fmgr.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "utils/builtins.h"
#include "lib/stringinfo.h"
#include "pgstat.h"
#include "portability/instr_time.h"
#include "miscadmin.h"
#include "tcop/utility.h"
#include "nodes/nodes.h"
#include <string.h>

PG_MODULE_MAGIC;

/* Global variables */
static ExecutorRun_hook_type prev_ExecutorRun = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;
static int nest_level = 0;

/* Prototypes */
void _PG_init(void);
void _PG_fini(void);
static void apt_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction, uint64 count
#if PG_VERSION_NUM < 160000
    , bool execute_once
#endif
);
static void apt_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
                               bool readOnlyTree, ProcessUtilityContext context,
                               ParamListInfo params, QueryEnvironment *queryEnv,
                               DestReceiver *dest, QueryCompletion *qc);
static void simple_hash(const char *str, char *out);
static void log_apt_event(const char *queryText, const char *cmd, uint64 rows, double duration_ms);
static bool is_internal_query(const char *queryText);

/* 
 * Infallible internal query check.
 */
static bool
is_internal_query(const char *queryText)
{
    if (queryText == NULL) return true;
    
    /* Using strcasestr to avoid any manual loops or allocations */
    if (strcasestr(queryText, "apt_events") || 
        strcasestr(queryText, "apt_sessions") || 
        strcasestr(queryText, "apt_alerts"))
        return true;
        
    return false;
}

static void
simple_hash(const char *str, char *out)
{
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    sprintf(out, "%016lx", hash);
}

/* Logging function */
static void
log_apt_event(const char *queryText, const char *cmd, uint64 rows, double duration_ms)
{
    int ret;
    StringInfoData buf;
    char hash_str[17];

    /* Absolute safety */
    if (nest_level > 1 || is_internal_query(queryText))
        return;

    simple_hash(queryText, hash_str);

    PG_TRY();
    {
        if ((ret = SPI_connect()) == SPI_OK_CONNECT)
        {
            initStringInfo(&buf);
            appendStringInfo(&buf, 
                "INSERT INTO apt_events (session_id, command_type, rows_affected, query_hash, duration_ms) "
                "VALUES (%d, '%s', %llu, '%s', %.3f);",
                MyProcPid, cmd, (unsigned long long)rows, hash_str, duration_ms
            );

            SPI_execute(buf.data, false, 0);
            SPI_finish();
            pfree(buf.data);
        }
    }
    PG_CATCH();
    {
        /* Silently fail on logging error to prevent crash */
        SPI_finish();
    }
    PG_END_TRY();
}

static void
apt_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction, uint64 count
#if PG_VERSION_NUM < 160000
                , bool execute_once
#endif
)
{
    instr_time  start, duration;
    const char *cmd;

    /* 1. INFALLIBLE FILTER - If it is our table, skip EVERYTHING entirely */
    if (is_internal_query(queryDesc->sourceText))
    {
        if (prev_ExecutorRun)
#if PG_VERSION_NUM < 160000
            prev_ExecutorRun(queryDesc, direction, count, execute_once);
#else
            prev_ExecutorRun(queryDesc, direction, count);
#endif
        else
#if PG_VERSION_NUM < 160000
            standard_ExecutorRun(queryDesc, direction, count, execute_once);
#else
            standard_ExecutorRun(queryDesc, direction, count);
#endif
        return;
    }

    /* 2. RECURSION GUARD */
    if (nest_level > 0)
    {
        if (prev_ExecutorRun)
#if PG_VERSION_NUM < 160000
            prev_ExecutorRun(queryDesc, direction, count, execute_once);
#else
            prev_ExecutorRun(queryDesc, direction, count);
#endif
        else
#if PG_VERSION_NUM < 160000
            standard_ExecutorRun(queryDesc, direction, count, execute_once);
#else
            standard_ExecutorRun(queryDesc, direction, count);
#endif
        return;
    }

    nest_level++;
    INSTR_TIME_SET_CURRENT(start);

    PG_TRY();
    {
        if (prev_ExecutorRun)
#if PG_VERSION_NUM < 160000
            prev_ExecutorRun(queryDesc, direction, count, execute_once);
#else
            prev_ExecutorRun(queryDesc, direction, count);
#endif
        else
#if PG_VERSION_NUM < 160000
            standard_ExecutorRun(queryDesc, direction, count, execute_once);
#else
            standard_ExecutorRun(queryDesc, direction, count);
#endif

        INSTR_TIME_SET_CURRENT(duration);
        INSTR_TIME_SUBTRACT(duration, start);

        cmd = (queryDesc->operation == CMD_SELECT ? "SELECT" : 
               queryDesc->operation == CMD_INSERT ? "INSERT" :
               queryDesc->operation == CMD_UPDATE ? "UPDATE" :
               queryDesc->operation == CMD_DELETE ? "DELETE" : "OTHER");

        log_apt_event(queryDesc->sourceText, cmd, count, INSTR_TIME_GET_MILLISEC(duration));
    }
    PG_FINALLY();
    {
        nest_level--;
    }
    PG_END_TRY();
}

static void
apt_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
                   bool readOnlyTree, ProcessUtilityContext context,
                   ParamListInfo params, QueryEnvironment *queryEnv,
                   DestReceiver *dest, QueryCompletion *qc)
{
    instr_time  start, duration;
    uint64      rows = 0;
    const char *cmd = "UTILITY";

    /* 1. INFALLIBLE FILTER */
    if (is_internal_query(queryString))
    {
        if (prev_ProcessUtility)
            prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        else
            standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        return;
    }

    /* 2. RECURSION GUARD */
    if (nest_level > 0)
    {
        if (prev_ProcessUtility)
            prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        else
            standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        return;
    }

    nest_level++;
    INSTR_TIME_SET_CURRENT(start);

    PG_TRY();
    {
        if (prev_ProcessUtility)
            prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        else
            standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);

        INSTR_TIME_SET_CURRENT(duration);
        INSTR_TIME_SUBTRACT(duration, start);

        if (pstmt->utilityStmt)
        {
            NodeTag tag = nodeTag(pstmt->utilityStmt);
            if (tag == T_CopyStmt) cmd = "COPY";
            else if (tag == T_AlterTableStmt) cmd = "ALTER";
            else if (tag == T_CreateStmt) cmd = "CREATE";
            else if (tag == T_DropStmt) cmd = "DROP";
            else if (tag == T_GrantStmt) cmd = "GRANT";
        }

        if (qc) rows = qc->nprocessed;

        log_apt_event(queryString, cmd, rows, INSTR_TIME_GET_MILLISEC(duration));
    }
    PG_FINALLY();
    {
        nest_level--;
    }
    PG_END_TRY();
}

void
_PG_init(void)
{
    prev_ExecutorRun = ExecutorRun_hook;
    ExecutorRun_hook = (ExecutorRun_hook_type) apt_ExecutorRun;

    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = (ProcessUtility_hook_type) apt_ProcessUtility;
}

void
_PG_fini(void)
{
    ExecutorRun_hook = prev_ExecutorRun;
    ProcessUtility_hook = prev_ProcessUtility;
}
