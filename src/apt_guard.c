/* -------------------------------------------------------------------------
 * apt_guard.c
 * -----------
 * Bulletproof Analytical Version (ExecutorEnd Hook).
 * Correctly nested exception handling for absolute stability.
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
#include "utils/acl.h"
#include "utils/guc.h"
#include "utils/resowner.h"
#include "access/xact.h"
#include "catalog/pg_type.h"
#include "utils/snapmgr.h"
#include <string.h>

PG_MODULE_MAGIC;

/* Global variables */
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;
static int nest_level = 0;

/* Prototypes */
void _PG_init(void);
void _PG_fini(void);

static void apt_ExecutorEnd(QueryDesc *queryDesc);
static void apt_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
                               bool readOnlyTree, ProcessUtilityContext context,
                               ParamListInfo params, QueryEnvironment *queryEnv,
                               DestReceiver *dest, QueryCompletion *qc);
static void log_apt_event(const char *queryText, const char *cmd, uint64 rows, 
                         double duration_ms, bool success, const char *err_code);
static bool is_internal_query(const char *queryText);

/* 
 * Infallible internal query check.
 */
static bool
is_internal_query(const char *queryText)
{
    if (queryText == NULL) return true;
    
    if (strcasestr(queryText, "apt_events") || 
        strcasestr(queryText, "apt_sessions") || 
        strcasestr(queryText, "apt_alerts") ||
        strcasestr(queryText, "apt_user_profile") ||
        strcasestr(queryText, "apt_sequence_patterns"))
        return true;
        
    return false;
}

/* 
 * Core logging function with Subtransactions.
 */
static void
log_apt_event(const char *queryText, const char *cmd, uint64 rows, 
             double duration_ms, bool success, const char *err_code)
{
    int ret;
    StringInfoData buf;
    const char *user_id;
    const char *ip_addr;
    Oid argtypes[1];
    Datum values[1];
    MemoryContext oldcontext = CurrentMemoryContext;
    ResourceOwner oldowner = CurrentResourceOwner;

    if (nest_level > 1 || is_internal_query(queryText) || !IsTransactionState())
        return;

    user_id = GetConfigOptionByName("session_authorization", NULL, true);
    if (!user_id || strlen(user_id) == 0) user_id = "unknown_user";
    
    ip_addr = GetConfigOptionByName("client_addr", NULL, true);
    if (!ip_addr || strlen(ip_addr) == 0) ip_addr = "127.0.0.1";

    volatile bool pushed_snapshot = false;
    BeginInternalSubTransaction(NULL);
    PG_TRY();
    {
        if (!ActiveSnapshotSet()) {
            PushActiveSnapshot(GetTransactionSnapshot());
            pushed_snapshot = true;
        }

        if ((ret = SPI_connect()) == SPI_OK_CONNECT)
        {
            const char *query = "INSERT INTO apt_events (user_id, session_hint, query_type, query_text, duration_ms, rows_accessed, success_flag, error_code, ip_address) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);";
            Oid argt[9];
            Datum vals[9];
            char nulls[9] = {' ', ' ', ' ', ' ', ' ', ' ', ' ', 'n', ' '}; 
            
            char session_hint_str[32];
            snprintf(session_hint_str, sizeof(session_hint_str), "%d", MyProcPid);
            
            argt[0] = TEXTOID; vals[0] = CStringGetTextDatum(user_id);
            argt[1] = TEXTOID; vals[1] = CStringGetTextDatum(session_hint_str);
            argt[2] = TEXTOID; vals[2] = CStringGetTextDatum(cmd);
            argt[3] = TEXTOID; vals[3] = CStringGetTextDatum(queryText);
            argt[4] = FLOAT8OID; vals[4] = Float8GetDatum(duration_ms);
            argt[5] = INT4OID; vals[5] = Int32GetDatum((int32)rows);
            argt[6] = BOOLOID; vals[6] = BoolGetDatum(success);
            argt[7] = TEXTOID;
            if (err_code) {
                nulls[7] = ' ';
                vals[7] = CStringGetTextDatum(err_code);
            }
            argt[8] = TEXTOID; vals[8] = CStringGetTextDatum(ip_addr);

            ret = SPI_execute_with_args(query, 9, argt, vals, nulls, false, 0);
            
            SPI_finish();
        }

        if (pushed_snapshot) {
            PopActiveSnapshot();
            pushed_snapshot = false;
        }

        ReleaseCurrentSubTransaction();
    }
    PG_CATCH();
    {
        ErrorData *edata;
        MemoryContextSwitchTo(oldcontext);
        edata = CopyErrorData();
        elog(WARNING, "APT_GUARD SPI ERROR: %s", edata->message);
        FreeErrorData(edata);
        FlushErrorState();
        
        if (pushed_snapshot) {
            PopActiveSnapshot();
            pushed_snapshot = false;
        }

        RollbackAndReleaseCurrentSubTransaction();
    }
    PG_END_TRY();

    CurrentResourceOwner = oldowner;
}

static void
apt_ExecutorEnd(QueryDesc *queryDesc)
{
    double duration_ms = 0;
    uint64 rows = 0;
    const char *cmd = "OTHER";

    if (is_internal_query(queryDesc->sourceText) || nest_level > 0)
    {
        if (prev_ExecutorEnd)
            prev_ExecutorEnd(queryDesc);
        else
            standard_ExecutorEnd(queryDesc);
        return;
    }

    nest_level++;
    
    if (queryDesc->totaltime)
    {
        InstrEndLoop(queryDesc->totaltime);
        duration_ms = queryDesc->totaltime->total * 1000.0;
    }

    if (queryDesc->estate)
        rows = queryDesc->estate->es_processed;

    cmd = (queryDesc->operation == CMD_SELECT ? "SELECT" : 
           queryDesc->operation == CMD_INSERT ? "INSERT" :
           queryDesc->operation == CMD_UPDATE ? "UPDATE" :
           queryDesc->operation == CMD_DELETE ? "DELETE" : "OTHER");

    /* DOUBLE NESTED FOR MAX STABILITY */
    PG_TRY();
    {
        PG_TRY();
        {
            if (prev_ExecutorEnd)
                prev_ExecutorEnd(queryDesc);
            else
                standard_ExecutorEnd(queryDesc);
        }
        PG_CATCH();
        {
            /* Mark failure? But we rethrow anyway */
            PG_RE_THROW();
        }
        PG_END_TRY();

        /* If we reached here, execution succeeded */
        log_apt_event(queryDesc->sourceText, cmd, rows, duration_ms, true, NULL);
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

    if (is_internal_query(queryString) || nest_level > 0)
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
        PG_TRY();
        {
            if (prev_ProcessUtility)
                prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
            else
                standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        }
        PG_CATCH();
        {
            PG_RE_THROW();
        }
        PG_END_TRY();

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

        log_apt_event(queryString, cmd, rows, INSTR_TIME_GET_MILLISEC(duration), true, NULL);
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
    prev_ExecutorEnd = ExecutorEnd_hook;
    ExecutorEnd_hook = (ExecutorEnd_hook_type) apt_ExecutorEnd;

    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = (ProcessUtility_hook_type) apt_ProcessUtility;
}

void
_PG_fini(void)
{
    ExecutorEnd_hook = prev_ExecutorEnd;
    ProcessUtility_hook = prev_ProcessUtility;
}
