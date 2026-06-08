#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char exec_id[256];
    zs_s64 exec_id_len = zs_req_header("x-execution-id", 14,
                                        exec_id, sizeof(exec_id));
    char vm_id[256];
    zs_s64 vm_id_len   = zs_req_header("x-microvm-id", 12,
                                        vm_id, sizeof(vm_id));

    /* Both headers are required */
    if (exec_id_len <= 0 || vm_id_len <= 0) {
        const char msg[] = "x-execution-id and x-microvm-id are required\n";
        zs_respond(400, msg, sizeof(msg) - 1);
        return 0;
    }

    /* Look up backend URL by execution_id */
    char backend_url[512];
    zs_s64 url_len = zs_kv_get(exec_id, (zs_u64)exec_id_len,
                                backend_url, sizeof(backend_url));
    if (url_len <= 0) {
        const char msg[] = "no backend for execution_id\n";
        zs_respond(503, msg, sizeof(msg) - 1);
        return 0;
    }

    zs_reverse_proxy(backend_url, (zs_u64)url_len);
    return 0;
}
