/*
 * call_gateway.c — a caller script.
 *
 * Handles the HTTP request, delegates greeting construction to another script
 * (call_greeter) over an inter-script call, and returns that script's JSON
 * reply to the client. Reads the greeting subject from the "name" query
 * parameter, e.g. GET /?name=ada -> {"greeting":"Hello, ada!"}.
 */
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char name[128];
  zs_s64 got = zs_req_query_param(ZS_STR("name"), name, sizeof(name));
  if (got <= 0 || name[0] == '\0')
    zs_strcpy(name, "world");

  zs_s64 payload = zs_json_new_object();
  zs_s64 name_value = zs_json_new_object();
  zs_json_set_string(name_value, ZS_STR(name));
  zs_json_set(payload, ZS_STR("name"), name_value);
  zs_object_free(name_value);

  zs_s64 reply = zs_call(ZS_STR("call_greeter"), ZS_STR("greet"), payload);
  zs_object_free(payload);

  if (reply < 0) {
    zs_respond(502, ZS_STR("{\"error\":\"greeter call failed\"}"));
    return 0;
  }

  zs_json_respond(200, reply);
  zs_object_free(reply);
  return 0;
}
