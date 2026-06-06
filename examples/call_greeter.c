/*
 * call_greeter.c — a callee script.
 *
 * It exports no request entrypoint; instead it exposes a single inter-script
 * call, "greet", in the "zeroserve.call.greet" code section. Another script
 * invokes it with:
 *
 *   zs_call(ZS_STR("call_greeter"), ZS_STR("greet"), payload);
 *
 * Input:  {"name": "<string>"}   (defaults to "world" when absent)
 * Output: {"greeting": "Hello, <name>!"}
 */
#include <zeroserve.h>

ZS_CALL(greet) {
  char name[128];
  name[0] = '\0';

  zs_s64 name_node = zs_json_get(json_handle, ZS_STR("name"));
  if (name_node >= 0) {
    zs_json_read_string(name_node, name, sizeof(name));
    zs_object_free(name_node);
  }
  if (name[0] == '\0')
    zs_strcpy(name, "world");

  char greeting[160];
  char *p = zs_stpcpy(greeting, "Hello, ");
  p = zs_stpcpy(p, name);
  zs_stpcpy(p, "!");

  zs_s64 out = zs_json_new_object();
  zs_s64 value = zs_json_new_object();
  zs_json_set_string(value, ZS_STR(greeting));
  zs_json_set(out, ZS_STR("greeting"), value);
  zs_object_free(value);

  return out;
}
