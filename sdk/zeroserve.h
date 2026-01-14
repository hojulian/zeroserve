#ifndef ZEROSERVE_SDK_ZEROSERVE_H
#define ZEROSERVE_SDK_ZEROSERVE_H

#define ZS_STR(s) (s), zs_strlen((s))
#define ZS_STR_WITH_NULL(s) (s), (zs_strlen((s)) + 1)

typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned short uint16_t;
typedef short int16_t;
typedef unsigned char uint8_t;
typedef char int8_t;
typedef unsigned long size_t;
typedef long ssize_t;

#define ZS_SECTION(name) __attribute__((section(name)))
#define ZS_ENTRY ZS_SECTION("zeroserve.request")
#define ZS_INLINE __attribute__((always_inline))
#define ZS_MIN(a, b) ((a) < (b) ? (a) : (b))
#define ZS_MAX(a, b) ((a) > (b) ? (a) : (b))

#define ZS_BASE64_STANDARD 0
#define ZS_BASE64_STANDARD_NO_PAD 1
#define ZS_BASE64_URL 2
#define ZS_BASE64_URL_NO_PAD 3

typedef uint64_t zs_u64;
typedef int64_t zs_s64;
typedef uint32_t zs_u32;
typedef int32_t zs_s32;
typedef uint16_t zs_u16;
typedef int16_t zs_s16;
typedef uint8_t zs_u8;
typedef int8_t zs_s8;

extern zs_s64 zs_log(const char *msg, zs_u64 len);
extern zs_u64 zs_now_ms(void);
extern zs_s64 zs_getrandom(void *out, zs_u64 out_len);
extern zs_s64 zs_hmac_sha256(const void *key, zs_u64 key_len, const void *msg,
                             zs_u64 msg_len, void *out);
extern zs_s64 zs_base64_encode(const void *data, zs_u64 data_len, void *out,
                               zs_u64 out_len, zs_u64 encoding);
extern zs_s64 zs_base64_decode_in_place(void *buf, zs_u64 buf_len,
                                        zs_u64 encoding);

extern zs_s64 zs_json_parse(const void *data, zs_u64 data_len);
extern zs_s64 zs_load_static_json(const char *path, zs_u64 path_len);
extern zs_s64 zs_json_reset(zs_u64 json);
extern zs_s64 zs_json_get(zs_u64 json, const char *key, zs_u64 key_len);
extern zs_s64 zs_json_array_get(zs_u64 json, zs_u64 array_index);
extern zs_s64 zs_json_read_string(zs_u64 json, char *out, zs_u64 out_len);
extern zs_s64 zs_json_read_i64(zs_u64 json, void *out, zs_u64 out_len);
extern zs_s64 zs_json_read_bool(zs_u64 json, void *out, zs_u64 out_len);
extern zs_s64 zs_object_free(zs_u64 idx);

extern zs_s64 zs_req_method(char *out, zs_u64 out_len);
extern zs_s64 zs_req_path(char *out, zs_u64 out_len);
extern zs_s64 zs_req_uri(char *out, zs_u64 out_len);
extern zs_s64 zs_req_set_uri(const char *uri, zs_u64 uri_len);
extern zs_s64 zs_req_query(char *out, zs_u64 out_len);
extern zs_s64 zs_req_scheme(char *out, zs_u64 out_len);
extern zs_s64 zs_req_peer(char *out, zs_u64 out_len);
extern zs_s64 zs_req_header(const char *name, zs_u64 name_len, char *out,
                            zs_u64 out_len);
extern zs_s64 zs_req_set_header(const char *name, zs_u64 name_len,
                                const char *value, zs_u64 value_len);
extern zs_s64 zs_req_query_param(const char *name, zs_u64 name_len, char *out,
                                 zs_u64 out_len);

extern zs_s64 zs_meta_get(const char *key, zs_u64 key_len, char *out,
                          zs_u64 out_len);
extern zs_s64 zs_meta_set(const char *key, zs_u64 key_len, const char *value,
                          zs_u64 value_len);

extern zs_s64 zs_respond(zs_u64 status, const void *body, zs_u64 body_len);

extern zs_s64 zs_reverse_proxy(const char *backend_url, zs_u64 backend_url_len);

extern void *zs_memcpy(void *dst, const void *src, size_t n);
extern int zs_memcmp(const void *a, const void *b, size_t n);
extern void *zs_memset(void *dst, int c, size_t n);

static __attribute__((unused)) ZS_INLINE char *
zs_strncpy(char *dst, const char *src, size_t n) {
  size_t i = 0;

  for (; i < n && src[i] != '\0'; i++)
    dst[i] = src[i];
  for (; i < n; i++)
    dst[i] = '\0';
  return dst;
}

static __attribute__((unused)) ZS_INLINE char *zs_strcpy(char *dst,
                                                         const char *src) {
  size_t i = 0;

  while (src[i] != '\0') {
    dst[i] = src[i];
    i++;
  }
  dst[i] = '\0';
  return dst;
}

static __attribute__((unused)) ZS_INLINE char *zs_stpcpy(char *dst,
                                                         const char *src) {
  size_t i = 0;

  while (src[i] != '\0') {
    dst[i] = src[i];
    i++;
  }
  dst[i] = '\0';
  return dst + i;
}

static __attribute__((unused)) ZS_INLINE int zs_strcmp(const char *a,
                                                       const char *b) {
  size_t i = 0;

  while (a[i] != '\0' && b[i] != '\0') {
    if (a[i] != b[i])
      return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
    i++;
  }
  return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
}

static __attribute__((unused)) ZS_INLINE int
zs_strncmp(const char *a, const char *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (a[i] != b[i])
      return (int)(unsigned char)a[i] - (int)(unsigned char)b[i];
    if (a[i] == '\0')
      return 0;
  }
  return 0;
}

static __attribute__((unused)) ZS_INLINE char *
zs_strrchr(const char *s, int c) {
  const char *last = 0;
  char target = (char)c;

  for (;;) {
    if (*s == target)
      last = s;
    if (*s == '\0')
      break;
    s++;
  }

  return (char *)last;
}

static __attribute__((unused)) ZS_INLINE size_t zs_strlen(const char *s) {
  size_t len = 0;

  while (s[len] != '\0')
    len++;
  return len;
}

static __attribute__((unused)) ZS_INLINE int
zs_utoa10(unsigned int value, char *out, size_t out_size) {
  /* Need at least 2 bytes for "0" + '\0' */
  if (!out || out_size < 2)
    return -1;

  /* Special case: value == 0 */
  if (value == 0) {
    out[0] = '0';
    out[1] = '\0';
    return 1;
  }

  /* First, count digits */
  unsigned int tmp = value;
  size_t digits = 0;
  while (tmp > 0) {
    tmp /= 10;
    digits++;
  }

  /* Ensure buffer can hold digits + null terminator */
  if (digits + 1 > out_size)
    return -1;

  /* Write digits from the end */
  out[digits] = '\0';
  size_t i = digits;
  while (value > 0) {
    unsigned int digit = value % 10;
    value /= 10;
    out[--i] = (char)('0' + digit);
  }

  return (int)digits;
}

#endif
