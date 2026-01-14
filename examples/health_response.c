#include <zeroserve.h>

static uint64_t floor_div(uint64_t a, uint64_t b) {
    // Floor division for possibly-negative a (b > 0).
    uint64_t q = a / b;
    uint64_t r = a % b;
    if (r != 0 && a < 0) q -= 1;
    return q;
}

static ZS_INLINE int year_from_unix_ms_fast(uint64_t unix_ms) {
    const uint64_t MS_PER_DAY = 86400000ULL;

    // Days since 1970-01-01, with correct behavior for negative timestamps too.
    uint64_t z = floor_div(unix_ms, MS_PER_DAY);

    // civil_from_days(z): z is days since 1970-01-01
    z += 719468;  // shift to days since 0000-03-01 (Gregorian), via a fixed offset

    uint64_t era = z / 146097;      // 400-year eras
    uint64_t doe = z - era * 146097; // [0, 146096]
    uint64_t yoe =
        (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;       // [0, 399]

    int y = (int)(yoe + (uint64_t)era * 400ULL);

    uint64_t doy = doe - (365ULL * yoe + yoe / 4 - yoe / 100); // [0, 365]
    uint64_t mp = (5ULL * doy + 2ULL) / 153ULL;                // [0, 11]
    unsigned int m = (unsigned int)(mp + (mp < 10 ? 3 : (uint64_t)-9)); // [1,12]

    // If month is Jan/Feb, it's actually in the next civil year relative to the March-based year.
    y += (m <= 2);

    return y;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));
  char body[256];

  if (zs_strcmp(path, "/health") == 0) {
    char *bp = zs_stpcpy(body, "{\"status\":\"ok\",\"year\":\"");
    bp += zs_utoa10(year_from_unix_ms_fast(zs_now_ms()), bp, 16);
    bp = zs_stpcpy(bp, "\"}\n");
    zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
    zs_respond(200, body, bp - body);
  }

  return 0;
}
