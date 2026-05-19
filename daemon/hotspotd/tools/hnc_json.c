/* HNC hotfix20.8 - optional hnc_json C helper.
 * Conservative helper: bin/hnc_json tries this helper first for selected
 * commands and falls back to the shell implementation on any failure.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static char *read_file(const char *p, size_t *n) {
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long l = ftell(f); fseek(f, 0, SEEK_SET);
    if (l < 0) { fclose(f); return NULL; }
    char *b = malloc((size_t)l + 1); if (!b) { fclose(f); return NULL; }
    size_t r = fread(b, 1, (size_t)l, f); fclose(f); b[r] = 0; if (n) *n = r; return b;
}
static int write_file(const char *p, const char *s) {
    char tmp[1024]; snprintf(tmp, sizeof(tmp), "%s.hnc_json_c.%ld.tmp", p, (long)getpid());
    FILE *f = fopen(tmp, "wb"); if (!f) return 1;
    fwrite(s, 1, strlen(s), f); fputc('\n', f); if (fclose(f) != 0) { unlink(tmp); return 1; }
    if (rename(tmp, p) != 0) { unlink(tmp); return 1; }
    return 0;
}
static int valid_json(const char *s) {
    int ins = 0, esc = 0, dep = 0, seen = 0;
    for (; *s; s++) { unsigned char c = (unsigned char)*s; if (ins) { if (esc) { esc = 0; continue; } if (c == '\\') { esc = 1; continue; } if (c == '"') { ins = 0; continue; } if (c < 32) return 1; continue; } if (isspace(c)) continue; seen = 1; if (c == '"') ins = 1; else if (c == '{' || c == '[') dep++; else if (c == '}' || c == ']') { if (--dep < 0) return 1; } }
    return (!seen || ins || esc || dep) ? 1 : 0;
}
static char *escstr(const char *v) {
    size_t cap = strlen(v) * 2 + 3, k = 0; char *o = malloc(cap); if (!o) return NULL; o[k++] = '"';
    for (; *v; v++) { unsigned char c = (unsigned char)*v; if (k + 4 >= cap) { cap *= 2; char *p = realloc(o, cap); if (!p) { free(o); return NULL; } o = p; } if (c == '\\' || c == '"') { o[k++] = '\\'; o[k++] = c; } else if (c >= 32) o[k++] = c; }
    o[k++] = '"'; o[k] = 0; return o;
}
static char *literal(const char *v, const char *t) {
    if (!t || !strcmp(t, "str") || !strcmp(t, "string")) return escstr(v);
    if (!strcmp(t, "bool") || !strcmp(t, "boolean")) return (!strcmp(v, "true") || !strcmp(v, "false")) ? strdup(v) : NULL;
    if (!strcmp(t, "null")) return !strcmp(v, "null") ? strdup("null") : NULL;
    if (!strcmp(t, "num") || !strcmp(t, "number")) return strdup(v);
    if (!strcmp(t, "json") || !strcmp(t, "raw")) return valid_json(v) == 0 ? strdup(v) : NULL;
    return NULL;
}
static char *join3(const char *a, size_t an, const char *m, const char *b) {
    size_t mn = strlen(m), bn = strlen(b); char *o = malloc(an + mn + bn + 1); if (!o) return NULL;
    memcpy(o, a, an); memcpy(o + an, m, mn); memcpy(o + an + mn, b, bn); o[an + mn + bn] = 0; return o;
}
static char *find_key(const char *s, const char *key, char **val, char **end) {
    char *k = escstr(key); if (!k) return NULL; size_t kn = strlen(k); char *p = s ? strstr((char *)s, k) : NULL; free(k); if (!p) return NULL;
    char *c = strchr(p + kn, ':'); if (!c) return NULL; c++; while (isspace((unsigned char)*c)) c++;
    int ins = 0, esc = 0, dep = 0; char *q = c; for (; *q; q++) { unsigned char ch = (unsigned char)*q; if (ins) { if (esc) { esc = 0; continue; } if (ch == '\\') { esc = 1; continue; } if (ch == '"') ins = 0; continue; } else { if (ch == '"') ins = 1; else if (ch == '{' || ch == '[') dep++; else if ((ch == ',' || ch == '}') && dep == 0) break; else if (ch == '}' || ch == ']') dep--; } }
    if (val) *val = c;
    if (end) *end = q;
    return p;
}
static int set_object_key(const char *file, const char *key, const char *v, const char *typ) {
    size_t n = 0; char *s = read_file(file, &n); if (!s) s = strdup("{}"); if (!s) return 1; if (valid_json(s)) { free(s); return 2; }
    char *lit = literal(v, typ); if (!lit) { free(s); return 2; }
    char *val = NULL, *end = NULL, *p = find_key(s, key, &val, &end), *out = NULL;
    if (p) out = join3(s, (size_t)(val - s), lit, end);
    else { char *k = escstr(key); if (!k) { free(s); free(lit); return 1; } char *r = strchr(s, '{'); if (!r) { free(k); free(s); free(lit); return 2; } char *q = r + 1; while (isspace((unsigned char)*q)) q++; int empty = (*q == '}'); size_t ml = strlen(k) + strlen(lit) + 4; char *m = malloc(ml); if (!m) { free(k); free(s); free(lit); return 1; } snprintf(m, ml, "%s:%s%s", k, lit, empty ? "" : ","); out = join3(s, (size_t)(r + 1 - s), m, r + 1); free(m); free(k); }
    free(s); free(lit); if (!out) return 1; int rc = valid_json(out) ? 1 : write_file(file, out); free(out); return rc;
}
static int del_object_key(const char *file, const char *key) {
    size_t n = 0; char *s = read_file(file, &n); if (!s) return 0; if (valid_json(s)) { free(s); return 2; }
    char *val = NULL, *end = NULL, *p = find_key(s, key, &val, &end); if (!p) { free(s); return 0; }
    char *after = end; while (isspace((unsigned char)*after)) after++; if (*after == ',') after++;
    else { while (p > s && isspace((unsigned char)p[-1])) p--; if (p > s && p[-1] == ',') p--; }
    char *out = join3(s, (size_t)(p - s), "", after); free(s); if (!out) return 1; int rc = valid_json(out) ? 1 : write_file(file, out); free(out); return rc;
}
static int array_add(const char *file, const char *key, const char *v) {
    size_t n = 0; char *s = read_file(file, &n); if (!s) s = strdup("{}"); if (!s) return 1; if (valid_json(s)) { free(s); return 2; }
    char *lit = escstr(v), *val = NULL, *end = NULL, *p = find_key(s, key, &val, &end), *out = NULL; if (!lit) { free(s); return 1; }
    if (!p) { char *arr = malloc(strlen(lit) + 3); sprintf(arr, "[%s]", lit); int rc = set_object_key(file, key, arr, "json"); free(arr); free(lit); free(s); return rc; }
    if (strstr(val, lit)) { free(lit); free(s); return 0; }
    char *rb = strrchr(val, ']'); if (!rb || rb > end) { free(lit); free(s); return 2; }
    char *q = val + 1; while (isspace((unsigned char)*q)) q++; int empty = (*q == ']'); char *m = malloc(strlen(lit) + 2); sprintf(m, "%s%s", empty ? "" : ",", lit); out = join3(s, (size_t)(rb - s), m, rb); free(m); free(lit); free(s); if (!out) return 1; int rc = valid_json(out) ? 1 : write_file(file, out); free(out); return rc;
}
static int array_del(const char *file, const char *key, const char *v) {
    size_t n = 0; char *s = read_file(file, &n); if (!s) return 0; char *lit = escstr(v), *val = NULL, *end = NULL, *p = find_key(s, key, &val, &end); if (!lit) { free(s); return 1; } if (!p) { free(s); free(lit); return 0; }
    char *x = strstr(val, lit); if (!x || x > end) { free(s); free(lit); return 0; } char *a = x, *b = x + strlen(lit); while (isspace((unsigned char)*b)) b++; if (*b == ',') b++; else { while (a > val && isspace((unsigned char)a[-1])) a--; if (a > val && a[-1] == ',') a--; }
    char *out = join3(s, (size_t)(a - s), "", b); free(s); free(lit); if (!out) return 1; int rc = valid_json(out) ? 1 : write_file(file, out); free(out); return rc;
}
static int token_revoke(const char *file, const char *tid) {
    size_t n = 0; char *s = read_file(file, &n); if (!s) return 0; char *tk = escstr(tid); if (!tk) { free(s); return 1; } char *p = strstr(s, tk); free(tk); if (!p) { free(s); return 0; }
    char *r = strstr(p, "\"revoked\""); if (!r) { free(s); return 0; } char *f = strstr(r, "false"); if (!f) { free(s); return 0; } char *out = join3(s, (size_t)(f - s), "true", f + 5); free(s); if (!out) return 1; int rc = valid_json(out) ? 1 : write_file(file, out); free(out); chmod(file, 0600); return rc;
}
static int token_revoke_all(const char *file) {
    size_t n = 0; char *s = read_file(file, &n); if (!s) return 0; size_t cap = n + 1, k = 0; char *o = malloc(cap + 16); if (!o) { free(s); return 1; }
    for (char *p = s; *p;) { if (!strncmp(p, "false", 5)) { memcpy(o + k, "true", 4); k += 4; p += 5; } else o[k++] = *p++; if (k + 8 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; } }
    o[k] = 0; free(s); int rc = valid_json(o) ? 1 : write_file(file, o); free(o); chmod(file, 0600); return rc;
}
static int get_top(const char *file, const char *key) { size_t n = 0; char *s = read_file(file, &n); if (!s) return 2; char *val = NULL, *end = NULL; if (!find_key(s, key, &val, &end)) { free(s); return 3; } fwrite(val, 1, (size_t)(end - val), stdout); putchar('\n'); free(s); return 0; }
int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "version")) { puts("hnc_json_c hotfix20.8 optional write helper"); return 0; }
    if (argc == 3 && !strcmp(argv[1], "validate")) { size_t n = 0; char *s = read_file(argv[2], &n); if (!s) return 2; int rc = valid_json(s); free(s); return rc; }
    if (argc == 4 && (!strcmp(argv[1], "get-top") || !strcmp(argv[1], "get"))) return get_top(argv[2], argv[3]);
    if ((argc == 5 || argc == 6) && (!strcmp(argv[1], "set-object-key") || !strcmp(argv[1], "object-set"))) return set_object_key(argv[2], argv[3], argv[4], argc == 6 ? argv[5] : "str");
    if (argc == 4 && (!strcmp(argv[1], "del-object-key") || !strcmp(argv[1], "object-del"))) return del_object_key(argv[2], argv[3]);
    if (argc == 5 && (!strcmp(argv[1], "add-array-unique") || !strcmp(argv[1], "array-add-unique"))) return array_add(argv[2], argv[3], argv[4]);
    if (argc == 5 && (!strcmp(argv[1], "del-array-value") || !strcmp(argv[1], "array-del-value"))) return array_del(argv[2], argv[3], argv[4]);
    if (argc == 4 && !strcmp(argv[1], "token-revoke")) return token_revoke(argv[2], argv[3]);
    if (argc == 3 && !strcmp(argv[1], "token-revoke-all")) return token_revoke_all(argv[2]);
    return 2;
}
