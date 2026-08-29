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
/* CR-1 fix: find_key walks char-by-char, skipping string values to avoid
   matching a key pattern that appears inside a JSON string value. */
static char *find_key(const char *s, const char *key, char **val, char **end) {
    char *k = escstr(key); if (!k) return NULL; size_t kn = strlen(k);
    if (!s) { free(k); return NULL; }
    const char *p = s; int in_str = 0, esc = 0;
    for (; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (in_str) { if (esc) { esc = 0; continue; } if (c == '\\') { esc = 1; continue; } if (c == '"') in_str = 0; continue; }
        if (!strncmp(p, k, kn)) {
            char *c2 = (char *)p + kn; while (isspace((unsigned char)*c2)) c2++;
            if (*c2 == ':') {
                c2++; while (isspace((unsigned char)*c2)) c2++;
                int ins2 = 0, esc2 = 0, dep2 = 0; char *q = c2;
                for (; *q; q++) { unsigned char ch = (unsigned char)*q; if (ins2) { if (esc2) { esc2 = 0; continue; } if (ch == '\\') { esc2 = 1; continue; } if (ch == '"') ins2 = 0; continue; } else { if (ch == '"') ins2 = 1; else if (ch == '{' || ch == '[') dep2++; else if ((ch == ',' || ch == '}') && dep2 == 0) break; else if (ch == '}' || ch == ']') dep2--; } }
                free(k);
                if (val) *val = c2;
                if (end) *end = q;
                return (char *)p;
            }
        }
        if (c == '"') { in_str = 1; continue; }
    }
    free(k); return NULL;
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
    if (!p) { char *arr = malloc(strlen(lit) + 3); snprintf(arr, strlen(lit) + 3, "[%s]", lit); int rc = set_object_key(file, key, arr, "json"); free(arr); free(lit); free(s); return rc; }
    /* exact-match scan: walk quoted strings between [ and ] */
    { char *scan = val + 1; size_t lit_len = strlen(lit);
      while (scan < end) { while (scan < end && *scan != '"') scan++; if (scan >= end) break;
        char *es = scan + 1; while (es < end && *es != '"') { if (*es == '\\' && es + 1 < end) es++; es++; }
        if (es < end && (size_t)(es - scan + 1) == lit_len && !strncmp(scan, lit, lit_len)) { free(lit); free(s); return 0; }
        scan = es + 1; } }
    char *rb = strrchr(val, ']'); if (!rb || rb > end) { free(lit); free(s); return 2; }
    char *q = val + 1; while (isspace((unsigned char)*q)) q++; int empty = (*q == ']'); char *m = malloc(strlen(lit) + 2); snprintf(m, strlen(lit) + 2, "%s%s", empty ? "" : ",", lit); out = join3(s, (size_t)(rb - s), m, rb); free(m); free(lit); free(s); if (!out) return 1; int rc = valid_json(out) ? 1 : write_file(file, out); free(out); return rc;
}
static int array_del(const char *file, const char *key, const char *v) {
    size_t n = 0; char *s = read_file(file, &n); if (!s) return 0; char *lit = escstr(v), *val = NULL, *end = NULL, *p = find_key(s, key, &val, &end); if (!lit) { free(s); return 1; } if (!p) { free(s); free(lit); return 0; }
    /* exact-match scan to find the element to remove */
    char *x = NULL;
    { char *scan = val + 1; size_t lit_len = strlen(lit);
      while (scan < end) { while (scan < end && *scan != '"') scan++; if (scan >= end) break;
        char *es = scan + 1; while (es < end && *es != '"') { if (*es == '\\' && es + 1 < end) es++; es++; }
        if (es < end && (size_t)(es - scan + 1) == lit_len && !strncmp(scan, lit, lit_len)) { x = scan; break; }
        scan = es + 1; } }
    if (!x || x > end) { free(s); free(lit); return 0; } char *a = x, *b = x + strlen(lit); while (isspace((unsigned char)*b)) b++; if (*b == ',') b++; else { while (a > val && isspace((unsigned char)a[-1])) a--; if (a > val && a[-1] == ',') a--; }
    char *out = join3(s, (size_t)(a - s), "", b); free(s); free(lit); if (!out) return 1; int rc = valid_json(out) ? 1 : write_file(file, out); free(out); return rc;
}
static int token_revoke(const char *file, const char *tid) {
    size_t n = 0; char *s = read_file(file, &n); if (!s) return 0;
    if (!tid) { /* revoke all: walk tokens and set revoked=true where false */
        size_t cap = n + 1, k = 0; char *o = malloc(cap + 16); if (!o) { free(s); return 1; }
        const char *rev_key = "\"revoked\""; size_t rk_len = 9;
        int in_str = 0, esc = 0;
        for (char *p = s; *p;) {
            unsigned char c = (unsigned char)*p;
            if (in_str) {
                if (esc) { esc = 0; if (k + 2 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; } o[k++] = *p++; continue; }
                if (c == '\\') { esc = 1; if (k + 2 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; } o[k++] = *p++; continue; }
                if (c == '"') in_str = 0;
                if (k + 1 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; }
                o[k++] = *p++; continue;
            }
            if (!strncmp(p, rev_key, rk_len)) {
                while (k + 1 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; }
                memcpy(o + k, rev_key, rk_len); k += rk_len; p += rk_len;
                char *c2 = (char *)p; while (*c2 && isspace((unsigned char)*c2)) { if (k + 1 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; } o[k++] = *c2++; }
                if (*c2 == ':') { if (k + 1 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; } o[k++] = *c2++; p = c2;
                    while (*p && isspace((unsigned char)*p)) { if (k + 1 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; } o[k++] = *p++; }
                    if (!strncmp(p, "false", 5)) { if (k + 4 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; } memcpy(o + k, "true", 4); k += 4; p += 5; }
                }
                continue;
            }
            if (c == '"') { in_str = 1; if (k + 1 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; } o[k++] = *p++; continue; }
            if (k + 1 > cap) { cap *= 2; char *np = realloc(o, cap); if (!np) { free(o); free(s); return 1; } o = np; }
            o[k++] = *p++;
        }
        o[k] = 0; free(s);
        int rc = valid_json(o) ? 1 : write_file(file, o); free(o); chmod(file, 0600); return rc;
    }
    char *tk = escstr(tid); if (!tk) { free(s); return 1; }
    char *tval = NULL, *tend = NULL;
    char *p = find_key(s, tk, &tval, &tend); free(tk);
    if (!p || !tval) { free(s); return 0; }
    char saved = *tend; *tend = 0;
    char *val = NULL, *end = NULL;
    find_key(tval, "revoked", &val, &end);
    *tend = saved;
    /* v5.9.91: 老 tokens.json 的条目可能没有 "revoked" 字段(旧版写出的文件)。
     * 旧实现在 find_key 未命中(!val)时 return 0 —— 调用方把 rc=0 当成功,
     * 撤销被静默吞掉(安全操作静默失效, C-2)。未命中时改为在 token 对象的
     * 收尾 '}' 前插入 "revoked":true; 已是 true 的保持幂等成功。 */
    if (val && end && !strncmp(val, "true", 4)) { free(s); return 0; }
    char *out;
    if (val && end) {
        /* false → true 原地替换 */
        out = join3(s, (size_t)(val - s), "true", end);
    } else {
        /* 无 revoked 键: 回退找 token 对象的收尾 '}'(tend 指向对象后一个
         * 字符; 空白已跳过), 在它前面插 ,"revoked":true */
        char *ins = tend - 1;
        while (ins > tval && isspace((unsigned char)*ins)) ins--;
        if (ins <= tval || *ins != '}') { free(s); return 1; }
        out = join3(s, (size_t)(ins - s), ",\"revoked\":true", ins);
    }
    free(s); if (!out) return 1;
    int rc = valid_json(out) ? 1 : write_file(file, out);
    free(out); chmod(file, 0600); return rc;
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
    if (argc >= 3 && !strcmp(argv[1], "token-revoke")) return token_revoke(argv[2], argc >= 4 ? argv[3] : NULL);
    return 2;
}
