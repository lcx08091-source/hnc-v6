#!/system/bin/sh
# json_guard.sh - hotfix18.3 lightweight JSON syntax validator
# Usage: json_guard.sh <file>
# Purpose: validate generated JSON before replacing persisted HNC state files.
# It is intentionally dependency-free for Android busybox/toybox environments.

[ -n "$1" ] || { echo "json_guard: file required" >&2; exit 2; }
FILE=$1
[ -f "$FILE" ] || { echo "json_guard: missing file: $FILE" >&2; exit 1; }

awk '
function ch(){ return substr(s,i,1) }
function skipws(   c){ while(i<=n){ c=substr(s,i,1); if(c==" "||c=="\t"||c=="\r"||c=="\n") i++; else break } }
function ishex(c){ return c ~ /^[0-9A-Fa-f]$/ }
function fail(msg){ err=msg " at byte " i; return 0 }
function parse_string(   c,e,k){
    if(ch()!="\"") return fail("expected string")
    i++
    while(i<=n){
        c=ch()
        if(c=="\""){ i++; return 1 }
        if(c=="\\"){
            i++; if(i>n) return fail("trailing escape")
            e=ch()
            if(e=="\""||e=="\\"||e=="/"||e=="b"||e=="f"||e=="n"||e=="r"||e=="t"){ i++; continue }
            if(e=="u"){
                for(k=1;k<=4;k++){ i++; if(i>n || !ishex(ch())) return fail("bad unicode escape") }
                i++; continue
            }
            return fail("bad escape")
        }
        # JSON strings may not contain raw control chars.
        if(c < " ") return fail("control char in string")
        i++
    }
    return fail("unterminated string")
}
function parse_number(   start,c,hasdigit){
    start=i
    if(ch()=="-") i++
    hasdigit=0
    if(ch()=="0"){ hasdigit=1; i++ }
    else if(ch() ~ /^[1-9]$/){ hasdigit=1; while(i<=n && ch() ~ /^[0-9]$/) i++ }
    else return fail("bad number")
    if(ch()=="."){
        i++; if(!(ch() ~ /^[0-9]$/)) return fail("bad number fraction")
        while(i<=n && ch() ~ /^[0-9]$/) i++
    }
    c=ch()
    if(c=="e" || c=="E"){
        i++; c=ch(); if(c=="+" || c=="-") i++
        if(!(ch() ~ /^[0-9]$/)) return fail("bad number exponent")
        while(i<=n && ch() ~ /^[0-9]$/) i++
    }
    return hasdigit
}
function parse_literal(lit,   L){
    L=length(lit)
    if(substr(s,i,L)==lit){ i+=L; return 1 }
    return 0
}
function parse_value(   c){
    skipws(); c=ch()
    if(c=="\"") return parse_string()
    if(c=="{") return parse_object()
    if(c=="[") return parse_array()
    if(c=="t") return parse_literal("true") || fail("bad literal")
    if(c=="f") return parse_literal("false") || fail("bad literal")
    if(c=="n") return parse_literal("null") || fail("bad literal")
    if(c=="-" || c ~ /^[0-9]$/) return parse_number()
    return fail("expected value")
}
function parse_object(   c){
    if(ch()!="{") return fail("expected object")
    i++; skipws()
    if(ch()=="}"){ i++; return 1 }
    while(i<=n){
        skipws(); if(!parse_string()) return 0
        skipws(); if(ch() != ":") return fail("expected colon")
        i++; if(!parse_value()) return 0
        skipws(); c=ch()
        if(c==","){ i++; continue }
        if(c=="}"){ i++; return 1 }
        return fail("expected comma or object end")
    }
    return fail("unterminated object")
}
function parse_array(   c){
    if(ch()!="[") return fail("expected array")
    i++; skipws()
    if(ch()=="]"){ i++; return 1 }
    while(i<=n){
        if(!parse_value()) return 0
        skipws(); c=ch()
        if(c==","){ i++; continue }
        if(c=="]"){ i++; return 1 }
        return fail("expected comma or array end")
    }
    return fail("unterminated array")
}
{ s = s $0 "\n" }
END {
    sub(/\n$/, "", s)
    n=length(s); i=1; err=""
    if(n==0){ print "empty JSON" > "/dev/stderr"; exit 1 }
    if(!parse_value()){ print err > "/dev/stderr"; exit 1 }
    skipws()
    if(i<=n){ print "trailing data at byte " i > "/dev/stderr"; exit 1 }
    print "ok"
}
' "$FILE" >/dev/null
