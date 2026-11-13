#!/system/bin/sh
# Shared reads for manual rule changes and watchdog restoration.
# rules.json contains saved policy; devices.json supplies the current address.
# Source this file after setting HNC_DIR. It does not write configuration.

device_policy_ipv4() {
    printf '%s' "$1" | grep -Eq '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
}

device_current_ip() {
    local policy_ip
    policy_ip=$(HNC="$HNC_DIR" sh "$HNC_DIR/bin/hnc_json" get-object-key \
        "$HNC_DIR/data/devices.json" "$1" 2>/dev/null | awk '
        {s=s $0} END {
            if (match(s, /"ip"[[:space:]]*:[[:space:]]*"[0-9.]+"/)) {
                v=substr(s,RSTART,RLENGTH)
                sub(/^[^:]*:[[:space:]]*"/,"",v); sub(/"$/,"",v); print v
            }
        }')
    device_policy_ipv4 "$policy_ip" && printf '%s\n' "$policy_ip"
}

device_rule_mid() {
    local policy_mid
    policy_mid=$(HNC="$HNC_DIR" sh "$HNC_DIR/bin/hnc_json" get-device \
        "$HNC_DIR/data/rules.json" "$1" mark_id 2>/dev/null) || return 1
    case "$policy_mid" in ''|*[!0-9]*) return 1 ;; esac
    [ "$policy_mid" -ge 1 ] && [ "$policy_mid" -le 99 ] || return 1
    printf '%s\n' "$policy_mid"
}

# Project the eight scalar networking fields from one structured device read.
# Ignore unrelated strings/objects (including punctuation in device names).
# Output: mark_id|ip|down|up|delay|jitter|loss|sqm. Missing numeric fields are zero.
device_rule_fields() {
    local policy_object
    policy_object=$(HNC="$HNC_DIR" sh "$HNC_DIR/bin/hnc_json" get-device \
        "$HNC_DIR/data/rules.json" "$1" 2>/dev/null) || return 1
    printf '%s\n' "$policy_object" | awk '
    function string_end(start,   j,c) {
        for (j=start+1; j<=length(s); j++) {
            c=substr(s,j,1)
            if (c=="\\") j++
            else if (c=="\"") return j
        }
        return length(s)
    }
    {s=s $0 "\n"}
    END {
        split("mark_id down_mbps up_mbps delay_ms jitter_ms loss_pct", numeric, " ")
        for (n in numeric) {known[numeric[n]]=1; value[numeric[n]]=0}
        value["ip"]=""; value["sqm_enabled"]="false"
        depth=0
        for (i=1; i<=length(s); i++) {
            c=substr(s,i,1)
            if (c=="\"") {
                end=string_end(i); key=substr(s,i+1,end-i-1)
                tail=substr(s,end+1); i=end
                if (depth!=1 || !match(tail,/^[[:space:]]*:[[:space:]]*/)) continue
                tail=substr(tail,RLENGTH+1)
                if (known[key] && match(tail,/^[0-9]+([.][0-9]+)?([,}[:space:]]|$)/)) {
                    v=substr(tail,1,RLENGTH); sub(/[,}[:space:]]$/, "",v); value[key]=v
                } else if (key=="ip" && match(tail,/^"[0-9.]+"/)) {
                    value[key]=substr(tail,2,RLENGTH-2)
                } else if (key=="sqm_enabled" && tail ~ /^true([,}[:space:]]|$)/) value[key]="true"
            } else if (c=="{" || c=="[") depth++
            else if (c=="}" || c=="]") depth--
        }
        mid=value["mark_id"]
        if (mid !~ /^[0-9]+$/ || mid+0<1 || mid+0>99) exit 1
        print mid "|" value["ip"] "|" value["down_mbps"] "|" value["up_mbps"] "|" value["delay_ms"] "|" value["jitter_ms"] "|" value["loss_pct"] "|" value["sqm_enabled"]
    }'
}
