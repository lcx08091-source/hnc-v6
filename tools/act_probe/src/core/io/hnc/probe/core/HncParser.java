package io.hnc.probe.core;

import java.util.List;
import java.util.Map;

/**
 * 解析 HNC GET /api/devices 的返回(daemon/hnc_httpd/server.go buildDevicesPayload):
 * <pre>
 * {"devices":[{"mac":"..","ip":"192.168.43.7","online":true,
 *    "fg":{"state":"active","app_id":"douyin","name":"抖音","confidence":82,"updated":1760000000,
 *          "activity":{"id":"video_stream","label":"刷抖音","conf":0.72,"src":"domain"}},
 *    "traffic_type":{"type":"video_stream","label":"看视频","confidence":0.8}}, ...],
 *  "whitelist_mode":..., "remote_enabled":true}
 * </pre>
 * 找本机: 先按 IP(多条时优先 online), 找不到再按 MAC(root 模式才知道本机 MAC)。
 */
public final class HncParser {
    private HncParser() {}

    public static HncObs parse(String body, String myIp, String myMac) {
        Map<String, Object> root;
        try {
            root = Json.parseObject(body);
        } catch (IllegalArgumentException e) {
            return HncObs.error("HNC 返回的不是 JSON 对象: " + e.getMessage(), 200);
        }
        List<Object> devs = Json.asArr(root.get("devices"));
        if (devs == null) return HncObs.error("HNC 返回里没有 devices 数组", 200);

        Map<String, Object> best = null;
        if (myIp != null && !myIp.isEmpty()) {
            for (Object d : devs) {
                Map<String, Object> m = Json.asObj(d);
                if (m == null || !myIp.equals(Json.str(m, "ip"))) continue;
                if (best == null || (isOnline(m) && !isOnline(best))) best = m;
            }
        }
        if (best == null && myMac != null && !myMac.isEmpty()) {
            for (Object d : devs) {
                Map<String, Object> m = Json.asObj(d);
                if (m != null && myMac.equalsIgnoreCase(Json.str(m, "mac"))) { best = m; break; }
            }
        }
        if (best == null) {
            HncObs o = HncObs.error("HNC 设备列表里没找到本机(IP " + myIp
                    + (myMac != null ? ", MAC " + myMac : "") + ", 共 " + devs.size() + " 台)", 200);
            o.ip = myIp;
            return o;
        }

        HncObs o = new HncObs();
        o.ok = true;
        o.http = 200;
        o.ip = Json.str(best, "ip");
        o.mac = Json.str(best, "mac");
        o.online = Json.bool(best, "online");
        Map<String, Object> fg = Json.asObj(best.get("fg"));
        if (fg != null) {
            o.fgState = Json.strNE(fg, "state");
            o.fgApp = Json.strNE(fg, "app_id");
            o.fgName = Json.strNE(fg, "name");
            o.fgConf = Json.num(fg, "confidence");
            o.fgUpdated = Json.lng(fg, "updated");
            Map<String, Object> act = Json.asObj(fg.get("activity"));
            if (act != null) {
                o.actId = Json.strNE(act, "id");
                o.actLabel = Json.strNE(act, "label");
                o.actConf = Json.num(act, "conf");
                o.actSrc = Json.strNE(act, "src");
            }
        }
        Map<String, Object> tt = Json.asObj(best.get("traffic_type"));
        if (tt != null) {
            o.ttType = Json.strNE(tt, "type");
            o.ttLabel = Json.strNE(tt, "label");
            o.ttConf = Json.num(tt, "confidence");
        }
        return o;
    }

    private static boolean isOnline(Map<String, Object> m) {
        return Boolean.TRUE.equals(Json.bool(m, "online"));
    }
}
