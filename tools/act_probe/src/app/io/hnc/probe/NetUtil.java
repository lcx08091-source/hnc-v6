package io.hnc.probe;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;

import java.net.Inet4Address;
import java.net.InetAddress;

/** 本机 Wi-Fi(连着 HNC 热点)的网络 / IPv4 / 网关。 */
final class NetUtil {
    private NetUtil() {}

    static final class Wifi {
        Network network;
        String ip;
        String gateway;
    }

    @SuppressWarnings("deprecation")
    static Wifi wifi(Context c) {
        ConnectivityManager cm = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return null;
        try {
            for (Network n : cm.getAllNetworks()) {
                NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                if (nc == null || !nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) continue;
                LinkProperties lp = cm.getLinkProperties(n);
                if (lp == null) continue;
                Wifi w = new Wifi();
                w.network = n;
                for (LinkAddress la : lp.getLinkAddresses()) {
                    InetAddress a = la.getAddress();
                    if (a instanceof Inet4Address && !a.isLoopbackAddress()) {
                        w.ip = a.getHostAddress();
                        break;
                    }
                }
                for (RouteInfo r : lp.getRoutes()) {
                    if (r.isDefaultRoute() && r.getGateway() instanceof Inet4Address) {
                        w.gateway = r.getGateway().getHostAddress();
                        break;
                    }
                }
                if (w.ip != null) return w;
            }
        } catch (RuntimeException ignored) {
            // 个别 ROM 上偶发 SecurityException / NPE, 当作拿不到
        }
        return null;
    }
}
