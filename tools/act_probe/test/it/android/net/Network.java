package android.net;
/** JVM 集成测试用的桩: 真机上是绑定到 Wi-Fi 网络的 openConnection。 */
public class Network {
    public java.net.URLConnection openConnection(java.net.URL u) throws java.io.IOException { return u.openConnection(); }
}
