# HNC 采集 App(io.hnc.probe)

按剧本测 HNC「应用内活动细分」(`/api/devices[].fg.activity`)准不准的小工具,装在**连着 HNC 热点的测试手机**上。

- 它负责**真值**:剧本告诉你「现在去刷 3 分钟抖音」,同时每 2–5 秒记下本机真实状态(前台应用 / Activity、是否在通话、相机 / 麦克风是否被占用、亮灭屏),按标注规则算出「此刻真实在干什么」。
- 它负责**对照**(可选):每 10 秒向 HNC 要一次 `/api/devices`,按本机 Wi-Fi IP 找到自己,记下 HNC 当时的判断。
- 跑完给出按步汇总和混淆计数(真值 × HNC 输出,含「没输出」一列),可导出 JSON。

它**不抓包**:HNC 的流量观测本来就在热点手机上(root)。这个 App 只看本机系统状态,不碰任何流量内容。

目录 `tools/act_probe/` 不进模块安装包(CI 打包时排除 `tools/*`)。

---

## 1. 编译 / 测试

```sh
sh tools/act_probe/build.sh      # → tools/act_probe/out/hnc-probe.apk(不用 Gradle)
sh tools/act_probe/test.sh       # 纯 Java 逻辑单测(规则匹配 / 剧本解析 / 混淆计数 / HNC JSON 解析 / dumpsys 解析 / 会话存取)
sudo sh tools/act_probe/it_hnc.sh  # 可选: 本机跑真的 hnc_httpd, 用 App 的 HncClient 走一遍配对 + 拉取(需要 Go 和 root)
```

- 需要 JDK 11+、Android SDK `build-tools/34.0.0`(aapt2 / d8 / zipalign / apksigner)和 `platforms/android-34/android.jar`。路径用 `ANDROID_HOME` / `BUILD_TOOLS` / `ANDROID_JAR` 改。
- 调试签名 keystore 第一次编译时用 keytool 生成在 `.keys/debug.keystore`;`out/` 和 `.keys/` 都在 `.gitignore` 里,不提交。换了 keystore 要先卸载旧 APK 再装。
- 代码分两层:`src/core/`(纯 Java,不许 import android.*,test.sh 会检查)和 `src/app/`(Android 界面 / 服务 / 采样)。
- 注意:JDK 21 的 javac 会给**匿名类 / 非静态内部类**的构造器写 `MethodParameters` 属性,build-tools 34 的 d8 8.2 遇到会崩。源码里一律用静态嵌套类、lambda 或方法引用;build.sh 会提前检查并报出是哪个 class。

## 2. 安装与授权

```sh
adb install -r tools/act_probe/out/hnc-probe.apk
```

| 权限 | 用途 | 怎么给 |
|---|---|---|
| 使用情况访问(PACKAGE_USAGE_STATS) | 前台包名 + Activity 类名(来自系统使用情况记录的 ACTIVITY_RESUMED 事件) | App 里点「去授权」→ 系统设置里打开「HNC 采集」。**不给的话真值只能靠剧本** |
| 通知(Android 13+) | 运行中常驻通知 + 每步结束提醒,通知栏有「下一步 / 中止」按钮 | 首次打开会请求 |
| 网络(INTERNET / ACCESS_NETWORK_STATE) | 只连你填的 HNC 地址;读本机 Wi-Fi IP / 网关 | 安装即有 |
| 前台服务 / 唤醒锁 / 震动 | 熄屏步也要继续计时和采样;每步结束震动 | 安装即有 |

不申请相机、麦克风、位置、存储、无障碍权限:相机占用用 `CameraManager.AvailabilityCallback`、录音占用用 `AudioManager.getActiveRecordingConfigurations()`,都不需要权限。

ColorOS 建议在电池设置里允许本 App 后台运行(设置页有入口),否则熄屏步可能被杀。

## 3. 跑剧本(5 步)

1. 设置页:授权「使用情况访问」;(可选)配好 HNC 对照并「测试连接」通过;(可选)打开 root 模式。
2. 剧本页确认剧本(内置默认 18 步约 44 分钟:微信 5 项、王者 3 项、腾讯会议 2 项、抖音 3 项、B 站 3 项,外加「熄屏 2 分钟」和「后台下载」两个对照)。先把这些应用登录好、准备好通话对象。
3. 点「开始」:第 1 步立刻计时。按屏幕 / 通知上的说明操作。每步到时**震动**,进入「步间等待」,准备好下一步的场景后点通知栏的「下一步」。做不了的步(没队友、没可下载的更新)直接点「下一步」跳过。
4. 尽量用**通知栏**的「下一步 / 中止」,别切回本 App —— 切回来时前台是本 App,样本会被标成 `probe_in_fg`。
5. 跑完(或中止)去「结果」页看汇总,「导出到下载目录」(`下载/HNC-Probe/hnc-probe-<时间>.json`)或「另存为…」。

统计口径:
- 每步开头 `warmup_sec`(默认 20 秒)是预热期,不计入命中率和混淆(HNC 的活动判定有约 30 秒衰减 + 换标签防抖)。
- 步间等待(gap)的样本照记,但不标真值、不计入统计。
- 「命中」= HNC `fg.activity.id` 等于当时的真值;真值为 `idle` 时 HNC 没输出或输出 `background` 都算命中。

## 4. 真值怎么定

每个样本:

1. 按**标注规则**从上到下匹配,第一条命中的给出真值(`truth_src = "rule"`);
2. 没有规则命中 → 真值 = 剧本这一步的 `expect`(`truth_src = "script"`)。**剧本是主真值**,自动信号用来发现「剧本说在看直播,其实没进直播间」这类偏差。

另外每个样本按信号做几条检查,打成 `flags`(只标记,不改真值):

| flag | 含义 |
|---|---|
| `rule_disagree` | 规则判出的活动与剧本 expect 不一致 |
| `pkg_mismatch` | 这一步指定了应用,但前台是别的应用(亮屏时) |
| `probe_in_fg` | 前台是本 App 自己 |
| `call_missing` | 剧本说在通话,但没检测到通话模式也没有录音 |
| `camera_missing` | 剧本说视频通话,但相机没被占用 |
| `screen_off` | 剧本不是 idle 也不在通话,却熄屏了 |
| `screen_on_in_idle` | 剧本要熄屏(idle),却亮着屏 |

## 5. root 模式多了什么

设置页打开 root 模式时会先跑一次 `su` 里的 `id` 确认 uid=0。开启后,每次采样在一个常驻 su 会话里执行**一条固定的只读命令**(源码 `RootParsers.SAMPLE_CMD`,白名单精确匹配,不拼接任何输入):

```sh
echo '##ACT'; dumpsys activity activities | grep -i 'resumedactivity'
echo '##CAM'; dumpsys media.camera | grep -i -A 8 'active camera clients'
echo '##AUD'; dumpsys audio | grep -E 'MODE_|pack:|riid|RecordActivityMonitor'
```

另在运行开始时读一次 `cat /sys/class/net/wlan0/address`(在 HNC 列表里按 IP 找不到本机时按 MAC 兜底)。

多拿到的:
- 前台 Activity 完整类名(`topResumedActivity`,不依赖使用情况记录的事件);
- **哪个包**在占用相机(`camera_pkg`)、在录音(`mic_pkg`,跳过被静音的录音);
- 系统真实音频模式(`Actual mode`)。

dumpsys 的输出格式是按 AOSP 写的解析器,各 ROM / 版本可能不同:哪一项解析不出来就保留免 root 的值(样本里 `root=true` 表示至少有一项用了 root 结果,`cls_src=root` 表示类名来自 dumpsys)。建议第一次在 ColorOS 上用「Activity」页的「读当前前台(root)」看看各项能不能解析出来。

## 6. 标注规则:怎么写、怎么导入

格式(`assets/default_rules.json` 是内置默认):

```json
{
  "schema": "hnc-probe-rules/1",
  "name": "我的规则",
  "packages": {
    "com.tencent.mm": {"app": "wechat", "name": "微信", "verified": true}
  },
  "rules": [
    {"id": "video_call_by_camera", "when": {"in_call": true, "camera": true}, "then": "video_call"},
    {"id": "douyin_live_room", "enabled": true,
     "when": {"pkg": "com.ss.android.ugc.aweme", "activity": "\\.LivePlayActivity$"}, "then": "live_stream"}
  ]
}
```

- `when` 里的条件全部满足才命中;**信号拿不到 = 不命中**。可用条件:
  - `pkg`:包名字符串或数组;`pkg_not`:排除的包名数组
  - `activity`:Java 正则,对**完整类名**做 find(要整段匹配就加 `^...$`)
  - `in_call` / `camera` / `mic` / `screen_on`:布尔
  - `expect`:只在剧本当前步的 expect 是这些值时才生效(字符串或数组)
- `then`:活动 id,取值 `video_stream live_stream voice_call video_call gaming download upload browsing background idle`(前 9 个与 HNC `app_activity.go` 一致,`idle` 是本工具的「空闲 / 熄屏」)。
- 按顺序匹配,第一条命中的生效;`enabled: false` 或任何条件写着 `待核实` 的规则不生效。
- `packages` 把包名映射到 HNC 的 `fg.app_id`,用来在汇总里算「应用命中率」。

内置默认规则只有 3 条生效(通话 + 相机 → video_call;通话无相机 → voice_call(王者除外,开黑语音交给剧本);熄屏不通话 → idle),其余 7 条 Activity 规则是 **`待核实` 占位** —— 类名不确定就不编。腾讯会议包名 `com.tencent.wemeet.app` 不在 HNC 的 `data/pkg_app_map.json` 里,也标了待核实。

**写规则的流程**:
1. 进到目标界面(比如抖音直播间)停一会儿,或跑一遍剧本;
2. 「Activity」页点「从使用情况记录刷新」(免 root)或开 root 模式跑剧本,列表里就有真实类名;**点一行复制类名,长按复制一条规则草稿**(`enabled:false`、`then:"填活动id"`,不改直接导入会被拒);
3. 设置页「查看」或「复制当前剧本」拿到 JSON,编辑后存成文件;
4. 设置页「导入规则」(系统文件选择器);校验不过不会保存,并列出所有问题(未知活动 id、不认识的条件、正则写错、id 重复……)。

## 7. 剧本格式

```json
{
  "schema": "hnc-probe-script/1",
  "name": "我的剧本",
  "warmup_sec": 20,
  "steps": [
    {"app": "com.tencent.mm", "app_name": "微信", "expect": "voice_call", "label": "微信 · 语音通话",
     "minutes": 2, "instruction": "和另一台手机打微信语音通话"},
    {"app": "", "expect": "idle", "label": "对照 · 熄屏", "minutes": 2, "instruction": "锁屏放着"}
  ]
}
```

`app` 为包名,`""` 或 `"*"` 表示不限应用;`expect` 同上活动 id;`minutes` 可以是小数(0–120);可选 `hnc_app` 直接指定期望的 HNC `fg.app_id`(否则按规则文件 packages 映射)。剧本页「导入剧本」导入,运行中不能换。

## 8. HNC 对照怎么配

HNC 远程访问的鉴权(读自 `daemon/hnc_httpd` 的 middleware.go / pair.go / auth.go / tls.go):

- 远程端口 `:8443` 只走 **HTTPS,自签证书**;`/api/devices` 不是公开路径,必须带 `Cookie: hnc_token=<TokenID>.<Secret>`,没有 Bearer 头这条路。
- 令牌只能靠**配对码**换:热点手机 HNC 设置里「生成配对码」(6 位,120 秒有效,一次性)→ `POST /api/pair/verify`(表单 `pin=`)→ `302 + Set-Cookie`。每 IP 10 分钟错 5 次锁定(指数退避),同一配对码错 10 次作废。
- 令牌 14 天不用失效;热点手机「已授权设备」里可撤销。HNC 若开了 WebUI 访问白名单,本机要在名单里(否则 403)。
- 127.0.0.1 来的请求走的是本机 KSU WebUI 那套(root-only secret),和本 App 无关。

步骤:
1. 热点手机 HNC 设置 → 打开「启用远程访问服务」(v5.33.0-rc2 起几秒内生效);再到 设置 → 应用识别 → 前台识别引擎 → 「在 App 里干什么(实验)」选「开」—— v5.34.0-rc2 起默认关,关着时 HNC 不给 `fg.activity`,结果会全落在「无输出」列。
2. 本 App 设置页 → 「用网关地址」(自动填 Wi-Fi 网关 IP:8443)→「保存地址」。只接受私网 IPv4,只走 HTTPS。
3. 「测试连接」→ 弹出证书 SHA-256 指纹。**确认这台是你自己的 HNC 热点手机**再点信任。核对方法(热点手机 root shell,结果是小写无冒号的同一串):
   ```sh
   grep -v CERTIFICATE /data/local/hnc/data/httpd_cert.pem | tr -d '\n' | base64 -d | sha256sum
   ```
   信任后只接受这一个证书、只用于这个地址(不改系统 / 全局 TLS 设置;HNC 的证书 SAN 里通常只有 127.0.0.1,所以主机名校验改为「只认你填的 IP」)。证书变了会拒绝并提示。
4. 热点手机上「生成配对码」,120 秒内填到本 App 点「配对」。成功后热点手机「已授权设备」里多一条记录。
5. 再点「测试连接」,应能看到 HNC 眼里的本机(fg / activity / traffic_type)。打开「对照」开关。

也可以手动粘贴令牌(`TokenID.Secret` 格式)。令牌只存在 App 私有设置里,**不进导出文件**。本 App 只调 `POST /api/pair/verify` 和 `GET /api/devices`,不跟随重定向。连续 3 次 401 / 403 / 证书不对会停止本次运行的对照(真值照记)。

## 9. 导出 JSON 字段

```text
schema        "hnc-probe-export/1"
exported_at   导出时间(毫秒)
app           {package, version_name, version_code}
system        {manufacturer, brand, model, device, android_release, sdk_int, security_patch, build_display, build_incremental}
session       {id, started, ended, end_state(done|aborted|running), settings{interval_sec, root_mode, hnc_enabled, hnc_addr, usage_access, custom_script, custom_rules}}
script        剧本原文(JSON 对象, 可再导入)
rules         规则原文(JSON 对象, 可再导入)
samples[]     真值样本:
  t           时间戳(毫秒, 本机时钟)
  step        剧本步下标(0 起)
  phase       run | warmup | gap
  pkg, cls    前台包名 / Activity 完整类名(拿不到为 null)
  cls_src     usage | root
  in_call     是否在通话(音频模式为 IN_COMMUNICATION / IN_CALL 等)
  audio_mode  MODE_NORMAL / MODE_IN_COMMUNICATION / ...
  camera, camera_pkg   相机是否被占用 / 占用的包(root)
  mic, mic_pkg         是否有录音 / 录音的包(root)
  screen_on   是否亮屏
  root        本样本是否用到 root 结果
  truth       真值活动 id(gap 为 null)
  truth_src   rule | script
  rule        命中的规则 id
  flags[]     偏差标记(见第 4 节)
hnc[]         HNC 对照观测(每 10 秒):
  t, step, phase, latency_ms
  ok, err, http          是否成功 / 失败原因 / HTTP 码
  ip, mac, online        HNC 列表里本机那一行
  fg_state, fg_app, fg_name, fg_conf, fg_updated   fg.state / app_id / name / confidence / updated(秒, 热点手机时钟)
  act_id, act_label, act_conf, act_src             fg.activity.{id,label,conf,src}(没输出为 null)
  tt_type, tt_label, tt_conf                       traffic_type.{type,label,confidence}
  truth, truth_src       观测时刻的真值(最近一个同步样本; 没有则用剧本 expect)
summary
  steps[]     每步: label, app, expect, samples, samples_counted, truth_top, truth_dist, fg_pkg_top,
              flagged_samples, flagged_ratio, flags, hnc_obs, hnc_ok, hnc_errors, hnc_activity_top,
              hnc_activity_dist, hnc_app_top, hnc_app_dist, hnc_traffic_dist, hit, hit_ratio,
              want_hnc_app, app_hit_ratio
  confusion   {rows: 真值 id[], cols: HNC 活动 id[] + "none", counts: {真值: {HNC 列: 次数}}}
  overall     {samples_counted, flagged_samples, hnc_obs, hnc_ok, hnc_errors, hit, hit_ratio}
notes         口径与隐私说明
```

会话原始数据在 App 私有目录 `files/sessions/<yyyyMMdd-HHmmss>/`(meta.json、samples.jsonl、hnc.jsonl、summary.json)。进程被杀时已写的数据不丢,结果页显示「未正常结束」并现算汇总。

## 10. 隐私与安全边界

- 只用于维护者自己的测试设备。不抓包、不做中间人、不解密、不用无障碍服务。
- 数据只在本机(App 私有目录,`allowBackup=false`),导出才写到下载目录。除了你填的 HNC 地址不联网,没有任何统计上报。
- root 只执行上面列出的固定只读命令,不改系统任何东西。

## 11. 局限

- **真值的粒度**:免 root 能拿到「哪个 App 在前台、哪个 Activity、在不在通话、相机 / 麦克风有没有人用」,但拿不到「这一刻抖音在播直播流还是点播流」这种应用内部状态 —— 这正是靠剧本 + Activity 规则来补的。直播 / 点播 / 上传这类活动的 Activity 类名默认都是待核实,需要维护者在真机上看过后自己写规则。
- **通话判定**依赖应用把音频模式切到 `MODE_IN_COMMUNICATION`;个别应用 / 游戏语音可能不切(→ `call_missing` 标记会提示)。王者开黑语音默认不套通话规则。
- **相机**:可用性回调是「有任何相机不可用」;个别机型有常驻不可用的相机或手电筒占用相机,会误报占用(root 模式按 dumpsys 的客户端包名更准)。ColorOS 是否在后台照常回调需要真机验证。
- 使用情况记录在少数 ROM 上有延迟或被精简;画中画 / 小窗 / 分屏时「前台」只有一个,可能不准。
- root 模式的 dumpsys 解析按 AOSP 格式写,ColorOS 16 上需要真机确认(解析不出来自动退回免 root 值)。
- HNC 观测按本机 Wi-Fi IP 匹配;随机 MAC / DHCP 换 IP 时以 IP 为准,root 模式另有 MAC 兜底。
- 时间对齐:样本用测试手机时钟,HNC 的 `fg_updated` 是热点手机时钟;每 10 秒一次观测,配对的真值取 ±(2×采样间隔+1.5 秒)内最近的样本。
- 本 App 每 10 秒访问一次 HNC(每次一次 bcrypt 校验 + 一行 auth 日志),对 HNC 和本机流量的影响很小但不是零;它是对网关自身的连接,一般不会被算成某个应用的流量。
- 没有图形化编辑器:剧本 / 规则改 JSON 再导入。界面只求能用。
