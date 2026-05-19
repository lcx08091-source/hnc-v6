# HNC v5.1 libbpf 改造 — FINAL 版(跳过 elftoolchain)

## 策略变更
elftoolchain cross-compile 太脆(4 层 header 循环依赖),
**直接用 JiaHuann/libbpf-bootstrap-android 已验证的 aarch64 预编译 .a**。

- `libelf.a` (aarch64 Android) + headers — 来自 JiaHuann BSD-3
- `libz.a` (aarch64 Android) + zlib.h — 同上
- `libbpf.a` — 我们自己 NDK 编(21 个 .c,无 GNU 扩展依赖)

这样 CI 只需要编 libbpf 的 21 个 .c,libelf + libz 完全跳过。

## 执行步骤(全在 Termux ~/hnc-v5)

```sh
cd ~/hnc-v5
cp /sdcard/Download/HNC-v5_1-libbpf-FINAL.zip .
unzip -o HNC-v5_1-libbpf-FINAL.zip
rm HNC-v5_1-libbpf-FINAL.zip

# ─── 1. 删除 elftoolchain 和 zlib submodules (不再用) ───
git submodule deinit -f third_party/libelf 2>/dev/null
git submodule deinit -f third_party/zlib 2>/dev/null
git rm -f third_party/libelf 2>/dev/null
git rm -f third_party/zlib 2>/dev/null
rm -rf .git/modules/third_party/libelf .git/modules/third_party/zlib
rm -rf third_party/libelf third_party/zlib

# .gitmodules 只保留 libbpf
cat > .gitmodules <<GITMOD
[submodule "third_party/libbpf"]
	path = third_party/libbpf
	url = https://github.com/libbpf/libbpf.git
GITMOD

# ─── 2. vendor JiaHuann 预编译的 libelf + libz ───
# (之前已 git clone 到 ~/jh, 现在 cp 进来)
mkdir -p third_party_prebuilt/libelf/include
mkdir -p third_party_prebuilt/libz/include

# libelf (aarch64 .a + headers)
cp ~/jh/deps/libelf-aarch64/usr/lib/libelf.a           third_party_prebuilt/libelf/
cp ~/jh/deps/libelf-aarch64/usr/include/libelf.h       third_party_prebuilt/libelf/include/
cp ~/jh/deps/libelf-aarch64/usr/include/gelf.h         third_party_prebuilt/libelf/include/
cp ~/jh/deps/libelf-aarch64/usr/include/nlist.h        third_party_prebuilt/libelf/include/
cp -r ~/jh/deps/libelf-aarch64/usr/include/elfutils    third_party_prebuilt/libelf/include/ 2>/dev/null || true

# libz (aarch64 .a + headers)
cp ~/jh/deps/zlib-1.2.10/libz.a                        third_party_prebuilt/libz/
cp ~/jh/deps/zlib-1.2.10/zlib.h                        third_party_prebuilt/libz/include/
cp ~/jh/deps/zlib-1.2.10/zconf.h                       third_party_prebuilt/libz/include/

# Vendor LICENSE/注明来源
cat > third_party_prebuilt/LICENSE.md <<LICEOF
# Prebuilt libelf.a and libz.a — Source attribution

These static libraries (aarch64 Android) are vendored from:
  https://github.com/JiaHuann/libbpf-bootstrap-android (BSD-3-Clause)
  License file: ~/jh/LICENSE

libelf itself is LGPL-2.1 (from elfutils 0.179 upstream).
zlib is under the zlib License.

The binaries are used unmodified as build-time dependencies.
LICEOF

# ─── 3. 验证文件到位 ───
ls -la third_party_prebuilt/libelf/libelf.a
ls -la third_party_prebuilt/libz/libz.a
ls third_party_prebuilt/libelf/include/
ls third_party_prebuilt/libz/include/

# ─── 4. Commit + push ───
git add -A
git status
git commit -m "v5.1 FINAL: vendor prebuilt libelf.a + libz.a from JiaHuann

Replaces failing elftoolchain cross-compile with verified aarch64
Android prebuilt static libs (JiaHuann/libbpf-bootstrap-android,
BSD-3). Only libbpf needs NDK compile (21 .c, known to work on
Bionic). Total vendored: ~5MB.

Eliminates CI build_libs loop (fix1 -> fix2 -> fix3 hit endless
elfdefinitions.h / Elf32_Ehdr / ELFDATA2LSB undef chain)."
git push
```

## CI 预期
下次 CI 跑:
- Submodule init: 只拉 libbpf(不拉 libelf / zlib → 快)
- build_libs.sh: cp 预编译 .a + 编 libbpf 21 个 .c(~2 分钟)
- hotspotd 链接: 成功
- BPF 对象编译:成功(单独 clang -target bpf)
- 打 zip → 上传 artifact → 完成

## 如果仍然失败(应对)
1. **libbpf 21 个 .c 有 N 个失败** — 贴哪几个失败的 .c 名字,我加 shim
2. **hotspotd 链接 undefined symbol** — 大概率 `bpf_program__*` / `bpf_map__*` name mismatch,libbpf v1.8 vs 我们 loader.c 的 API。贴 link error,我 patch loader.c
3. **LSM init 时 libbpf 报错** — 最后一关,libbpf 处理 BTF/CO-RE,
   错误信息会直接说问题在哪(比 hand-rolled 可控)

## 如果 CI 过了但装机 LSM 还不 active
libbpf 自己报错(比如 "bpf_program__attach_lsm failed"),我们根据它
的具体错误做下一步 — 可能需要:
- 微调 BPF 程序的 SEC name
- 手动指定 attach_btf_id 
- 升级 kernel BTF 解决偏移问题

但这些问题 libbpf 会给清晰的错误信息,不再是 hand-rolled 的黑盒。
