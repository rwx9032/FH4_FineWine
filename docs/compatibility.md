# 兼容性与验证矩阵

最后更新：2026-10-28。以 [HANDOFF.md](../HANDOFF.md) 为现场记录。

## 组件边界

Apple GPTK 4.0 beta 3 中包含至少三个不同层面的组件，不能互相替代：

| 组件 | 位置 | 作用 | 本工具是否使用 |
|---|---|---|---|
| Metal Shader Converter 4.0b3 | `Metal Shader Converter 4.0 beta 3.pkg` → `/usr/local/bin/metal-shaderconverter`、`/usr/local/lib/libmetalirconverter.dylib` 与头文件 | 离线把 DXIL 转为 Metal IR 的 CLI/库 | 否 |
| D3DMetal 4.0b3 运行时 | Evaluation DMG 的 `redist/lib/external/D3DMetal.framework` | Metal 图形后端 framework | 由用户提供 `external`，工具只复制与校验 |
| D3DMetal Unix 侧胶水 | 同一 `external/libd3dshared.dylib` | `d3d12.so`/`apd12.so` 等链接目标 | 由用户提供，工具只建立链接 |

“安装了转换器 pkg”不等于“CrossOver 已升级到 D3DMetal 4”。本工具不会执行任何 pkg 安装器。

## 已验证（隔离副本，2026-10-28）

验证对象是 CrossOver **26.3.0.39832** 应用副本和私有 win64 bottle，均位于临时目录；未修改 `/Applications/CrossOver.app`，未重启或干扰 Endfield。使用 Apple GPTK 4.0b3 Evaluation 的 `external`，以及用户提供的三份 PE 载荷。

| 项目 | 结果 | 证据 |
|---|---|---|
| stock `kernelbase.dll` 补丁 | 通过 | 输入 SHA-256 `ca72…39191b`，输出 `313a…0f182`；135 字节差异；固定 RVA `0x2ce30`→`0x8bf20` |
| GPTK `external` 复制与校验 | 通过 | `libd3dshared` `e985…41f1`，`D3DMetal` `b16a…31e1`，版本 4.0b3，x86_64 |
| `d3d12.dll` 装载 | 通过 | 11 个导出，序号 100–110；`GetProcAddress("D3D12CreateDevice")` 成功 |
| `apd12.dll` 装载 | 通过，需 builtin 覆盖 | 未覆盖时按 native 查找失败 `c0000135`；注册表 `apd12=builtin` 后成功 |
| Unix 胶水 | 通过 | `apd12.so` → `../../external/libd3dshared.dylib`，与 `d3d12.so` 相同 |
| 环境变量 | 通过 | 写入 `CX_GRAPHICS_BACKEND`、`HB_D3D12_REAL`、两个 `HB_TSSHIM_*`、`D3DM_VENDOR_ID`、`D3DM_DEVICE_ID`；保留 `WINEMSYNC` |
| `D3D12CreateDevice` ABI | 通过 | 64 位探针以 `rcx=NULL`、`edx=0xb000`、`r8=&IID`、`r9=&out` 调用，返回 `S_OK` 且得到非空设备指针 |
| ad-hoc 签名 | 通过 | `codesign --verify --all-architectures --deep --strict` |
| 安装 / `--replace` / 回滚 | 通过 | 两次安装后逐级回滚，app、bottle、`user.reg` 均恢复；末尾 `state=pristine` |
| 失败注入回滚 | 通过 | 签名失败、回滚中途失败、manifest 篡改、symlink 目标均被拒绝且不残留越界写入 |

补充观察：把与 `apd12.dll` 字节完全相同的文件改名为 `foo.dll` 后可正常 native 装载，说明失败来自 Wine/CrossOver 对 `apd12` 这个名字的默认 native 解析，而不是 PE 内容损坏。`WINEDLLOVERRIDES` 会被 CrossOver 的 Perl 启动器在读取 bottle 环境后删除，因此持久修复必须写 `HKCU\Software\Wine\DllOverrides`；工具以最小改动写入 `"apd12"="builtin"`，并在回滚时恢复原值。

## 未验证

- 没有目标 `ForzaHorizon4.exe`（也未固定其 SHA-256），因此没有启动游戏、进入世界、渲染正确性、帧率、稳定性或存档验证。
- 没有把补丁安装进用户正在使用的 CrossOver 或 Endfield bottle；Endfield 会话未被触碰。
- 没有验证固定 RVA 的 VEH 补丁在真实 FH4 版本上的效果；目前没有已验证的游戏构建，`install` 始终要求显式 `--allow-unverified-game`；可选的 EXE 与 SHA-256 只固定身份，不能证明固定 RVA 兼容。
- 没有恢复供应商签名；安装后是 ad-hoc 签名。
- 没有从 COFF 符号恢复 shim 源码；只提取了模块和函数名清单。

## 环境要求

- macOS，Python 3.12+，CrossOver 26.3.0，win64 bottle。
- 用户本机提供 GPTK 4.x `external`、三份 PE 载荷；工具不下载、不包含这些二进制。
- 目标 app/bottle 处于空闲状态；`check` 只读，不要求空闲，也不写注册表。

## 不支持 / 禁止

- 不使用 vkd3d 或自制 DLL 冒充 D3DMetal/Apple 组件。
- 不接受与已知 stock 哈希不符的 `kernelbase.dll`，不做模糊匹配。
- 不在 Wine/CrossOver 进程运行时安装或回滚。
- 不覆盖运行中的 CrossOver、不重启 Endfield、不修改游戏画质或 video 注册表设置。
