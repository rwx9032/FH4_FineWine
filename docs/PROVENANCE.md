# 来源与二进制边界

## FineWine 移植依据

实施参考固定 FineWine 1.3.1 源码归档：

- commit `1b9d8e6c1fee6d96661d04dbab157fdf3329bd06`
- 归档 SHA-256 `3509cada6a9cde05433a47d9a705182197d35c016fa40191362f13cf30a78d8c`
- 归档内 `LICENSE` 为 MIT。

项目借鉴其对 GPTK `external` 组件的移植与 CrossOver 目录组织思路。本仓库新写工具按 MIT 授权；Wine/GPTK 修改组件仍受各自许可约束。仓库不包含 Wine/GPTK/原 shim DLL，也不因借鉴移植流程而声称拥有 Apple 或其他项目的二进制。

## Apple GPTK 4.0 beta 3 组件

| 文件 | SHA-256 | 说明 |
|---|---|---|
| `Game_Porting_Toolkit_4.0_beta_3.dmg` | `32ce206597e392267574a6c423ef80b9eab8b3c710d8957f011d2b106393b87b` | 用户下载的 GPTK 发行 DMG（含转换器 pkg 与 Evaluation DMG） |
| `Metal Shader Converter 4.0 beta 3.pkg` | `449833211e4ef0d46bfaa94848e801acff49e226d3c348bba0673f13716be622` | 转换器；payload 为 `/usr/local/bin/metal-shaderconverter`、头文件、`libmetalirconverter.dylib` |
| `Evaluation environment for Windows games 4.0 beta 3.dmg` | `9550b8e5c304aab7e0f16ff92b50abc90070846239df52d98409da7d0f40a7b0` | 内含 `redist/lib/external` 运行时 |
| `external/libd3dshared.dylib` | `e985a9e0b9807856018ee63ac40de3b3baaca7c33568f672d80d89934fbc41f1` | x86_64 Mach-O，250672 字节 |
| `external/D3DMetal.framework/Versions/A/D3DMetal` | `b16aab78127dcf6dbbaba4cfaf8120b96c90ee7b31a48be8599847932a4931e1` | x86_64，7973168 字节；`CFBundleShortVersionString=4.0b3` |

转换器 pkg 中的二进制与 Evaluation 运行时是不同组件；安装转换器不会生成或替换 `external` 下的 D3DMetal 4。`tools/fh4.py` 从不执行 pkg 安装器，也不下载 Apple 组件。

## 用户提供的补丁载荷

原工具 app 提供了以下 PE DLL，工具按 SHA-256 校验后从本机导入。原 app 未运行；这些摘要仅用于识别输入文件。

| 文件 | SHA-256 | 导出 |
|---|---|---|
| `apd12.dll` | `f1bcaa4d79e4353e075e7f284ebcb2d44a1b0cb2aa88f01f6341dc3c518b976f` | 11 个，序号 100–110 |
| `d3d12.dll` | `bc9d107e70aeb7e401b77303896b17d53c274fd92415b181f58ace378fb81a44` | 11 个，序号 100–110 |
| `kernelbase.dll` | `313a9d07019422fe0f56a579667d005d756728e13b66329aaa15321d92b0f182` | 补丁后的 26.3 `kernelbase.dll` |

载荷文件保留在本地 `payloads/`，该目录被 Git 忽略；仓库不包含 Apple GPTK 的 `D3DMetal.framework` 或 `libd3dshared.dylib`。

## kernelbase 补丁

`tools/fh4.py patch-kernelbase` 只接受 stock SHA-256 `ca72a76ce5770996cc9cba6989031a79eb1e63b6d9fca90d59eebab22e39191b` 的 x86_64 CrossOver 26.3 文件，校验 `.data` 布局与零填充 cave，然后做确定性修改：

- 将固定 RVA `0x2ce30`（`GetPackagesByPackageFamily`）改写为跳转到 `.data` 尾部的 stub；
- stub 位于 RVA `0x8bf20`，对应 raw 偏移 `0x8ab20`；
- 共 135 字节变化，输出 SHA-256 必须等于上表。

工具对具体二进制进行结构和哈希检查，不提供 Apple shim 的源代码级重建。

## COFF 符号与“可复现”

两个 PE 载荷保留了 COFF 符号表。`tools/fh4.py inspect` 可列出：

- `d3d12.dll`：模块名含 `d3d12.c` 及 MinGW CRT 模块；函数名含 `DllMain`、`D3D12CreateDevice` 等；
- `apd12.dll`：函数名含 `ne_init_unix_call`、`ne_unix_call_dispatcher`、`D3D12CreateDevice` 等。

这些只是名称和重定位信息，**不包含原始 C/C++ 源码**。因此本项目能复现的是：载荷导入校验、kernelbase 确定性补丁、文件布局/环境/注册表/签名/回滚流程；不能从二进制还原 shim 源码，也不会用占位实现冒充原 shim。
