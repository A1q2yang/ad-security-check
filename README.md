# 域环境安全检查工具 (AD Security Assessment)

一个用 **PowerShell** 编写的 Active Directory 域环境安全自查工具。在**普通域用户终端**上运行，通过 LDAP **只读枚举**域控环境，发现常见的、可被攻击者利用的配置缺陷（错误配置 / 弱配置），并生成**中文 HTML 整改报告**。

> 仅做只读枚举与读取属性，**不进行任何攻击、口令破解或配置修改**。适用于授权范围内的内部安全自查与蓝队加固。

---

## 特性

- **无需域管理员权限**：绝大多数检查项普通已认证域用户即可完成。
- **无需安装 RSAT / ActiveDirectory 模块**：基于 .NET `System.DirectoryServices`，原生兼容。
- **兼容性广**：Windows PowerShell 5.1 与 PowerShell 7（Windows）均可运行。
- **一份直观报告**：按严重级别（严重 / 高危 / 中危 / 低危 / 信息）汇总，含受影响对象清单、整改建议与攻击技术参考（MITRE ATT&CK / CVE）。
- **单文件**：拷贝一个 `.ps1` 即可运行。

---

## 快速开始

在**已加入域**的 Windows 终端上，以一个普通域用户身份打开 PowerShell：

```powershell
# 1) 允许当前会话执行脚本（仅本进程，不改系统策略）
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 2) 运行（自动定位当前域与域控，报告生成在当前目录）
.\Invoke-ADSecurityCheck.ps1
```

运行结束后会在当前目录生成 `AD-Security-Report-<时间戳>.html`，并在交互式桌面会话中自动打开。

---

## 常用参数

| 参数 | 说明 | 默认 |
|------|------|------|
| `-Domain` | 目标域 DNS 名称，如 `corp.example.com` | 当前计算机所在域 |
| `-Server` | 指定要查询的域控主机名 / IP | 系统自动定位 |
| `-OutputPath` | HTML 报告输出路径 | 当前目录带时间戳文件 |
| `-Credential` | 指定连接域的凭据 (`PSCredential`) | 当前登录用户 |
| `-StaleDays` | 判定“僵尸 / 不活跃账户”的天数阈值 | `90` |
| `-OldPasswordDays` | 判定“口令过旧”（重点特权账户）的天数阈值 | `365` |
| `-SkipSysvolCheck` | 跳过 SYSVOL 中 GPP cpassword 文件扫描 | 关闭 |
| `-SysvolTimeoutSeconds` | SYSVOL 扫描超时（秒），超时自动跳过 | `120` |

### 示例

```powershell
# 指定域与域控
.\Invoke-ADSecurityCheck.ps1 -Domain corp.example.com -Server dc01.corp.example.com

# 指定输出路径，并放宽僵尸账户阈值到 180 天
.\Invoke-ADSecurityCheck.ps1 -OutputPath C:\Temp\ad-report.html -StaleDays 180

# 从非域内机器、用指定凭据连接
$cred = Get-Credential
.\Invoke-ADSecurityCheck.ps1 -Domain corp.example.com -Server 10.0.0.10 -Credential $cred
```

---

## 检查项一览（共 34 项）

### 域级别策略 / 基线

| 检查项 | 关注的风险 |
|---|---|
| 默认域密码策略 | 弱口令、可在线爆破 / 喷洒 (T1110) |
| 细粒度密码策略 (PSO) | 特权/服务账户口令未单独加严 |
| 机器账户配额 (MachineAccountQuota) | RBCD / noPac (CVE-2021-42278/42287) |
| krbtgt 口令老化 | 黄金票据 (T1558.001) |
| 域控清单与操作系统 | EOL 系统、ZeroLogon 等 |
| 域/林功能级别 + 成员 EOL 系统 | 弱加密、缺少现代凭据保护 |
| 域 / 林信任 + SID Filtering | SID History 跨域提权 (T1134.005) |
| 匿名 LDAP / dsHeuristics | 匿名枚举目录 |

### Kerberos / 委派

| 检查项 | 关注的风险 |
|---|---|
| 可 Kerberoasting 的 SPN 账户 | Kerberoasting (T1558.003) |
| 关闭 Kerberos 预认证的账户 | AS-REP Roasting (T1558.004) |
| 弱 Kerberos 加密 (RC4/DES) | 票据更易破解 |
| 非约束委派 | 攻陷主机即可冒充任意用户（配合 PetitPotam） |
| 约束委派（含协议转换） | S4U 冒充任意用户 |
| 基于资源的约束委派 (RBCD) | 常见提权链终点 |

### 账户卫生

| 检查项 | 关注的风险 |
|---|---|
| 口令非必需 / 可逆加密 / 仅 DES | 空口令、明文还原、弱加密 |
| 口令永不过期（含特权） | 凭据长期有效 (T1078) |
| 僵尸 / 不活跃用户账户 | 被忽视的突破口 |
| 僵尸计算机账户 | 陈旧机器账户与凭据 |
| 内置 Administrator (RID 500) 卫生 | 未改名 / 口令老化 |
| Guest (来宾) 账户启用状态 | 弱身份入口 |
| Pre-Windows 2000 Compatible Access 含宽泛主体 | 匿名枚举 |

### 特权账户与防护

| 检查项 | 关注的风险 |
|---|---|
| 特权账户口令老化 | 历史泄露危害大 |
| SID History | 隐蔽提权 / 持久化 (T1134.005) |
| 特权组成员（递归） | 过度授权、组内含计算机账户 |
| 高危易忽视组（DnsAdmins 等） | DnsAdmins → DC 代码执行 |
| Protected Users 覆盖 | 管理员凭据保护不足 |
| 特权账户『敏感，不可委派』标志 | 凭据被委派窃取 |
| 孤立 adminCount 账户 | 隐性特权遗留 (AdminSDHolder) |

### 凭据窃取面

| 检查项 | 关注的风险 |
|---|---|
| LAPS 部署情况 | 统一本地管理员口令、横向移动 |
| gMSA 口令可读范围 (msDS-GroupMSAMembership) | 服务账户凭据泄露 |
| 账户属性中的明文口令 / 可读机密 | description/info 含口令、userPassword 可读 (T1552) |
| DCSync (目录复制) 权限 | 远程导出全部哈希 (T1003.006) |
| SYSVOL GPP cpassword | MS14-025 明文口令 (T1552.006) |

### AD CS 证书服务

| 检查项 | 关注的风险 |
|---|---|
| 证书模板 ESC1 / ESC2 / ESC3 / ESC4 | 域接管的现代主流路径 |

### 配置异常

| 检查项 | 关注的风险 |
|---|---|
| 重复 SPN | 配置错误 / SPN 劫持迹象 |

---

## 权限说明

- **绝大多数检查**：普通已认证域用户即可读取（LDAP 查询是默认允许的）。
- **DCSync 权限检查 (ACL)**：需要能读取域对象的 `nTSecurityDescriptor`。普通用户通常可读；若无权，工具会降级为低危提示而非中断。
- **SYSVOL GPP 扫描**：需要能访问 `\\<域>\SYSVOL` 共享（域用户默认可读）。可用 `-SkipSysvolCheck` 跳过。

---

## 注意事项

- 报告由自动化枚举生成，**可能存在误报 / 漏报**，整改前请结合人工核实。
- `lastLogonTimestamp` 存在最多约 9–14 天的域复制延迟，僵尸账户判断会有一定时间误差。
- 对生产环境的任何整改（如设置 `MachineAccountQuota=0`、加入 Protected Users、轮换 krbtgt 等）**请先在测试环境验证兼容性**，避免影响依赖旧协议 / 委派的业务。
- 本工具仅限在**获得授权**的环境中使用。

---

## 运行环境

- 操作系统：Windows（已加入域，或可通过网络访问目标域控）
- PowerShell：Windows PowerShell 5.1 / PowerShell 7+（Windows）
- 依赖：`System.DirectoryServices`（系统自带），`System.Net.WebUtility`（系统自带）

> 说明：脚本中 SID 解析等使用了 `System.Security.Principal.SecurityIdentifier`，该 API 仅在 Windows 平台支持，因此本工具需在 Windows 上运行。
