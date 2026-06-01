<#
.SYNOPSIS
    域环境安全检查工具 (AD Security Assessment Tool)

.DESCRIPTION
    在普通域用户终端上运行，通过 LDAP 只读枚举 Active Directory 域环境，
    检查域控环境中常见的、可被攻击者利用的安全风险点（错误配置/弱配置），
    并生成中文 HTML 整改报告。

    设计目标：
      * 防御性安全审计 —— 仅做只读枚举，不做任何修改、不读取/破解口令、不发起攻击。
      * 无需域管理员权限 —— 绝大多数检查项普通已认证域用户即可完成。
      * 无需安装 RSAT / ActiveDirectory 模块 —— 基于 .NET System.DirectoryServices。

.PARAMETER Domain
    目标域的 DNS 名称（如 corp.example.com）。默认使用当前计算机所在域。

.PARAMETER Server
    指定要查询的域控制器主机名或 IP。默认由系统自动定位。

.PARAMETER OutputPath
    HTML 报告输出路径。默认在当前目录生成带时间戳的文件。

.PARAMETER Credential
    用于连接域的凭据 (PSCredential)。默认使用当前登录用户的上下文。

.PARAMETER StaleDays
    判定"僵尸/不活跃账户"的天数阈值。默认 90 天。

.PARAMETER OldPasswordDays
    判定"口令过旧"的天数阈值（重点关注特权账户）。默认 365 天。

.PARAMETER SkipSysvolCheck
    跳过 SYSVOL 中 GPP cpassword 的文件扫描（该项需要访问 \\domain\SYSVOL）。

.PARAMETER SysvolTimeoutSeconds
    SYSVOL GPP 扫描的最长耗时（秒）。超时将自动跳过，避免在大型域/慢网络下卡住。默认 120 秒。

.EXAMPLE
    .\Invoke-ADSecurityCheck.ps1

.EXAMPLE
    .\Invoke-ADSecurityCheck.ps1 -Domain corp.example.com -Server dc01.corp.example.com -OutputPath C:\Temp\report.html

.NOTES
    作者   : Kiro AD Security Assessment
    用途   : 仅限授权的内部安全自查 / 蓝队加固。请勿在未获授权的环境中使用。
    兼容性 : Windows PowerShell 3.0+ / PowerShell 7+ (Windows)
#>
[CmdletBinding()]
param(
    [string]$Domain,
    [string]$Server,
    [string]$OutputPath,
    [System.Management.Automation.PSCredential]$Credential,
    [int]$StaleDays = 90,
    [int]$OldPasswordDays = 365,
    [switch]$SkipSysvolCheck,
    [int]$SysvolTimeoutSeconds = 120
)

#region ========================= 全局状态 =========================

# 所有检查结果统一收集到此列表
$script:Findings = New-Object System.Collections.ArrayList

# 严重级别定义（用于排序与统计），数字越大越严重
$script:SeverityRank = @{
    'Critical' = 4   # 严重 —— 可直接导致域沦陷/持久化
    'High'     = 3   # 高危 —— 可显著提升攻击者权限或横向移动
    'Medium'   = 2   # 中危 —— 存在被利用的风险，需整改
    'Low'      = 1   # 低危 —— 加固建议
    'Info'     = 0   # 信息 —— 环境基线信息
}

$script:SeverityText = @{
    'Critical' = '严重'
    'High'     = '高危'
    'Medium'   = '中危'
    'Low'      = '低危'
    'Info'     = '信息'
}

# UAC (userAccountControl) 位标志
$script:UAC = @{
    SCRIPT                         = 0x00000001
    ACCOUNTDISABLE                 = 0x00000002
    HOMEDIR_REQUIRED               = 0x00000008
    LOCKOUT                        = 0x00000010
    PASSWD_NOTREQD                 = 0x00000020
    PASSWD_CANT_CHANGE             = 0x00000040
    ENCRYPTED_TEXT_PWD_ALLOWED     = 0x00000080
    TEMP_DUPLICATE_ACCOUNT         = 0x00000100
    NORMAL_ACCOUNT                 = 0x00000200
    INTERDOMAIN_TRUST_ACCOUNT      = 0x00000800
    WORKSTATION_TRUST_ACCOUNT      = 0x00001000
    SERVER_TRUST_ACCOUNT           = 0x00002000
    DONT_EXPIRE_PASSWORD           = 0x00010000
    MNS_LOGON_ACCOUNT              = 0x00020000
    SMARTCARD_REQUIRED             = 0x00040000
    TRUSTED_FOR_DELEGATION         = 0x00080000
    NOT_DELEGATED                  = 0x00100000
    USE_DES_KEY_ONLY               = 0x00200000
    DONT_REQ_PREAUTH               = 0x00400000
    PASSWORD_EXPIRED               = 0x00800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000
}

#endregion

#region ========================= 辅助函数 =========================

function Write-Step {
    param([string]$Message, [string]$Status = 'RUN')
    $color = switch ($Status) {
        'OK'   { 'Green' }
        'WARN' { 'Yellow' }
        'ERR'  { 'Red' }
        default { 'Cyan' }
    }
    $tag = switch ($Status) {
        'OK'   { '[ +] ' }
        'WARN' { '[ !] ' }
        'ERR'  { '[ x] ' }
        default { '[..] ' }
    }
    Write-Host ($tag + $Message) -ForegroundColor $color
}

function Add-Finding {
    <#
        统一登记一个检查结论。即便"未发现问题"也可登记为 Info/通过项，
        让报告能体现检查覆盖面。
    #>
    param(
        [Parameter(Mandatory)] [string]$Category,     # 检查类别
        [Parameter(Mandatory)] [string]$Title,        # 风险项标题
        [Parameter(Mandatory)]
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        [string]$Description = '',                     # 风险说明
        [object[]]$Affected = @(),                     # 受影响对象（字符串或哈希表）
        [string]$Remediation = '',                     # 整改建议
        [string]$Reference = '',                       # 参考/攻击技术编号
        [bool]$Passed = $false                         # 是否为"通过/未发现问题"
    )
    $null = $script:Findings.Add([pscustomobject]@{
        Category    = $Category
        Title       = $Title
        Severity    = $Severity
        Description = $Description
        Affected    = @($Affected)
        Remediation = $Remediation
        Reference   = $Reference
        Passed      = $Passed
        Count       = @($Affected).Count
    })
}

function Get-DirectoryEntry {
    <# 构造一个 DirectoryEntry（支持指定 server / 凭据 / 子路径）。#>
    param([string]$PathSuffix = '')
    $prefix = 'LDAP://'
    if ($Server) { $prefix += "$Server/" }
    $path = $prefix + $PathSuffix
    if ($Credential) {
        $netCred = $Credential.GetNetworkCredential()
        $user = if ($netCred.Domain) { "$($netCred.Domain)\$($netCred.UserName)" } else { $netCred.UserName }
        return New-Object System.DirectoryServices.DirectoryEntry($path, $user, $netCred.Password)
    }
    return New-Object System.DirectoryServices.DirectoryEntry($path)
}

function Invoke-LdapQuery {
    <#
        执行一次 LDAP 查询并返回 SearchResult 集合。
        -Filter      : LDAP 过滤器
        -Properties  : 需要返回的属性
        -SearchRoot  : 搜索根 DN（默认整个域）
    #>
    param(
        [Parameter(Mandatory)] [string]$Filter,
        [string[]]$Properties = @(),
        [string]$SearchRoot
    )
    $root = if ($SearchRoot) { Get-DirectoryEntry $SearchRoot } else { Get-DirectoryEntry $script:DomainDN }
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    $searcher.SizeLimit = 0
    foreach ($p in $Properties) { $null = $searcher.PropertiesToLoad.Add($p) }
    try {
        return $searcher.FindAll()
    } finally {
        $searcher.Dispose()
        $root.Dispose()
    }
}

function Get-Prop {
    <# 安全地从 SearchResult 取单值属性。#>
    param($Result, [string]$Name, $Default = $null)
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        return $Result.Properties[$Name][0]
    }
    return $Default
}

function Get-PropAll {
    <# 取多值属性，返回数组。#>
    param($Result, [string]$Name)
    if ($Result.Properties.Contains($Name)) {
        return @($Result.Properties[$Name])
    }
    return @()
}

function Test-UacFlag {
    param([int]$Uac, [int]$Flag)
    return (($Uac -band $Flag) -eq $Flag)
}

function Convert-FileTimeToDate {
    <# 把 AD 的 FileTime (Int64) 转为 DateTime；0 或 9223372036854775807 视为"从未"。#>
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $ft = [Int64]$Value
        if ($ft -le 0 -or $ft -eq 9223372036854775807) { return $null }
        return [DateTime]::FromFileTime($ft)
    } catch { return $null }
}

function ConvertTo-DistinguishedNameShort {
    <# 把 DN 转为可读的简短样本（用于显示账户/OU 路径）。#>
    param([string]$Dn)
    return $Dn
}

#endregion


#region ========================= 域连接初始化 =========================

function Initialize-DomainContext {
    <#
        连接 RootDSE，确定 defaultNamingContext / configurationNamingContext，
        读取域基础信息，填充到 $script: 作用域变量。
    #>
    Write-Step "正在连接域并读取 RootDSE ..." 'RUN'

    $rootDse = Get-DirectoryEntry 'RootDSE'
    $script:DomainDN  = [string]$rootDse.Properties['defaultNamingContext'][0]
    $script:ConfigDN  = [string]$rootDse.Properties['configurationNamingContext'][0]
    $script:SchemaDN  = [string]$rootDse.Properties['schemaNamingContext'][0]
    $script:RootDomainDN = [string]$rootDse.Properties['rootDomainNamingContext'][0]
    $dcName = [string]$rootDse.Properties['dnsHostName'][0]
    $rootDse.Dispose()

    if ([string]::IsNullOrEmpty($script:DomainDN)) {
        throw "无法读取 defaultNamingContext，请确认终端已加入域且可访问域控，或使用 -Server / -Credential 指定。"
    }

    # 读取域对象本身（密码策略、机器账户配额、域功能级别等都在域根对象上）
    $domObj = Get-DirectoryEntry $script:DomainDN
    $script:DomainObject = $domObj

    # 域 SID
    try {
        $sidBytes = $domObj.Properties['objectSid'][0]
        $script:DomainSid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
    } catch { $script:DomainSid = $null }

    $script:DomainInfo = [ordered]@{
        '域 DN'        = $script:DomainDN
        '域 SID'       = $script:DomainSid
        '查询的域控'   = if ($Server) { $Server } else { $dcName }
        '执行账户'     = if ($Credential) { $Credential.UserName } else { "$env:USERDOMAIN\$env:USERNAME" }
        '扫描时间'     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        '工具主机'     = $env:COMPUTERNAME
    }

    Write-Step "已连接域: $($script:DomainDN)" 'OK'
}

#endregion


#region ========================= 检查项：域级别策略 =========================

function Test-PasswordPolicy {
    Write-Step "检查域默认密码策略 ..." 'RUN'
    try {
        $d = $script:DomainObject
        $minPwdLen   = [int]($d.Properties['minPwdLength'][0])
        $pwdHistory  = [int]($d.Properties['pwdHistoryLength'][0])
        $lockoutThr  = [int]($d.Properties['lockoutThreshold'][0])
        $pwdProps    = [int]($d.Properties['pwdProperties'][0])
        # maxPwdAge / minPwdAge 以 100 纳秒为单位的负数表示
        $maxPwdAgeRaw = $d.ConvertLargeIntegerToInt64($d.Properties['maxPwdAge'][0])
        $maxPwdAgeDays = if ($maxPwdAgeRaw -ne 0) { [math]::Round([math]::Abs($maxPwdAgeRaw) / 864000000000) } else { 0 }
        $complexity = (($pwdProps -band 1) -eq 1)   # DOMAIN_PASSWORD_COMPLEX

        $issues = @()
        if ($minPwdLen -lt 12)    { $issues += "最小密码长度为 $minPwdLen（建议 >= 12，特权账户建议 >= 15）" }
        if (-not $complexity)     { $issues += "未启用密码复杂性要求" }
        if ($pwdHistory -lt 12)   { $issues += "密码历史长度为 $pwdHistory（建议 >= 12 防止口令复用）" }
        if ($lockoutThr -eq 0)    { $issues += "账户锁定阈值为 0（未启用锁定，易遭在线口令爆破/喷洒）" }
        if ($maxPwdAgeDays -eq 0)  { $issues += "密码永不过期（maxPwdAge = 0）" }
        elseif ($maxPwdAgeDays -gt 365) { $issues += "最长密码有效期为 $maxPwdAgeDays 天（偏长）" }

        $detailRows = @(
            "最小密码长度: $minPwdLen",
            "密码复杂性: $(if($complexity){'已启用'}else{'未启用'})",
            "密码历史: $pwdHistory",
            "锁定阈值: $lockoutThr",
            "最长密码有效期: $(if($maxPwdAgeDays -eq 0){'永不过期'}else{"$maxPwdAgeDays 天"})"
        )

        if ($issues.Count -gt 0) {
            $sev = if ($lockoutThr -eq 0 -or $minPwdLen -lt 8) { 'High' } else { 'Medium' }
            Add-Finding -Category '密码策略' -Title '域默认密码策略存在弱项' -Severity $sev `
                -Description ("当前默认域密码策略存在以下弱点，可能被口令爆破/喷洒利用：`n - " + ($issues -join "`n - ")) `
                -Affected ($detailRows | ForEach-Object { @{ '当前策略项' = $_ } }) `
                -Remediation "建议：最小长度 >=12（特权账户/服务账户 >=15-25 并使用 gMSA）；启用复杂性；密码历史 >=24；设置合理锁定阈值（如 5 次/30 分钟）；启用细粒度密码策略 (FGPP/PSO) 对特权账户加严。" `
                -Reference "CIS / MITRE ATT&CK T1110 (Brute Force)"
        } else {
            Add-Finding -Category '密码策略' -Title '域默认密码策略基本合规' -Severity 'Info' -Passed $true `
                -Description ("默认密码策略未发现明显弱项：`n - " + ($detailRows -join "`n - "))
        }
        Write-Step "密码策略检查完成" 'OK'
    } catch {
        Write-Step "密码策略检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-MachineAccountQuota {
    Write-Step "检查机器账户配额 (ms-DS-MachineAccountQuota) ..." 'RUN'
    try {
        $val = $script:DomainObject.Properties['ms-DS-MachineAccountQuota']
        $quota = if ($val -and $val.Count -gt 0) { [int]$val[0] } else { 10 }  # 默认 10

        if ($quota -gt 0) {
            Add-Finding -Category '权限提升面' -Title "任意域用户可加入计算机账户 (MachineAccountQuota = $quota)" -Severity 'Medium' `
                -Description "ms-DS-MachineAccountQuota = $quota 表示任意已认证域用户都可以向域中加入最多 $quota 个计算机账户。攻击者常借此创建机器账户配合基于资源的约束委派 (RBCD)、noPac (CVE-2021-42278/42287) 等技术进行权限提升。" `
                -Affected @(@{ '配置项' = 'ms-DS-MachineAccountQuota'; '当前值' = $quota }) `
                -Remediation "将 ms-DS-MachineAccountQuota 设为 0，改由管理员/委派的专门账户负责加域；并通过 GPO『将工作站添加到域』权限精细控制。" `
                -Reference "RBCD / CVE-2021-42278 / CVE-2021-42287 (noPac)"
        } else {
            Add-Finding -Category '权限提升面' -Title '机器账户配额已收紧 (MachineAccountQuota = 0)' -Severity 'Info' -Passed $true `
                -Description "普通用户无法自行加入计算机账户，降低了 RBCD/noPac 类攻击的前置条件。"
        }
        Write-Step "机器账户配额检查完成" 'OK'
    } catch {
        Write-Step "机器账户配额检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-KrbtgtPassword {
    Write-Step "检查 krbtgt 账户口令老化 ..." 'RUN'
    try {
        $res = Invoke-LdapQuery -Filter '(sAMAccountName=krbtgt)' -Properties @('pwdLastSet','sAMAccountName')
        foreach ($r in $res) {
            $pwdLastSet = Convert-FileTimeToDate (Get-Prop $r 'pwdLastSet')
            if ($pwdLastSet) {
                $ageDays = [math]::Round(((Get-Date) - $pwdLastSet).TotalDays)
                if ($ageDays -gt 180) {
                    $sev = if ($ageDays -gt 365) { 'High' } else { 'Medium' }
                    Add-Finding -Category 'Kerberos / 持久化' -Title "krbtgt 口令长期未轮换（已 $ageDays 天）" -Severity $sev `
                        -Description "krbtgt 账户口令上次设置于 $($pwdLastSet.ToString('yyyy-MM-dd'))，距今约 $ageDays 天。krbtgt 哈希一旦泄露即可伪造『黄金票据』(Golden Ticket) 实现长期持久化；口令长期不轮换将使历史泄露的票据持续有效。" `
                        -Affected @(@{ '账户' = 'krbtgt'; '口令设置时间' = $pwdLastSet.ToString('yyyy-MM-dd'); '已使用天数' = $ageDays }) `
                        -Remediation "定期（建议每 180 天）轮换 krbtgt 口令；发生疑似域沦陷时应『连续轮换两次』（间隔 >10 小时或所有票据生命周期后），可使用微软官方 Reset-KrbtgtKeys 脚本。" `
                        -Reference "MITRE ATT&CK T1558.001 (Golden Ticket)"
                } else {
                    Add-Finding -Category 'Kerberos / 持久化' -Title 'krbtgt 口令轮换周期正常' -Severity 'Info' -Passed $true `
                        -Description "krbtgt 口令于 $($pwdLastSet.ToString('yyyy-MM-dd')) 设置，约 $ageDays 天，处于合理范围。"
                }
            }
        }
        Write-Step "krbtgt 检查完成" 'OK'
    } catch {
        Write-Step "krbtgt 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-DomainControllers {
    Write-Step "枚举域控制器与操作系统版本 ..." 'RUN'
    try {
        # UAC 含 SERVER_TRUST_ACCOUNT(0x2000) 的计算机即为 DC
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' `
            -Properties @('dNSHostName','operatingSystem','operatingSystemVersion','sAMAccountName')
        $dcs = @()
        $outdated = @()
        foreach ($r in $res) {
            $os = [string](Get-Prop $r 'operatingSystem')
            $host = [string](Get-Prop $r 'dNSHostName')
            $dcs += @{ '域控' = $host; '操作系统' = $os }
            # 识别已停止支持的服务器系统
            if ($os -match '2003|2008|2012') {
                $outdated += @{ '域控' = $host; '操作系统' = $os }
            }
        }

        Add-Finding -Category '基线信息' -Title "发现 $($dcs.Count) 台域控制器" -Severity 'Info' -Passed $true `
            -Description "域控制器清单（操作系统版本）。" -Affected $dcs

        if ($outdated.Count -gt 0) {
            Add-Finding -Category '系统加固' -Title "存在已停止支持的域控操作系统（$($outdated.Count) 台）" -Severity 'High' `
                -Description "以下域控运行已结束支持 (EOL) 的 Windows Server 版本，缺少安全更新，存在大量公开可利用漏洞（如 ZeroLogon、PrintNightmare 等的修复缺失风险）。" `
                -Affected $outdated `
                -Remediation "尽快将域控升级到受支持的 Windows Server 版本（2019/2022/2025），并保持补丁更新。" `
                -Reference "CVE-2020-1472 (ZeroLogon) 等"
        }
        Write-Step "域控枚举完成" 'OK'
    } catch {
        Write-Step "域控枚举失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-DomainTrusts {
    Write-Step "检查域信任关系 ..." 'RUN'
    try {
        $res = Invoke-LdapQuery -Filter '(objectClass=trustedDomain)' `
            -Properties @('trustPartner','trustDirection','trustType','trustAttributes')
        $trusts = @()
        $risky = @()
        foreach ($r in $res) {
            $partner = [string](Get-Prop $r 'trustPartner')
            $dir = [int](Get-Prop $r 'trustDirection' 0)
            $attr = [int](Get-Prop $r 'trustAttributes' 0)
            $dirText = switch ($dir) { 1 {'入站 (Inbound)'} 2 {'出站 (Outbound)'} 3 {'双向 (Bidirectional)'} default {"未知($dir)"} }
            # trustAttributes: 0x40 = TREAT_AS_EXTERNAL; 0x4 = QUARANTINED_DOMAIN(SID Filtering 启用); 0x8 = FOREST_TRANSITIVE
            $sidFiltering = (($attr -band 0x4) -eq 0x4)
            $row = @{ '信任对象' = $partner; '方向' = $dirText; 'SID Filtering' = $(if($sidFiltering){'启用'}else{'未启用/未知'}) }
            $trusts += $row
            if (-not $sidFiltering -and ($attr -band 0x8) -eq 0) {
                $risky += $row
            }
        }
        if ($trusts.Count -eq 0) {
            Add-Finding -Category '信任关系' -Title '未发现外部/林信任' -Severity 'Info' -Passed $true -Description "当前域没有配置到其他域/林的信任关系。"
        } else {
            Add-Finding -Category '信任关系' -Title "发现 $($trusts.Count) 个域信任关系" -Severity 'Info' -Passed $true `
                -Description "域信任清单。请确认每条信任的业务必要性，并对入站/双向信任重点关注。" -Affected $trusts
            if ($risky.Count -gt 0) {
                Add-Finding -Category '信任关系' -Title "存在未启用 SID Filtering 的信任（$($risky.Count) 条）" -Severity 'Medium' `
                    -Description "未启用 SID 过滤的信任可能被『SID History 注入』跨域提权利用。" `
                    -Affected $risky `
                    -Remediation "对外部信任启用 SID Filtering / Quarantine；评估是否可改为选择性身份验证 (Selective Authentication)；清理不再需要的信任。" `
                    -Reference "MITRE ATT&CK T1134.005 (SID-History Injection)"
            }
        }
        Write-Step "信任关系检查完成" 'OK'
    } catch {
        Write-Step "信任关系检查失败: $($_.Exception.Message)" 'ERR'
    }
}

#endregion


#region ========================= 检查项：Kerberos 与委派 =========================

function Test-Kerberoastable {
    Write-Step "检查可 Kerberoasting 的服务账户 (SPN) ..." 'RUN'
    try {
        # 用户对象（非计算机）且设置了 SPN
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' `
            -Properties @('sAMAccountName','servicePrincipalName','adminCount','pwdLastSet','userAccountControl','memberOf')
        $all = @()
        $privileged = @()
        foreach ($r in $res) {
            $sam = [string](Get-Prop $r 'sAMAccountName')
            if ($sam -eq 'krbtgt') { continue }
            $spns = (Get-PropAll $r 'servicePrincipalName') -join '; '
            $adminCount = [int](Get-Prop $r 'adminCount' 0)
            $pwdSet = Convert-FileTimeToDate (Get-Prop $r 'pwdLastSet')
            $pwdAge = if ($pwdSet) { [math]::Round(((Get-Date) - $pwdSet).TotalDays) } else { $null }
            $row = @{
                '账户' = $sam
                'SPN'  = $spns
                '特权(adminCount)' = $(if($adminCount -ge 1){'是'}else{'否'})
                '口令年龄(天)' = $pwdAge
            }
            $all += $row
            if ($adminCount -ge 1) { $privileged += $row }
        }

        if ($all.Count -gt 0) {
            # 普通可 Kerberoast 账户
            $sev = if ($privileged.Count -gt 0) { 'Critical' } else { 'High' }
            Add-Finding -Category 'Kerberos / 凭据窃取' -Title "存在可被 Kerberoasting 的服务账户（$($all.Count) 个）" -Severity $sev `
                -Description "这些用户账户配置了 SPN，任意域用户都可向其请求服务票据 (TGS) 并离线破解其口令。其中标记『特权=是』的账户隶属于特权组，一旦破解将直接导致高权限沦陷。`n注意：本工具仅枚举，不请求票据、不进行破解。" `
                -Affected $all `
                -Remediation "1) 优先将服务账户迁移为组托管服务账户 (gMSA/dMSA)，由系统自动维护 25+ 位随机口令；2) 对必须保留的服务账户设置 25 位以上高强度口令并定期轮换；3) 移除特权组中带 SPN 的用户账户，遵循最小权限；4) 启用 AES 加密、禁用 RC4。" `
                -Reference "MITRE ATT&CK T1558.003 (Kerberoasting)"
        } else {
            Add-Finding -Category 'Kerberos / 凭据窃取' -Title '未发现可 Kerberoasting 的用户型服务账户' -Severity 'Info' -Passed $true `
                -Description "未发现设置了 SPN 的普通用户账户。"
        }
        Write-Step "Kerberoasting 检查完成" 'OK'
    } catch {
        Write-Step "Kerberoasting 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-AsRepRoastable {
    Write-Step "检查 AS-REP Roasting（不要求预认证的账户）..." 'RUN'
    try {
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' `
            -Properties @('sAMAccountName','adminCount','userAccountControl')
        $rows = @()
        foreach ($r in $res) {
            $rows += @{
                '账户' = [string](Get-Prop $r 'sAMAccountName')
                '特权(adminCount)' = $(if([int](Get-Prop $r 'adminCount' 0) -ge 1){'是'}else{'否'})
            }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category 'Kerberos / 凭据窃取' -Title "存在不要求 Kerberos 预认证的账户（$($rows.Count) 个）" -Severity 'High' `
                -Description "这些账户设置了『不要求 Kerberos 预身份验证』(DONT_REQ_PREAUTH)，攻击者无需任何凭据即可获取其 AS-REP 并离线破解口令。" `
                -Affected $rows `
                -Remediation "取消勾选账户属性中的『不要求 Kerberos 预身份验证』；如确因兼容性需要保留，则务必设置超长高强度口令并加强监控。" `
                -Reference "MITRE ATT&CK T1558.004 (AS-REP Roasting)"
        } else {
            Add-Finding -Category 'Kerberos / 凭据窃取' -Title '未发现关闭预认证的账户' -Severity 'Info' -Passed $true `
                -Description "所有账户均要求 Kerberos 预身份验证。"
        }
        Write-Step "AS-REP Roasting 检查完成" 'OK'
    } catch {
        Write-Step "AS-REP Roasting 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-UnconstrainedDelegation {
    Write-Step "检查非约束委派 (Unconstrained Delegation) ..." 'RUN'
    try {
        # TRUSTED_FOR_DELEGATION (0x80000)。需排除域控（DC 默认即非约束委派属正常）
        $res = Invoke-LdapQuery -Filter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
            -Properties @('sAMAccountName','dNSHostName','userAccountControl','objectClass')
        $rows = @()
        foreach ($r in $res) {
            $uac = [int](Get-Prop $r 'userAccountControl' 0)
            # 域控同时带 SERVER_TRUST_ACCOUNT(0x2000)，排除之
            if (Test-UacFlag $uac $script:UAC.SERVER_TRUST_ACCOUNT) { continue }
            $sam = [string](Get-Prop $r 'sAMAccountName')
            if ($sam -eq 'krbtgt') { continue }
            $type = if ([string]((Get-PropAll $r 'objectClass') -join ',') -match 'computer') { '计算机' } else { '用户' }
            $rows += @{ '账户' = $sam; '类型' = $type; '主机' = [string](Get-Prop $r 'dNSHostName') }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category 'Kerberos / 委派' -Title "存在配置非约束委派的非 DC 主机/账户（$($rows.Count) 个）" -Severity 'Critical' `
                -Description "配置了非约束委派的主机会在内存中缓存任何访问它的用户（含域管理员、域控机器账户）的 TGT。攻击者攻陷此类主机后可提取 TGT 冒充任意用户，常配合打印机 Bug/PetitPotam 强制域控认证，直接导致域沦陷。" `
                -Affected $rows `
                -Remediation "除域控外，普通服务器/账户不应使用非约束委派；改用『仅限指定服务的约束委派』或基于资源的约束委派；将敏感账户加入『Protected Users』组或勾选『账户敏感，不能被委派』。" `
                -Reference "MITRE ATT&CK T1558 / Unconstrained Delegation + PetitPotam"
        } else {
            Add-Finding -Category 'Kerberos / 委派' -Title '未发现非 DC 的非约束委派配置' -Severity 'Info' -Passed $true `
                -Description "除域控外没有主机配置非约束委派。"
        }
        Write-Step "非约束委派检查完成" 'OK'
    } catch {
        Write-Step "非约束委派检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-ConstrainedDelegation {
    Write-Step "检查约束委派 (Constrained Delegation) ..." 'RUN'
    try {
        $res = Invoke-LdapQuery -Filter '(msDS-AllowedToDelegateTo=*)' `
            -Properties @('sAMAccountName','msDS-AllowedToDelegateTo','userAccountControl')
        $rows = @()
        foreach ($r in $res) {
            $uac = [int](Get-Prop $r 'userAccountControl' 0)
            $protocolTrans = Test-UacFlag $uac $script:UAC.TRUSTED_TO_AUTH_FOR_DELEGATION
            $rows += @{
                '账户' = [string](Get-Prop $r 'sAMAccountName')
                '可委派至' = ((Get-PropAll $r 'msDS-AllowedToDelegateTo') -join '; ')
                '协议转换(任意用户)' = $(if($protocolTrans){'是 (高危)'}else{'否'})
            }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category 'Kerberos / 委派' -Title "存在约束委派配置（$($rows.Count) 个）" -Severity 'Medium' `
                -Description "约束委派允许账户代表用户访问指定服务。若开启『使用任意身份验证协议』(协议转换/S4U2Self)，攻击者控制该账户后可冒充任意用户（含域管）访问目标服务；且 SPN 的服务部分可被篡改以横向到同主机其他服务。" `
                -Affected $rows `
                -Remediation "审查每个约束委派的业务必要性与目标 SPN 范围；尽量避免『协议转换』；将高价值目标的管理员账户加入 Protected Users 或标记不可委派。" `
                -Reference "MITRE ATT&CK T1558 / Constrained Delegation (S4U)"
        } else {
            Add-Finding -Category 'Kerberos / 委派' -Title '未发现约束委派配置' -Severity 'Info' -Passed $true -Description "无账户配置 msDS-AllowedToDelegateTo。"
        }
        Write-Step "约束委派检查完成" 'OK'
    } catch {
        Write-Step "约束委派检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-ResourceBasedDelegation {
    Write-Step "检查基于资源的约束委派 (RBCD) ..." 'RUN'
    try {
        $res = Invoke-LdapQuery -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
            -Properties @('sAMAccountName','msDS-AllowedToActOnBehalfOfOtherIdentity')
        $rows = @()
        foreach ($r in $res) {
            $sam = [string](Get-Prop $r 'sAMAccountName')
            # 解析允许列表中的 SID
            $sids = @()
            try {
                $raw = $r.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity'][0]
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorBinaryForm([byte[]]$raw)
                foreach ($ace in $sd.GetAccessRules($true,$false,[System.Security.Principal.SecurityIdentifier])) {
                    $sids += $ace.IdentityReference.Value
                }
            } catch {}
            $rows += @{ '目标账户' = $sam; '允许冒充的主体(SID)' = (($sids | Select-Object -Unique) -join '; ') }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category 'Kerberos / 委派' -Title "存在基于资源的约束委派配置（$($rows.Count) 个）" -Severity 'High' `
                -Description "msDS-AllowedToActOnBehalfOfOtherIdentity 被设置，意味着列出的主体可代表任意用户访问该目标。若该属性可被低权限用户写入（结合 MachineAccountQuota>0），是常见的提权链终点。请核对每条配置是否为预期。" `
                -Affected $rows `
                -Remediation "核对每个 RBCD 配置的来源与必要性，清除非预期项；收紧对计算机对象 msDS-AllowedToActOnBehalfOfOtherIdentity / 写属性 的 ACL；将 MachineAccountQuota 设为 0。" `
                -Reference "MITRE ATT&CK T1558 / Resource-Based Constrained Delegation"
        } else {
            Add-Finding -Category 'Kerberos / 委派' -Title '未发现 RBCD 配置' -Severity 'Info' -Passed $true -Description "无对象设置 msDS-AllowedToActOnBehalfOfOtherIdentity。"
        }
        Write-Step "RBCD 检查完成" 'OK'
    } catch {
        Write-Step "RBCD 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

#endregion


#region ========================= 检查项：账户卫生 =========================

function Test-DangerousUacFlags {
    Write-Step "检查危险账户标志（口令非必需 / 可逆加密 / DES）..." 'RUN'

    # 口令非必需 PASSWD_NOTREQD (0x20)
    try {
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' `
            -Properties @('sAMAccountName','userAccountControl')
        $rows = @()
        foreach ($r in $res) {
            $uac = [int](Get-Prop $r 'userAccountControl' 0)
            $enabled = -not (Test-UacFlag $uac $script:UAC.ACCOUNTDISABLE)
            $rows += @{ '账户' = [string](Get-Prop $r 'sAMAccountName'); '状态' = $(if($enabled){'启用'}else{'禁用'}) }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category '账户卫生' -Title "存在『口令非必需』(PASSWD_NOTREQD) 账户（$($rows.Count) 个）" -Severity 'High' `
                -Description "这些账户被标记为口令非必需，可能存在空口令或可被设置为空口令，极易被直接登录利用。" `
                -Affected $rows `
                -Remediation "移除账户的 PASSWD_NOTREQD 标志，强制设置符合策略的强口令；禁用或清理不再使用的账户。" `
                -Reference "MITRE ATT&CK T1078 (Valid Accounts)"
        }
    } catch { Write-Step "PASSWD_NOTREQD 检查失败: $($_.Exception.Message)" 'ERR' }

    # 可逆加密存储口令 ENCRYPTED_TEXT_PWD_ALLOWED (0x80)
    try {
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))' `
            -Properties @('sAMAccountName')
        $rows = @()
        foreach ($r in $res) { $rows += @{ '账户' = [string](Get-Prop $r 'sAMAccountName') } }
        if ($rows.Count -gt 0) {
            Add-Finding -Category '账户卫生' -Title "存在『可逆加密存储口令』的账户（$($rows.Count) 个）" -Severity 'High' `
                -Description "启用可逆加密后，口令在域库中以可被还原为明文的方式保存，攻击者获取数据库后可直接还原明文口令。" `
                -Affected $rows `
                -Remediation "取消账户/GPO 中的『使用可逆加密存储密码』设置，并随后重置相关账户口令使旧的可逆密文失效。" `
                -Reference "CIS Benchmark"
        }
    } catch { Write-Step "可逆加密检查失败: $($_.Exception.Message)" 'ERR' }

    # 仅 DES USE_DES_KEY_ONLY (0x200000)
    try {
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))' `
            -Properties @('sAMAccountName')
        $rows = @()
        foreach ($r in $res) { $rows += @{ '账户' = [string](Get-Prop $r 'sAMAccountName') } }
        if ($rows.Count -gt 0) {
            Add-Finding -Category '账户卫生' -Title "存在仅使用 DES 加密的账户（$($rows.Count) 个）" -Severity 'Medium' `
                -Description "DES 加密强度极弱，相关 Kerberos 票据更易被破解。" `
                -Affected $rows `
                -Remediation "取消『仅使用 DES 加密类型』；在域内统一启用 AES 并逐步禁用 RC4/DES。" `
                -Reference "Kerberos Encryption Hardening"
        }
    } catch { Write-Step "DES 检查失败: $($_.Exception.Message)" 'ERR' }

    Write-Step "危险账户标志检查完成" 'OK'
}

function Test-PasswordNeverExpires {
    Write-Step "检查口令永不过期账户 ..." 'RUN'
    try {
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' `
            -Properties @('sAMAccountName','adminCount','userAccountControl')
        $rows = @()
        $privRows = @()
        foreach ($r in $res) {
            $uac = [int](Get-Prop $r 'userAccountControl' 0)
            if (Test-UacFlag $uac $script:UAC.ACCOUNTDISABLE) { continue }   # 跳过已禁用
            $sam = [string](Get-Prop $r 'sAMAccountName')
            $isPriv = [int](Get-Prop $r 'adminCount' 0) -ge 1
            $row = @{ '账户' = $sam; '特权(adminCount)' = $(if($isPriv){'是'}else{'否'}) }
            $rows += $row
            if ($isPriv) { $privRows += $row }
        }
        if ($rows.Count -gt 0) {
            $sev = if ($privRows.Count -gt 0) { 'High' } else { 'Medium' }
            Add-Finding -Category '账户卫生' -Title "存在口令永不过期的启用账户（$($rows.Count) 个，其中特权 $($privRows.Count) 个）" -Severity $sev `
                -Description "口令永不过期意味着即使口令泄露也长期有效，扩大了凭据被滥用的窗口；特权账户尤为危险。" `
                -Affected $rows `
                -Remediation "对交互式账户取消『密码永不过期』并纳入定期轮换；对必须长期有效的服务账户改用 gMSA 自动轮换。" `
                -Reference "T1078 / CIS"
        } else {
            Add-Finding -Category '账户卫生' -Title '未发现口令永不过期的启用账户' -Severity 'Info' -Passed $true -Description "无启用账户设置密码永不过期。"
        }
        Write-Step "口令永不过期检查完成" 'OK'
    } catch {
        Write-Step "口令永不过期检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-StaleAccounts {
    Write-Step "检查僵尸/不活跃账户（>$StaleDays 天）..." 'RUN'
    try {
        $threshold = (Get-Date).AddDays(-$StaleDays)
        # 启用、非计算机、非永不过期的人员账户
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Properties @('sAMAccountName','lastLogonTimestamp','pwdLastSet','adminCount')
        $rows = @()
        foreach ($r in $res) {
            $llt = Convert-FileTimeToDate (Get-Prop $r 'lastLogonTimestamp')
            if ($llt -and $llt -lt $threshold) {
                $rows += @{
                    '账户' = [string](Get-Prop $r 'sAMAccountName')
                    '最近登录' = $llt.ToString('yyyy-MM-dd')
                    '闲置天数' = [math]::Round(((Get-Date) - $llt).TotalDays)
                    '特权' = $(if([int](Get-Prop $r 'adminCount' 0) -ge 1){'是'}else{'否'})
                }
            }
        }
        if ($rows.Count -gt 0) {
            $rows = $rows | Sort-Object { -[int]$_['闲置天数'] }
            Add-Finding -Category '账户卫生' -Title "存在长期不活跃的启用账户（$($rows.Count) 个）" -Severity 'Medium' `
                -Description "这些账户已启用但超过 $StaleDays 天未登录。僵尸账户常被忽视、口令陈旧，是攻击者的理想突破口。（注：lastLogonTimestamp 存在最多约 9-14 天的复制延迟。）" `
                -Affected $rows `
                -Remediation "建立账户生命周期流程：定期禁用 N 天未登录账户，确认无用后删除；对离职/外包账户及时回收。" `
                -Reference "T1078 (Valid Accounts)"
        } else {
            Add-Finding -Category '账户卫生' -Title "未发现超过 $StaleDays 天未登录的启用账户" -Severity 'Info' -Passed $true -Description "账户活跃度良好。"
        }
        Write-Step "僵尸账户检查完成" 'OK'
    } catch {
        Write-Step "僵尸账户检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-PrivilegedOldPasswords {
    Write-Step "检查特权账户口令老化（>$OldPasswordDays 天）..." 'RUN'
    try {
        $threshold = (Get-Date).AddDays(-$OldPasswordDays)
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(adminCount=1))' `
            -Properties @('sAMAccountName','pwdLastSet','userAccountControl')
        $rows = @()
        foreach ($r in $res) {
            $uac = [int](Get-Prop $r 'userAccountControl' 0)
            if (Test-UacFlag $uac $script:UAC.ACCOUNTDISABLE) { continue }
            $pwd = Convert-FileTimeToDate (Get-Prop $r 'pwdLastSet')
            if ($pwd -and $pwd -lt $threshold) {
                $rows += @{
                    '特权账户' = [string](Get-Prop $r 'sAMAccountName')
                    '口令设置时间' = $pwd.ToString('yyyy-MM-dd')
                    '口令年龄(天)' = [math]::Round(((Get-Date) - $pwd).TotalDays)
                }
            }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category '特权账户' -Title "特权账户口令长期未更换（$($rows.Count) 个）" -Severity 'High' `
                -Description "受 adminCount 保护的特权账户口令超过 $OldPasswordDays 天未更换，一旦历史泄露危害极大。" `
                -Affected ($rows | Sort-Object { -[int]$_['口令年龄(天)'] }) `
                -Remediation "对所有特权账户立即轮换高强度口令并建立定期轮换机制；推行分层管理 (Tiering) 与专用管理账户/PAW。" `
                -Reference "Microsoft Privileged Access / T1078"
        } else {
            Add-Finding -Category '特权账户' -Title "未发现口令老化的特权账户" -Severity 'Info' -Passed $true -Description "特权账户口令年龄正常。"
        }
        Write-Step "特权账户口令检查完成" 'OK'
    } catch {
        Write-Step "特权账户口令检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-SidHistory {
    Write-Step "检查 SID History ..." 'RUN'
    try {
        $res = Invoke-LdapQuery -Filter '(sIDHistory=*)' -Properties @('sAMAccountName','sIDHistory')
        $rows = @()
        foreach ($r in $res) {
            $sids = @()
            foreach ($b in (Get-PropAll $r 'sIDHistory')) {
                try { $sids += (New-Object System.Security.Principal.SecurityIdentifier($b,0)).Value } catch {}
            }
            $rows += @{ '账户' = [string](Get-Prop $r 'sAMAccountName'); 'SIDHistory' = ($sids -join '; ') }
        }
        if ($rows.Count -gt 0) {
            # SID History 含特权 SID（如 -512 域管 / -519 企业管理员 / -518）尤为可疑
            $suspicious = $rows | Where-Object { $_['SIDHistory'] -match '-512$|-519$|-518$|-516$|-500$' }
            $sev = if ($suspicious.Count -gt 0) { 'High' } else { 'Medium' }
            Add-Finding -Category '持久化 / 提权' -Title "存在配置了 SID History 的账户（$($rows.Count) 个）" -Severity $sev `
                -Description "SID History 常用于域迁移，但也被攻击者滥用于隐蔽提权与持久化（在普通账户上注入特权组 SID）。请确认每条 SID History 均来自合法迁移。$(if($suspicious.Count -gt 0){"`n⚠ 其中有账户的 SID History 指向高特权 RID（512/519 等），高度可疑！"})" `
                -Affected $rows `
                -Remediation "核对来源；对非迁移场景或可疑的 SID History 予以清除；启用信任的 SID Filtering。" `
                -Reference "MITRE ATT&CK T1134.005 (SID-History Injection)"
        } else {
            Add-Finding -Category '持久化 / 提权' -Title '未发现 SID History' -Severity 'Info' -Passed $true -Description "无账户设置 sIDHistory。"
        }
        Write-Step "SID History 检查完成" 'OK'
    } catch {
        Write-Step "SID History 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

#endregion


#region ========================= 检查项：特权组与防护组件 =========================

function Resolve-GroupMembers {
    <#
        通过组的 well-known RID 解析成员（递归）。
        返回成员对象数组：@{ sAMAccountName; class; enabled; dn }
    #>
    param([string]$GroupRid, [string]$GroupNameFallback)

    $groupDn = $null
    if ($script:DomainSid -and $GroupRid) {
        # 用 objectSid 精确匹配，避免本地化组名问题
        try {
            $sidStr = "$($script:DomainSid)-$GroupRid"
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
            $bytes = New-Object 'byte[]' $sid.BinaryLength
            $sid.GetBinaryForm($bytes, 0)
            $hex = ($bytes | ForEach-Object { '\{0:x2}' -f $_ }) -join ''
            $res = Invoke-LdapQuery -Filter "(objectSid=$hex)" -Properties @('distinguishedName','sAMAccountName')
            foreach ($r in $res) { $groupDn = [string](Get-Prop $r 'distinguishedName'); break }
        } catch {}
    }
    if (-not $groupDn -and $GroupNameFallback) {
        $res = Invoke-LdapQuery -Filter "(&(objectCategory=group)(sAMAccountName=$GroupNameFallback))" -Properties @('distinguishedName')
        foreach ($r in $res) { $groupDn = [string](Get-Prop $r 'distinguishedName'); break }
    }
    if (-not $groupDn) { return @() }

    # 使用 LDAP_MATCHING_RULE_IN_CHAIN 递归获取所有成员
    $res = Invoke-LdapQuery -Filter "(memberOf:1.2.840.113556.1.4.1941:=$groupDn)" `
        -Properties @('sAMAccountName','objectClass','userAccountControl','objectCategory')
    $members = @()
    foreach ($r in $res) {
        $uac = [int](Get-Prop $r 'userAccountControl' 0)
        $classes = (Get-PropAll $r 'objectClass') -join ','
        $type = if ($classes -match 'computer') { '计算机' } elseif ($classes -match 'group') { '组' } else { '用户' }
        $members += @{
            sAMAccountName = [string](Get-Prop $r 'sAMAccountName')
            class = $type
            enabled = -not (Test-UacFlag $uac $script:UAC.ACCOUNTDISABLE)
        }
    }
    return $members
}

function Test-PrivilegedGroups {
    Write-Step "枚举特权组成员（递归）..." 'RUN'
    try {
        # RID -> 友好名称
        $groups = [ordered]@{
            '512' = 'Domain Admins (域管理员)'
            '519' = 'Enterprise Admins (企业管理员)'
            '518' = 'Schema Admins (架构管理员)'
            '544' = 'Administrators (内置管理员)'   # 注意 544 是 builtin domain 下，非域 SID 后缀
            '548' = 'Account Operators (账户操作员)'
            '549' = 'Server Operators (服务器操作员)'
            '550' = 'Print Operators (打印操作员)'
            '551' = 'Backup Operators (备份操作员)'
        }
        # Builtin 组 (544/548/549/550/551) 使用固定 SID S-1-5-32-RID
        $builtinRids = '544','548','549','550','551'

        $allCounts = @()
        foreach ($rid in $groups.Keys) {
            $name = $groups[$rid]
            $members = @()
            try {
                if ($builtinRids -contains $rid) {
                    # builtin SID = S-1-5-32-RID
                    $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-$rid")
                    $bytes = New-Object 'byte[]' $sid.BinaryLength
                    $sid.GetBinaryForm($bytes,0)
                    $hex = ($bytes | ForEach-Object { '\{0:x2}' -f $_ }) -join ''
                    $g = Invoke-LdapQuery -Filter "(objectSid=$hex)" -Properties @('distinguishedName')
                    $dn = $null
                    foreach ($r in $g) { $dn = [string](Get-Prop $r 'distinguishedName'); break }
                    if ($dn) {
                        $res = Invoke-LdapQuery -Filter "(memberOf:1.2.840.113556.1.4.1941:=$dn)" -Properties @('sAMAccountName','objectClass','userAccountControl')
                        foreach ($r in $res) {
                            $uac = [int](Get-Prop $r 'userAccountControl' 0)
                            $classes = (Get-PropAll $r 'objectClass') -join ','
                            $type = if ($classes -match 'computer') { '计算机' } elseif ($classes -match 'group') { '组' } else { '用户' }
                            $members += @{ sAMAccountName=[string](Get-Prop $r 'sAMAccountName'); class=$type; enabled=(-not (Test-UacFlag $uac $script:UAC.ACCOUNTDISABLE)) }
                        }
                    }
                } else {
                    $members = Resolve-GroupMembers -GroupRid $rid
                }
            } catch {}

            $rows = @()
            foreach ($m in $members) {
                $rows += @{ '成员' = $m.sAMAccountName; '类型' = $m.class; '状态' = $(if($m.enabled){'启用'}else{'禁用'}) }
            }
            $allCounts += @{ '特权组' = $name; '成员数' = $rows.Count }

            if ($rows.Count -gt 0) {
                # 重点：成员过多 或 含计算机账户 视为风险
                $hasComputer = ($members | Where-Object { $_.class -eq '计算机' }).Count -gt 0
                $sev = 'Info'; $passed = $true; $extra = ''
                if ($rid -eq '512' -and $rows.Count -gt 10) { $sev='Medium'; $passed=$false; $extra="域管理员成员偏多（$($rows.Count)），建议精简至个位数。" }
                if (($rid -eq '548' -or $rid -eq '549' -or $rid -eq '550' -or $rid -eq '551') -and $rows.Count -gt 0) {
                    $sev='Medium'; $passed=$false; $extra="$name 拥有可被滥用以提权的强权限，应保持为空或最小化。"
                }
                if ($hasComputer) { $sev='High'; $passed=$false; $extra += ' 该组包含计算机账户，异常且高危。' }

                Add-Finding -Category '特权账户' -Title "$name 成员（$($rows.Count) 个）" -Severity $sev -Passed $passed `
                    -Description ("特权组成员清单。$extra".Trim()) `
                    -Affected $rows `
                    -Remediation "遵循最小权限：仅保留必需的管理员；使用专用管理账户与分层模型 (Tier 0/1/2)；定期审阅成员；高敏组日常应为空，需要时临时提权 (JIT/PIM)。" `
                    -Reference "Microsoft Tiered Administration"
            }
        }
        Write-Step "特权组枚举完成" 'OK'
    } catch {
        Write-Step "特权组枚举失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-ProtectedUsers {
    Write-Step "检查特权账户是否纳入 Protected Users ..." 'RUN'
    try {
        # Protected Users RID = 525
        $members = Resolve-GroupMembers -GroupRid '525'
        $protectedSet = @{}
        foreach ($m in $members) { $protectedSet[$m.sAMAccountName] = $true }

        # 取域管理员成员
        $da = Resolve-GroupMembers -GroupRid '512'
        $notProtected = @()
        foreach ($m in $da) {
            if ($m.class -eq '用户' -and -not $protectedSet.ContainsKey($m.sAMAccountName)) {
                $notProtected += @{ '域管账户' = $m.sAMAccountName; '是否在 Protected Users' = '否' }
            }
        }
        if ($notProtected.Count -gt 0) {
            Add-Finding -Category '特权账户' -Title "部分域管理员未加入 Protected Users 组（$($notProtected.Count) 个）" -Severity 'Medium' `
                -Description "Protected Users 组可强制成员使用更强的 Kerberos 保护（禁用 NTLM/RC4/委派/凭据缓存等），显著降低凭据被窃取后被滥用的风险。建议将敏感管理员账户纳入。" `
                -Affected $notProtected `
                -Remediation "将 Tier-0 管理员账户加入 Protected Users 组（注意先在测试账户验证兼容性，避免影响需要委派/老协议的场景）；同时勾选『账户敏感，不能被委派』。" `
                -Reference "Microsoft Protected Users Security Group"
        } else {
            Add-Finding -Category '特权账户' -Title '域管理员均已纳入 Protected Users（或无适用账户）' -Severity 'Info' -Passed $true `
                -Description "未发现未受保护的域管理员用户账户。"
        }
        Write-Step "Protected Users 检查完成" 'OK'
    } catch {
        Write-Step "Protected Users 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-Laps {
    Write-Step "检查 LAPS 本地管理员密码方案部署情况 ..." 'RUN'
    try {
        # 统计计算机总数
        $allComp = Invoke-LdapQuery -Filter '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' -Properties @('sAMAccountName')
        $total = @($allComp).Count

        # 传统 LAPS: ms-Mcs-AdmPwdExpirationTime ; Windows LAPS: msLAPS-PasswordExpirationTime
        $lapsLegacy = 0; $lapsNew = 0
        try {
            $r1 = Invoke-LdapQuery -Filter '(ms-Mcs-AdmPwdExpirationTime=*)' -Properties @('sAMAccountName')
            $lapsLegacy = @($r1).Count
        } catch {}
        try {
            $r2 = Invoke-LdapQuery -Filter '(msLAPS-PasswordExpirationTime=*)' -Properties @('sAMAccountName')
            $lapsNew = @($r2).Count
        } catch {}
        $covered = $lapsLegacy + $lapsNew

        if ($total -gt 0 -and $covered -eq 0) {
            Add-Finding -Category '系统加固' -Title '未检测到 LAPS 部署' -Severity 'High' `
                -Description "未在任何计算机对象上发现 LAPS（传统 ms-Mcs-AdmPwd 或 Windows LAPS）属性。若全域本地管理员使用相同口令，攻击者攻陷一台主机后即可凭 Pass-the-Hash 横向移动到所有主机。" `
                -Affected @(@{ '计算机总数' = $total; '已纳管(LAPS)' = $covered }) `
                -Remediation "部署 Windows LAPS（Server 2019+/Win10+ 内置）为每台主机随机化本地管理员口令并定期轮换；通过 GPO 强制启用。" `
                -Reference "Microsoft LAPS / T1078.003"
        } elseif ($total -gt 0 -and $covered -lt $total) {
            $pct = [math]::Round($covered / $total * 100)
            Add-Finding -Category '系统加固' -Title "LAPS 覆盖不完整（$covered/$total，约 $pct%）" -Severity 'Medium' `
                -Description "部分计算机未纳入 LAPS 管理，未覆盖的主机可能仍使用统一本地管理员口令。" `
                -Affected @(@{ '计算机总数' = $total; '已纳管(LAPS)' = $covered; '传统LAPS' = $lapsLegacy; 'WindowsLAPS' = $lapsNew }) `
                -Remediation "排查未纳管主机，将其全部纳入 LAPS；核对 GPO 作用范围。" `
                -Reference "Microsoft LAPS"
        } else {
            Add-Finding -Category '系统加固' -Title 'LAPS 已基本覆盖' -Severity 'Info' -Passed $true `
                -Description "检测到 LAPS 属性覆盖了全部/绝大多数计算机（$covered/$total）。"
        }
        Write-Step "LAPS 检查完成" 'OK'
    } catch {
        Write-Step "LAPS 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

#endregion


#region ========================= 检查项：ACL / SYSVOL =========================

function Test-DCSyncRights {
    Write-Step "检查域对象上的 DCSync (目录复制) 权限 ..." 'RUN'
    try {
        # 复制权限对应的扩展权限 GUID
        $repGuids = @{
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
            '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
        }
        # 默认应拥有该权限的内置主体（域控/管理员等），用于降噪
        $expected = @('Domain Controllers','Enterprise Domain Controllers','Administrators','Domain Admins',
                      'Enterprise Admins','SYSTEM','Enterprise Read-only Domain Controllers','Read-only Domain Controllers',
                      'Built-in Administrators','Domain Admins','Key Admins','Enterprise Key Admins')

        $de = Get-DirectoryEntry $script:DomainDN
        $acl = $de.ObjectSecurity
        $rows = @()
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $g = $ace.ObjectType.ToString().ToLower()
            if ($repGuids.ContainsKey($g) -or $g -eq '00000000-0000-0000-0000-000000000000' -and ($ace.ActiveDirectoryRights -match 'ExtendedRight')) {
                if ($repGuids.ContainsKey($g)) {
                    $who = $ace.IdentityReference.Value
                    $shortWho = ($who -split '\\')[-1]
                    $isExpected = $false
                    foreach ($e in $expected) { if ($shortWho -like "*$e*") { $isExpected = $true; break } }
                    if (-not $isExpected) {
                        $rows += @{ '主体' = $who; '权限' = $repGuids[$g] }
                    }
                }
            }
        }
        $de.Dispose()

        if ($rows.Count -gt 0) {
            # 把同一主体的多条复制权限聚合
            Add-Finding -Category 'ACL / 凭据窃取' -Title "发现非预期主体拥有目录复制 (DCSync) 权限（$($rows.Count) 条）" -Severity 'Critical' `
                -Description "拥有 DS-Replication-Get-Changes(-All) 权限的主体可执行 DCSync，远程导出包括 krbtgt 在内的所有账户哈希，等同于完全控制域。以下主体并非默认的域控/管理员，属高危授权。" `
                -Affected $rows `
                -Remediation "立即核查这些授权的来源与必要性，移除非预期的复制权限；仅域控及必要的同步服务（如 Azure AD Connect 的专用账户，且应严格限定）才应拥有该权限；开启对域对象 ACL 变更的审计。" `
                -Reference "MITRE ATT&CK T1003.006 (DCSync)"
        } else {
            Add-Finding -Category 'ACL / 凭据窃取' -Title '未发现非预期的 DCSync 权限授予' -Severity 'Info' -Passed $true `
                -Description "域对象上的目录复制权限仅授予默认的域控/管理员主体。（注：本检查依赖当前账户能否读取域对象 ACL。）"
        }
        Write-Step "DCSync 权限检查完成" 'OK'
    } catch {
        Write-Step "DCSync 权限检查失败（可能无权读取 ACL）: $($_.Exception.Message)" 'WARN'
        Add-Finding -Category 'ACL / 凭据窃取' -Title 'DCSync 权限检查未完成' -Severity 'Low' `
            -Description "无法读取域对象的访问控制列表，可能是当前账户权限不足或连接受限。建议以具备读取 nTSecurityDescriptor 权限的账户复查。" `
            -Remediation "使用可读取域 ACL 的账户重新运行，或借助 BloodHound 等工具进行 ACL 攻击路径分析。"
    }
}

function Test-OrphanedAdminCount {
    Write-Step "检查孤立的 adminCount=1 账户 ..." 'RUN'
    try {
        # adminCount=1 但当前不在任何受保护组中的用户（可能是历史遗留，ACL 仍被 AdminSDHolder 锁定）
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(adminCount=1))' `
            -Properties @('sAMAccountName','memberOf','userAccountControl')
        $rows = @()
        foreach ($r in $res) {
            $sam = [string](Get-Prop $r 'sAMAccountName')
            if ($sam -eq 'krbtgt') { continue }
            $memberOf = (Get-PropAll $r 'memberOf') -join ';'
            # 若不再隶属常见特权组，视为可能的孤立 adminCount
            if ($memberOf -notmatch 'Admins|Operators|Administrators') {
                $rows += @{ '账户' = $sam }
            }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category '特权账户' -Title "存在可能孤立的 adminCount=1 账户（$($rows.Count) 个）" -Severity 'Low' `
                -Description "这些账户带有 adminCount=1 但当前已不在明显的特权组中。它们曾是特权账户，其 ACL 继承被 AdminSDHolder 接管（不再继承 OU 的委派）。需确认是否为历史遗留，避免被忽视的『隐性特权』。" `
                -Affected $rows `
                -Remediation "确认账户当前应有的权限；若确不再需要特权，清理 adminCount 属性并恢复 ACL 继承（需谨慎操作）；审阅 AdminSDHolder 的 ACL。" `
                -Reference "AdminSDHolder / SDProp"
        } else {
            Add-Finding -Category '特权账户' -Title '未发现明显孤立的 adminCount 账户' -Severity 'Info' -Passed $true -Description "adminCount=1 的账户均仍在特权组中。"
        }
        Write-Step "adminCount 检查完成" 'OK'
    } catch {
        Write-Step "adminCount 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-GppPassword {
    if ($SkipSysvolCheck) {
        Write-Step "已按参数跳过 SYSVOL GPP cpassword 扫描" 'WARN'
        return
    }
    Write-Step "扫描 SYSVOL 中的 GPP cpassword（仅扫 Preferences 目录，限时 $SysvolTimeoutSeconds 秒）..." 'RUN'
    try {
        # 取域 DNS 名
        $domainDns = ($script:DomainDN -replace 'DC=','' -replace ',', '.')
        $sysvol = "\\$domainDns\SYSVOL\$domainDns\Policies"

        # 在后台作业中执行文件遍历，并设置超时，避免大型域 / 慢网络下长时间无响应。
        # 同时仅深入每个 GPO 的 Machine\Preferences 与 User\Preferences 目录
        # （GPP cpassword 只可能出现在这里），避免遍历整棵策略树。
        $job = Start-Job -ScriptBlock {
            param($policiesPath)
            $targetNames = 'Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Printers.xml','Drives.xml'
            if (-not (Test-Path $policiesPath)) { return ,@('__NOPATH__') }
            $hits = New-Object System.Collections.ArrayList
            $gpoDirs = Get-ChildItem -Path $policiesPath -Directory -ErrorAction SilentlyContinue
            foreach ($gpo in $gpoDirs) {
                foreach ($scope in 'Machine','User') {
                    $pref = Join-Path $gpo.FullName "$scope\Preferences"
                    if (Test-Path $pref) {
                        $files = Get-ChildItem -Path $pref -Recurse -File -Include $targetNames -ErrorAction SilentlyContinue
                        foreach ($f in $files) {
                            try {
                                $c = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
                                if ($c -match 'cpassword="([^"]+)"') { [void]$hits.Add($f.FullName) }
                            } catch {}
                        }
                    }
                }
            }
            return ,@($hits)
        } -ArgumentList $sysvol

        $done = Wait-Job -Job $job -Timeout $SysvolTimeoutSeconds
        if (-not $done) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            Write-Step "SYSVOL 扫描超时（>$SysvolTimeoutSeconds 秒），已跳过" 'WARN'
            Add-Finding -Category '凭据窃取' -Title 'SYSVOL GPP 扫描超时未完成' -Severity 'Low' `
                -Description "SYSVOL 文件遍历超过 $SysvolTimeoutSeconds 秒（可能因 GPO 数量多或网络较慢）。本项未完成，请手工补充核查。" `
                -Remediation "可用 -SysvolTimeoutSeconds 增大超时阈值，或用 -SkipSysvolCheck 跳过；亦可在域控本地直接核查 Policies 目录中各 GPO 的 Preferences\*.xml 是否含 cpassword。"
            return
        }

        $result = @(Receive-Job -Job $job -ErrorAction SilentlyContinue)
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

        if ($result.Count -ge 1 -and $result[0] -eq '__NOPATH__') {
            Write-Step "无法访问 $sysvol，跳过" 'WARN'
            Add-Finding -Category '凭据窃取' -Title 'SYSVOL GPP 扫描未完成' -Severity 'Low' `
                -Description "无法访问 $sysvol，未能完成 GPP cpassword 扫描。" `
                -Remediation "确认终端可访问 SYSVOL 共享后重试，或在域控本地排查 Policies 目录。"
            return
        }

        $hits = @()
        foreach ($p in $result) {
            if ($p) { $hits += @{ '策略文件' = [string]$p; '说明' = '包含 cpassword 字段（微软固定 AES 密钥可解密为明文）' } }
        }
        if ($hits.Count -gt 0) {
            Add-Finding -Category '凭据窃取' -Title "SYSVOL 中发现 GPP cpassword（$($hits.Count) 处）" -Severity 'Critical' `
                -Description "组策略首选项 (GPP) 文件中包含 cpassword 字段。微软公开了用于加密它的固定 AES 密钥 (MS14-025)，任意域用户均可读取 SYSVOL 并将其解密为明文口令。" `
                -Affected $hits `
                -Remediation "删除这些 GPP 文件中的口令配置；安装 MS14-025 补丁；改用 LAPS 管理本地管理员口令；轮换所有曾经通过 GPP 下发过的口令。" `
                -Reference "MS14-025 / MITRE ATT&CK T1552.006"
        } else {
            Add-Finding -Category '凭据窃取' -Title 'SYSVOL 未发现 GPP cpassword' -Severity 'Info' -Passed $true `
                -Description "已扫描 SYSVOL\Policies 下的 GPP XML 文件，未发现 cpassword 字段。"
        }
        Write-Step "GPP cpassword 扫描完成" 'OK'
    } catch {
        Write-Step "GPP cpassword 扫描失败: $($_.Exception.Message)" 'ERR'
    }
}

#endregion


#region ========================= 检查项：扩展风险（AD CS / 加密 / 机密 / 卫生）=========================

# ---- 低权限/宽泛主体 SID 表（用于判断"授权过宽"） ----
function Get-LowPrivSidTable {
    $t = @{
        'S-1-1-0'      = 'Everyone'
        'S-1-5-7'      = 'Anonymous Logon'
        'S-1-5-11'     = 'Authenticated Users'
        'S-1-5-32-545' = 'Users (内置)'
    }
    if ($script:DomainSid) {
        $t["$($script:DomainSid)-513"] = 'Domain Users'
        $t["$($script:DomainSid)-515"] = 'Domain Computers'
    }
    return $t
}

# ---- 检测某对象 ACL 中，低权限主体是否拥有"危险/宽泛"权限 ----
function Get-BroadAclGrants {
    param(
        [Parameter(Mandatory)] [string]$Dn,
        [string[]]$ExtendedRightGuids = @(),   # 视为危险的扩展权限 GUID（小写）
        [switch]$IncludeWrite                   # 是否把 Write* 视为危险
    )
    $lowPriv = Get-LowPrivSidTable
    $found = @()
    try {
        $de = Get-DirectoryEntry $Dn
        $sd = $de.ObjectSecurity
        if ($null -eq $sd) { $de.Dispose(); return @() }
        foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = $ace.IdentityReference.Value
            if (-not $lowPriv.ContainsKey($sid)) { continue }
            $rights = [string]$ace.ActiveDirectoryRights
            $objType = ([string]$ace.ObjectType).ToLower()
            $why = $null
            if ($rights -match 'GenericAll') { $why = 'GenericAll(完全控制)' }
            elseif ($rights -match 'ExtendedRight' -and $objType -eq '00000000-0000-0000-0000-000000000000') { $why = 'AllExtendedRights' }
            elseif ($rights -match 'ExtendedRight' -and ($ExtendedRightGuids -contains $objType)) { $why = '指定扩展权限(如 Enroll)' }
            elseif ($IncludeWrite -and ($rights -match 'WriteDacl|WriteOwner|GenericWrite|WriteProperty')) { $why = $rights }
            if ($why) { $found += @{ identity = $lowPriv[$sid]; right = $why } }
        }
        $de.Dispose()
    } catch {}
    return $found
}

function Test-AdcsTemplates {
    Write-Step "检查 AD CS 证书模板漏洞 (ESC1/2/3/4) ..." 'RUN'
    try {
        if ([string]::IsNullOrEmpty($script:ConfigDN)) { Write-Step "无 Configuration NC，跳过 AD CS" 'WARN'; return }
        $pkiBase = "CN=Public Key Services,CN=Services,$($script:ConfigDN)"
        $tplRoot = "CN=Certificate Templates,$pkiBase"
        $caRoot  = "CN=Enrollment Services,$pkiBase"

        # 1) 枚举企业 CA 及其已发布模板（仅评估已发布模板，降低误报）
        $publishedTpls = @{}
        $caList = @()
        try {
            $caRes = Invoke-LdapQuery -Filter '(objectClass=pKIEnrollmentService)' -Properties @('name','dNSHostName','certificateTemplates') -SearchRoot $caRoot
            foreach ($r in $caRes) {
                $caList += @{ 'CA' = [string](Get-Prop $r 'name'); '主机' = [string](Get-Prop $r 'dNSHostName') }
                foreach ($t in (Get-PropAll $r 'certificateTemplates')) { $publishedTpls[[string]$t] = $true }
            }
        } catch {}

        if ($caList.Count -eq 0) {
            Add-Finding -Category 'AD CS' -Title '未发现 AD CS 证书颁发机构' -Severity 'Info' -Passed $true -Description "域内未检测到企业 CA (pKIEnrollmentService)。"
            Write-Step "AD CS 检查完成（无 CA）" 'OK'
            return
        }
        Add-Finding -Category 'AD CS' -Title "发现 $($caList.Count) 个证书颁发机构 (CA)" -Severity 'Info' -Passed $true -Description "企业 CA 清单。" -Affected $caList

        $clientAuthEku  = @('1.3.6.1.5.5.7.3.2','1.3.6.1.5.2.3.4','1.3.6.1.4.1.311.20.2.2','2.5.29.37.0')
        $anyPurposeEku  = '2.5.29.37.0'
        $enrollAgentEku = '1.3.6.1.4.1.311.20.2.1'
        $enrollGuid     = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
        $autoEnrollGuid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

        $vulns = @()
        $tplRes = Invoke-LdapQuery -Filter '(objectClass=pKICertificateTemplate)' `
            -Properties @('name','displayName','pKIExtendedKeyUsage','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-RA-Signature') -SearchRoot $tplRoot
        foreach ($r in $tplRes) {
            $name = [string](Get-Prop $r 'name')
            if (-not $publishedTpls.ContainsKey($name)) { continue }
            $nameFlag = [int](Get-Prop $r 'msPKI-Certificate-Name-Flag' 0)
            $enrollFlag = [int](Get-Prop $r 'msPKI-Enrollment-Flag' 0)
            $raSig = [int](Get-Prop $r 'msPKI-RA-Signature' 0)
            $ekus = @(Get-PropAll $r 'pKIExtendedKeyUsage')
            $suppliesSubject = (($nameFlag -band 0x1) -eq 0x1)
            $managerApproval = (($enrollFlag -band 0x2) -eq 0x2)
            $hasClientAuth = $false; foreach ($e in $ekus) { if ($clientAuthEku -contains [string]$e) { $hasClientAuth = $true } }
            $noEku = ($ekus.Count -eq 0)
            $hasAnyPurpose = ($ekus -contains $anyPurposeEku)
            $hasEnrollAgent = ($ekus -contains $enrollAgentEku)
            $dn = "CN=$name,$tplRoot"

            $enrollGrants = Get-BroadAclGrants -Dn $dn -ExtendedRightGuids @($enrollGuid,$autoEnrollGuid)
            $whoEnroll = (($enrollGrants | ForEach-Object { $_.identity }) | Select-Object -Unique) -join ', '

            $esc = @()
            if ($enrollGrants.Count -gt 0 -and -not $managerApproval -and $raSig -le 0) {
                if ($suppliesSubject -and ($hasClientAuth -or $noEku)) { $esc += 'ESC1' }
                if ($hasAnyPurpose -or $noEku) { $esc += 'ESC2' }
                if ($hasEnrollAgent) { $esc += 'ESC3' }
            }
            if ($esc.Count -gt 0) {
                $vulns += @{ '模板'=$name; '风险'=($esc -join ', '); '低权限主体'=$whoEnroll; '可自定义主体(SAN)'=$(if($suppliesSubject){'是'}else{'否'}); '需审批'=$(if($managerApproval){'是'}else{'否'}) }
            }
            $writeGrants = Get-BroadAclGrants -Dn $dn -IncludeWrite
            if ($writeGrants.Count -gt 0) {
                $vulns += @{ '模板'=$name; '风险'='ESC4(模板可被低权限改写)'; '低权限主体'=(($writeGrants | ForEach-Object { $_.identity }) | Select-Object -Unique) -join ', '; '可自定义主体(SAN)'='-'; '需审批'='-' }
            }
        }

        if ($vulns.Count -gt 0) {
            Add-Finding -Category 'AD CS' -Title "存在可被滥用的证书模板（$($vulns.Count) 项）" -Severity 'Critical' `
                -Description "以下已发布证书模板存在配置缺陷，低权限用户可申请到用于身份冒充的证书并提权至域管理员（域接管）。ESC1=可自定义主体+客户端认证 EKU；ESC2=Any Purpose/无 EKU；ESC3=注册代理；ESC4=模板 ACL 可被低权限改写。本工具仅枚举配置，不申请证书。" `
                -Affected $vulns `
                -Remediation "移除模板上对 Domain Users/Authenticated Users 的申请/写权限；关闭 ENROLLEE_SUPPLIES_SUBJECT 或启用管理员审批/RA 签名；收紧 EKU；下架不需要的模板；CA 启用强证书绑定并打齐补丁。建议用 Certify/Certipy 复核 ESC5-ESC11/13/15。" `
                -Reference "Certified Pre-Owned (ESC1-ESC4)"
        } else {
            Add-Finding -Category 'AD CS' -Title '未发现明显可滥用的证书模板' -Severity 'Info' -Passed $true -Description "已评估已发布模板的 ESC1/2/3/4 特征，未发现低权限可滥用项。"
        }
        Write-Step "AD CS 检查完成" 'OK'
    } catch {
        Write-Step "AD CS 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-WeakKerberosEncryption {
    Write-Step "检查弱 Kerberos 加密类型 (RC4/DES) ..." 'RUN'
    try {
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(|(servicePrincipalName=*)(adminCount=1)))' `
            -Properties @('sAMAccountName','msDS-SupportedEncryptionTypes','adminCount','servicePrincipalName','userAccountControl')
        $rows = @()
        foreach ($r in $res) {
            $uac = [int](Get-Prop $r 'userAccountControl' 0)
            if (Test-UacFlag $uac $script:UAC.ACCOUNTDISABLE) { continue }
            $sam = [string](Get-Prop $r 'sAMAccountName')
            if ($sam -eq 'krbtgt') { continue }
            $raw = Get-Prop $r 'msDS-SupportedEncryptionTypes'
            $isPriv = [int](Get-Prop $r 'adminCount' 0) -ge 1
            $tp = $(if($isPriv){'特权'}else{'服务'})
            if ($null -eq $raw) {
                $rows += @{ '账户'=$sam; '类型'=$tp; '加密设置'='未配置(可能回退 RC4)' }
            } else {
                $et = [int]$raw
                if (($et -band 0x3) -ne 0) { $rows += @{ '账户'=$sam; '类型'=$tp; '加密设置'='允许 DES(极弱)' } }
                elseif (($et -band 0x4) -ne 0 -and ($et -band 0x18) -eq 0) { $rows += @{ '账户'=$sam; '类型'=$tp; '加密设置'='仅 RC4(无 AES)' } }
            }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category 'Kerberos / 加密' -Title "存在使用弱 Kerberos 加密的服务/特权账户（$($rows.Count) 个）" -Severity 'Medium' `
                -Description "这些账户允许 DES 或仅 RC4（未启用 AES）。RC4/DES 票据更易被离线破解（配合 Kerberoasting），削弱了口令强度的保护。" `
                -Affected $rows `
                -Remediation "为账户配置 msDS-SupportedEncryptionTypes 启用 AES128/AES256（值含 0x18），并在域内逐步禁用 RC4/DES；服务账户尽量迁移 gMSA。" `
                -Reference "RC4 弃用 / Kerberoasting 加固"
        } else {
            Add-Finding -Category 'Kerberos / 加密' -Title '未发现弱加密的服务/特权账户' -Severity 'Info' -Passed $true -Description "相关账户均已启用 AES 或未启用弱加密。"
        }
        Write-Step "弱加密检查完成" 'OK'
    } catch {
        Write-Step "弱加密检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-HighRiskGroups {
    Write-Step "检查高危但易被忽视的组 (DnsAdmins 等) ..." 'RUN'
    try {
        $groups = @(
            @{ name='DnsAdmins'; sev='High'; risk='成员可让 DNS 服务(运行于 DC)加载任意 DLL，等同 DC 代码执行' },
            @{ name='Group Policy Creator Owners'; sev='Medium'; risk='可创建/链接 GPO，潜在横向与提权' },
            @{ name='Cert Publishers'; sev='Medium'; risk='可向用户对象/ NTAuth 发布证书，PKI 相关风险' },
            @{ name='DnsUpdateProxy'; sev='Medium'; risk='DNS 记录可被任意覆盖（投毒）' }
        )
        $any = $false
        foreach ($g in $groups) {
            $gr = Invoke-LdapQuery -Filter "(&(objectCategory=group)(sAMAccountName=$($g.name)))" -Properties @('distinguishedName')
            $dn = $null; foreach ($x in $gr) { $dn = [string](Get-Prop $x 'distinguishedName'); break }
            if (-not $dn) { continue }
            $mres = Invoke-LdapQuery -Filter "(memberOf:1.2.840.113556.1.4.1941:=$dn)" -Properties @('sAMAccountName','objectClass')
            $rows = @()
            foreach ($m in $mres) {
                $classes = (Get-PropAll $m 'objectClass') -join ','
                $type = if ($classes -match 'computer'){'计算机'} elseif ($classes -match 'group'){'组'} else {'用户'}
                $rows += @{ '成员'=[string](Get-Prop $m 'sAMAccountName'); '类型'=$type }
            }
            if ($rows.Count -gt 0) {
                $any = $true
                Add-Finding -Category '特权账户' -Title "$($g.name) 组非空（$($rows.Count) 个成员）" -Severity $g.sev `
                    -Description "$($g.risk)。请核实成员的业务必要性。" -Affected $rows `
                    -Remediation "遵循最小权限，移除不必要成员；DnsAdmins 等高危组应尽量为空或仅含受控管理账户。" `
                    -Reference "DnsAdmins DLL Injection 等"
            }
        }
        if (-not $any) {
            Add-Finding -Category '特权账户' -Title '高危易忽视组均为空' -Severity 'Info' -Passed $true -Description "DnsAdmins 等组未发现成员。"
        }
        Write-Step "高危组检查完成" 'OK'
    } catch {
        Write-Step "高危组检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-SecretsInAttributes {
    Write-Step "检查账户属性中的明文口令/可读机密 ..." 'RUN'
    try {
        $filter = '(&(objectClass=user)(|(description=*pass*)(description=*pwd*)(description=*密码*)(description=*口令*)(info=*pass*)(info=*pwd*)(info=*密码*)))'
        $res = Invoke-LdapQuery -Filter $filter -Properties @('sAMAccountName','description','info')
        $rows = @()
        foreach ($r in $res) {
            $d = [string](Get-Prop $r 'description'); $i = [string](Get-Prop $r 'info')
            $rows += @{ '账户'=[string](Get-Prop $r 'sAMAccountName'); '可疑字段'=("$d $i").Trim() }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category '凭据窃取' -Title "账户描述/备注疑似含明文口令（$($rows.Count) 个）" -Severity 'High' `
                -Description "description/info 等字段任意域用户可读，若包含口令将直接泄露凭据。" -Affected $rows `
                -Remediation "清除字段中的口令信息并轮换相关账户口令；规范运维不要把口令写入对象属性。" `
                -Reference "MITRE ATT&CK T1552 (Unsecured Credentials)"
        } else {
            Add-Finding -Category '凭据窃取' -Title '未在描述字段发现明文口令关键字' -Severity 'Info' -Passed $true -Description "未匹配到 pass/pwd/密码/口令 等关键字。"
        }

        $secretAttrs = 'userPassword','unixUserPassword','ms-Mcs-AdmPwd'
        foreach ($attr in $secretAttrs) {
            try {
                $sr = Invoke-LdapQuery -Filter "($attr=*)" -Properties @('sAMAccountName',$attr)
                $names = @(); foreach ($x in $sr) { $names += [string](Get-Prop $x 'sAMAccountName') }
                if ($names.Count -gt 0) {
                    $sev = if ($attr -eq 'ms-Mcs-AdmPwd') { 'High' } else { 'Medium' }
                    Add-Finding -Category '凭据窃取' -Title "属性 $attr 存在且当前账户可读（$($names.Count) 个对象）" -Severity $sev `
                        -Description "$attr 可能包含口令/本地管理员密码，当前执行账户能读取它，说明该属性的读取权限过宽。" `
                        -Affected (@($names) | ForEach-Object { @{ '对象'=$_ } }) `
                        -Remediation "收紧该属性读取 ACL；LAPS(ms-Mcs-AdmPwd) 应仅授权必要管理员可读；清理 userPassword 等历史明文属性。" `
                        -Reference "LAPS ACL / Unsecured Credentials"
                }
            } catch {}
        }
        Write-Step "机密属性检查完成" 'OK'
    } catch {
        Write-Step "机密属性检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-BuiltinAdminAndGuest {
    Write-Step "检查内置 Administrator(RID500) 与 Guest 账户 ..." 'RUN'
    try {
        if (-not $script:DomainSid) { Write-Step "无域 SID，跳过" 'WARN'; return }
        foreach ($pair in @(@{rid='500';kind='admin'}, @{rid='501';kind='guest'})) {
            $sidStr = "$($script:DomainSid)-$($pair.rid)"
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
            $bytes = New-Object 'byte[]' $sid.BinaryLength; $sid.GetBinaryForm($bytes,0)
            $hex = ($bytes | ForEach-Object { '\{0:x2}' -f $_ }) -join ''
            $res = Invoke-LdapQuery -Filter "(objectSid=$hex)" -Properties @('sAMAccountName','pwdLastSet','lastLogonTimestamp','userAccountControl')
            foreach ($r in $res) {
                $sam = [string](Get-Prop $r 'sAMAccountName')
                $uac = [int](Get-Prop $r 'userAccountControl' 0)
                $enabled = -not (Test-UacFlag $uac $script:UAC.ACCOUNTDISABLE)
                if ($pair.kind -eq 'admin') {
                    $pwd = Convert-FileTimeToDate (Get-Prop $r 'pwdLastSet')
                    $pwdAge = if ($pwd) { [math]::Round(((Get-Date)-$pwd).TotalDays) } else { $null }
                    $issues = @()
                    if ($sam -eq 'Administrator') { $issues += '未重命名(仍为 Administrator)' }
                    if ($null -ne $pwdAge -and $pwdAge -gt 365) { $issues += "口令已 $pwdAge 天未更换" }
                    if ($issues.Count -gt 0) {
                        Add-Finding -Category '特权账户' -Title '内置管理员账户(RID 500)存在弱点' -Severity 'Medium' `
                            -Description ("内置管理员：" + ($issues -join '；') + "。该账户权限极高且常被攻击者优先尝试，且无法被锁定。") `
                            -Affected @(@{ '账户'=$sam; '口令年龄(天)'=$pwdAge }) `
                            -Remediation "重命名内置管理员、设置超强口令并定期轮换；限制为应急使用；纳入 Protected Users 或标记不可委派；开启审计。" `
                            -Reference "CIS / 内置管理员加固"
                    } else {
                        Add-Finding -Category '特权账户' -Title '内置管理员账户基本合规' -Severity 'Info' -Passed $true -Description "RID 500 已重命名且口令较新。"
                    }
                } else {
                    if ($enabled) {
                        Add-Finding -Category '账户卫生' -Title 'Guest(来宾)账户已启用' -Severity 'Medium' `
                            -Description "来宾账户启用会提供弱身份/匿名访问入口。" -Affected @(@{ '账户'=$sam; '状态'='启用' }) `
                            -Remediation "禁用 Guest 账户（默认应保持禁用）。" -Reference "CIS"
                    } else {
                        Add-Finding -Category '账户卫生' -Title 'Guest(来宾)账户已禁用' -Severity 'Info' -Passed $true -Description "来宾账户处于禁用状态。"
                    }
                }
            }
        }
        Write-Step "内置账户检查完成" 'OK'
    } catch {
        Write-Step "内置账户检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-PreWindows2000Access {
    Write-Step "检查 Pre-Windows 2000 Compatible Access 组 ..." 'RUN'
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-554')
        $bytes = New-Object 'byte[]' $sid.BinaryLength; $sid.GetBinaryForm($bytes,0)
        $hex = ($bytes | ForEach-Object { '\{0:x2}' -f $_ }) -join ''
        $g = Invoke-LdapQuery -Filter "(objectSid=$hex)" -Properties @('member')
        $risky = @()
        foreach ($r in $g) {
            foreach ($m in (Get-PropAll $r 'member')) {
                $md = [string]$m
                if ($md -match 'S-1-1-0' -or $md -match 'S-1-5-7') { $risky += @{ '成员(DN)'=$md } }
            }
        }
        if ($risky.Count -gt 0) {
            Add-Finding -Category '系统加固' -Title 'Pre-Windows 2000 Compatible Access 含宽泛主体' -Severity 'High' `
                -Description "该组包含 Everyone/Anonymous Logon 时，会放宽匿名/低权限对目录的读取，便于攻击者匿名侦察（枚举用户、组、属性）。" `
                -Affected $risky `
                -Remediation "移除 Everyone/Anonymous Logon；仅在确有老系统兼容需求时保留必要主体，否则清空该组。" `
                -Reference "Anonymous Enumeration 加固"
        } else {
            Add-Finding -Category '系统加固' -Title 'Pre-Windows 2000 组未含宽泛主体' -Severity 'Info' -Passed $true -Description "未发现 Everyone/Anonymous 成员。"
        }
        Write-Step "Pre-Windows 2000 检查完成" 'OK'
    } catch {
        Write-Step "Pre-Windows 2000 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-AnonymousLdapAccess {
    Write-Step "检查匿名 LDAP / dsHeuristics ..." 'RUN'
    try {
        $dsDn = "CN=Directory Service,CN=Windows NT,CN=Services,$($script:ConfigDN)"
        $res = Invoke-LdapQuery -Filter '(objectClass=*)' -Properties @('dSHeuristics') -SearchRoot $dsDn
        $val = $null
        foreach ($r in $res) { $val = [string](Get-Prop $r 'dSHeuristics'); break }
        if ([string]::IsNullOrEmpty($val)) {
            Add-Finding -Category '系统加固' -Title 'dsHeuristics 未设置（匿名 LDAP 默认禁用）' -Severity 'Info' -Passed $true -Description "未配置 dSHeuristics，匿名 LDAP 操作默认被禁止。"
        } else {
            $ch7 = if ($val.Length -ge 7) { $val.Substring(6,1) } else { '0' }
            if ($ch7 -eq '2') {
                Add-Finding -Category '系统加固' -Title '已允许匿名 LDAP 操作 (dsHeuristics 第7位=2)' -Severity 'High' `
                    -Description "dSHeuristics 第 7 位为 2，允许匿名 LDAP 绑定/查询，攻击者无需凭据即可枚举目录信息。" `
                    -Affected @(@{ 'dSHeuristics'=$val }) `
                    -Remediation "将 dSHeuristics 第 7 位改回 0（禁止匿名 LDAP 操作）。" -Reference "Anonymous LDAP 加固"
            } else {
                Add-Finding -Category '系统加固' -Title 'dsHeuristics 未开启匿名 LDAP' -Severity 'Info' -Passed $true -Description "当前 dSHeuristics=$val，未允许匿名操作。"
            }
        }
        Write-Step "匿名 LDAP 检查完成" 'OK'
    } catch {
        Write-Step "匿名 LDAP 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-DuplicateSpn {
    Write-Step "检查重复 SPN ..." 'RUN'
    try {
        $res = Invoke-LdapQuery -Filter '(servicePrincipalName=*)' -Properties @('sAMAccountName','servicePrincipalName')
        $map = @{}
        foreach ($r in $res) {
            $sam = [string](Get-Prop $r 'sAMAccountName')
            foreach ($spn in (Get-PropAll $r 'servicePrincipalName')) {
                $key = ([string]$spn).ToLower()
                if (-not $map.ContainsKey($key)) { $map[$key] = New-Object System.Collections.ArrayList }
                [void]$map[$key].Add($sam)
            }
        }
        $dups = @()
        foreach ($k in $map.Keys) {
            $owners = @($map[$k] | Select-Object -Unique)
            if ($owners.Count -gt 1) { $dups += @{ 'SPN'=$k; '归属账户'=($owners -join ', ') } }
        }
        if ($dups.Count -gt 0) {
            Add-Finding -Category '配置异常' -Title "存在重复 SPN（$($dups.Count) 个）" -Severity 'Medium' `
                -Description "同一 SPN 注册在多个账户上会导致 Kerberos 认证异常，也可能是 SPN 劫持/伪造的迹象。" `
                -Affected $dups `
                -Remediation "核查重复 SPN 来源，删除多余/异常注册，确保每个 SPN 唯一。" -Reference "SPN 配置审计"
        } else {
            Add-Finding -Category '配置异常' -Title '未发现重复 SPN' -Severity 'Info' -Passed $true -Description "所有 SPN 均唯一。"
        }
        Write-Step "重复 SPN 检查完成" 'OK'
    } catch {
        Write-Step "重复 SPN 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-GmsaReadable {
    Write-Step "检查 gMSA 口令可读范围 ..." 'RUN'
    try {
        $res = Invoke-LdapQuery -Filter '(objectClass=msDS-GroupManagedServiceAccount)' -Properties @('sAMAccountName','msDS-GroupMSAMembership')
        $rows = @(); $cnt = 0
        $lowPriv = Get-LowPrivSidTable
        foreach ($r in $res) {
            $cnt++
            $sam = [string](Get-Prop $r 'sAMAccountName')
            $sids = @()
            try {
                $raw = $r.Properties['msDS-GroupMSAMembership'][0]
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorBinaryForm([byte[]]$raw)
                foreach ($ace in $sd.GetAccessRules($true,$false,[System.Security.Principal.SecurityIdentifier])) { $sids += $ace.IdentityReference.Value }
            } catch {}
            $broad = @($sids | Where-Object { $lowPriv.ContainsKey($_) })
            if ($broad.Count -gt 0) {
                $names = @(); foreach ($s in $broad) { $names += $lowPriv[$s] }
                $rows += @{ 'gMSA账户'=$sam; '可读口令的宽泛主体'=(($names | Select-Object -Unique) -join ', ') }
            }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category '凭据窃取' -Title "存在 gMSA 口令可被宽泛主体读取（$($rows.Count) 个）" -Severity 'High' `
                -Description "gMSA 的 msDS-GroupMSAMembership 决定谁能取回其托管口令。若含 Domain Users/Authenticated Users 等宽泛主体，则低权限用户可获取该服务账户口令。" `
                -Affected $rows `
                -Remediation "将 PrincipalsAllowedToRetrieveManagedPassword 收紧为仅运行该服务的特定主机/账户。" -Reference "gMSA 加固"
        } elseif ($cnt -gt 0) {
            Add-Finding -Category '凭据窃取' -Title 'gMSA 口令读取范围正常' -Severity 'Info' -Passed $true -Description "检测到 $cnt 个 gMSA，未发现宽泛可读。"
        } else {
            Add-Finding -Category '凭据窃取' -Title '未发现 gMSA' -Severity 'Info' -Passed $true -Description "域内未使用组托管服务账户。"
        }
        Write-Step "gMSA 检查完成" 'OK'
    } catch {
        Write-Step "gMSA 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-StaleComputers {
    Write-Step "检查僵尸计算机账户 (>$StaleDays 天) ..." 'RUN'
    try {
        $threshold = (Get-Date).AddDays(-$StaleDays)
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Properties @('sAMAccountName','lastLogonTimestamp','pwdLastSet','operatingSystem')
        $rows = @()
        foreach ($r in $res) {
            $llt = Convert-FileTimeToDate (Get-Prop $r 'lastLogonTimestamp')
            $pwd = Convert-FileTimeToDate (Get-Prop $r 'pwdLastSet')
            if (($llt -and $llt -lt $threshold) -or ($pwd -and $pwd -lt $threshold)) {
                $rows += @{
                    '计算机'=[string](Get-Prop $r 'sAMAccountName')
                    '系统'=[string](Get-Prop $r 'operatingSystem')
                    '最近登录'=$(if($llt){$llt.ToString('yyyy-MM-dd')}else{'未知'})
                    '机器口令年龄(天)'=$(if($pwd){[math]::Round(((Get-Date)-$pwd).TotalDays)}else{0})
                }
            }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category '账户卫生' -Title "存在僵尸计算机账户（$($rows.Count) 个）" -Severity 'Low' `
                -Description "这些计算机账户超过 $StaleDays 天未活动（域成员机器口令正常每 30 天自动轮换）。陈旧机器账户可能仍持有有效凭据或被重用。" `
                -Affected ($rows | Sort-Object { [int]$_['机器口令年龄(天)'] } -Descending) `
                -Remediation "禁用并在确认后删除长期离线的计算机账户，纳入资产生命周期管理。" -Reference "账户卫生"
        } else {
            Add-Finding -Category '账户卫生' -Title '未发现僵尸计算机账户' -Severity 'Info' -Passed $true -Description "计算机账户活跃度正常。"
        }
        Write-Step "僵尸计算机检查完成" 'OK'
    } catch {
        Write-Step "僵尸计算机检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-FunctionalLevelAndLegacyOs {
    Write-Step "检查域/林功能级别与 EOL 系统 ..." 'RUN'
    try {
        $rootDse = Get-DirectoryEntry 'RootDSE'
        $domFunc = [int]($rootDse.Properties['domainFunctionality'][0])
        $forestFunc = [int]($rootDse.Properties['forestFunctionality'][0])
        $rootDse.Dispose()
        $map = @{ 0='2000';1='2003 Interim';2='2003';3='2008';4='2008 R2';5='2012';6='2012 R2';7='2016' }
        $domText = if ($map.ContainsKey($domFunc)) { $map[$domFunc] } else { "级别$domFunc" }
        $forestText = if ($map.ContainsKey($forestFunc)) { $map[$forestFunc] } else { "级别$forestFunc" }
        if ($domFunc -lt 7 -or $forestFunc -lt 7) {
            Add-Finding -Category '系统加固' -Title "域/林功能级别偏低（域:$domText 林:$forestText）" -Severity 'Medium' `
                -Description "较低功能级别意味着仍兼容旧版域控与较弱安全特性（较弱加密、缺少较新的 Kerberos/凭据保护）。" `
                -Affected @(@{ '域功能级别'=$domText; '林功能级别'=$forestText }) `
                -Remediation "在确认无旧版域控后，逐步提升域/林功能级别至受支持版本(2016+)。" -Reference "功能级别加固"
        } else {
            Add-Finding -Category '系统加固' -Title "域/林功能级别正常（域:$domText 林:$forestText）" -Severity 'Info' -Passed $true -Description "功能级别处于受支持范围。"
        }

        $res = Invoke-LdapQuery -Filter '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Properties @('sAMAccountName','operatingSystem')
        $eol = @()
        foreach ($r in $res) {
            $os = [string](Get-Prop $r 'operatingSystem')
            if ($os -match 'XP|Vista|Windows 7|Windows 8|Server 2003|Server 2008|Server 2012') {
                $eol += @{ '计算机'=[string](Get-Prop $r 'sAMAccountName'); '系统'=$os }
            }
        }
        if ($eol.Count -gt 0) {
            Add-Finding -Category '系统加固' -Title "存在已停止支持(EOL)的成员系统（$($eol.Count) 台）" -Severity 'High' `
                -Description "这些主机运行已结束支持的 Windows，缺少安全更新，是内网横向移动的高危跳板。" `
                -Affected $eol `
                -Remediation "尽快升级或网络隔离这些 EOL 主机，并加强监控。" -Reference "EOL 系统风险"
        }
        Write-Step "功能级别/EOL 检查完成" 'OK'
    } catch {
        Write-Step "功能级别/EOL 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-SensitiveNotDelegated {
    Write-Step "检查特权账户是否标记为不可委派 ..." 'RUN'
    try {
        $protected = @{}
        foreach ($m in (Resolve-GroupMembers -GroupRid '525')) { $protected[$m.sAMAccountName] = $true }
        $res = Invoke-LdapQuery -Filter '(&(objectCategory=person)(objectClass=user)(adminCount=1))' -Properties @('sAMAccountName','userAccountControl')
        $rows = @()
        foreach ($r in $res) {
            $uac = [int](Get-Prop $r 'userAccountControl' 0)
            if (Test-UacFlag $uac $script:UAC.ACCOUNTDISABLE) { continue }
            $sam = [string](Get-Prop $r 'sAMAccountName')
            if ($sam -eq 'krbtgt') { continue }
            $notDelegated = Test-UacFlag $uac $script:UAC.NOT_DELEGATED
            if (-not $notDelegated -and -not $protected.ContainsKey($sam)) { $rows += @{ '特权账户'=$sam } }
        }
        if ($rows.Count -gt 0) {
            Add-Finding -Category '特权账户' -Title "特权账户未标记『敏感，不可委派』（$($rows.Count) 个）" -Severity 'Medium' `
                -Description "未设置 NOT_DELEGATED 且不在 Protected Users 的特权账户，其凭据可能被委派给被攻陷的服务从而被冒充。" `
                -Affected $rows `
                -Remediation "为特权账户勾选『账户敏感，不能被委派』(NOT_DELEGATED)，或加入 Protected Users 组。" -Reference "委派防护"
        } else {
            Add-Finding -Category '特权账户' -Title '特权账户均已防委派' -Severity 'Info' -Passed $true -Description "特权账户已标记不可委派或已在 Protected Users。"
        }
        Write-Step "不可委派检查完成" 'OK'
    } catch {
        Write-Step "不可委派检查失败: $($_.Exception.Message)" 'ERR'
    }
}

function Test-FineGrainedPasswordPolicies {
    Write-Step "检查细粒度密码策略 (PSO) ..." 'RUN'
    try {
        $psoRoot = "CN=Password Settings Container,CN=System,$($script:DomainDN)"
        $res = Invoke-LdapQuery -Filter '(objectClass=msDS-PasswordSettings)' `
            -Properties @('name','msDS-MinimumPasswordLength','msDS-PasswordSettingsPrecedence','msDS-PSOAppliesTo') -SearchRoot $psoRoot
        $rows = @()
        foreach ($r in $res) {
            $rows += @{
                'PSO'=[string](Get-Prop $r 'name')
                '最小长度'=[int](Get-Prop $r 'msDS-MinimumPasswordLength' 0)
                '优先级'=[int](Get-Prop $r 'msDS-PasswordSettingsPrecedence' 0)
                '应用对象数'=(Get-PropAll $r 'msDS-PSOAppliesTo').Count
            }
        }
        if ($rows.Count -eq 0) {
            Add-Finding -Category '密码策略' -Title '未配置细粒度密码策略 (PSO)' -Severity 'Low' `
                -Description "全域仅依赖单一默认密码策略，无法对特权/服务账户单独加严口令要求。" `
                -Remediation "为特权账户、服务账户创建更严格的 PSO（更长口令、更短有效期）。" -Reference "FGPP/PSO"
        } else {
            Add-Finding -Category '密码策略' -Title "已配置 $($rows.Count) 个细粒度密码策略 (PSO)" -Severity 'Info' -Passed $true `
                -Description "PSO 清单（建议核对其强度与应用范围是否覆盖特权/服务账户）。" -Affected $rows
        }
        Write-Step "PSO 检查完成" 'OK'
    } catch {
        Write-Step "PSO 检查失败: $($_.Exception.Message)" 'ERR'
    }
}

#endregion


#region ========================= HTML 报告生成 =========================

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    # System.Net.WebUtility 在 Windows PowerShell 5.1 与 PowerShell 7 中均内置可用，无需 Add-Type
    try { return [System.Net.WebUtility]::HtmlEncode($Text) } catch {}
    try { return [System.Web.HttpUtility]::HtmlEncode($Text) } catch {}
    # 最后兜底：手工转义关键字符
    return ($Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

function Format-AffectedTable {
    <# 把 Affected（哈希表数组）渲染为 HTML 表格。#>
    param([object[]]$Affected)
    if (-not $Affected -or $Affected.Count -eq 0) { return '' }

    # 收集所有列名（保持首个元素的列顺序）
    $first = $Affected[0]
    if ($first -isnot [hashtable] -and $first -isnot [System.Collections.Specialized.OrderedDictionary]) {
        # 简单字符串数组
        $items = ($Affected | ForEach-Object { '<li>' + (ConvertTo-HtmlEncoded ([string]$_)) + '</li>' }) -join ''
        return "<ul class='affected-list'>$items</ul>"
    }
    $cols = @($first.Keys)
    $thead = ($cols | ForEach-Object { '<th>' + (ConvertTo-HtmlEncoded $_) + '</th>' }) -join ''
    $rowsHtml = ''
    $max = 200   # 单项最多展示行数，避免报告过大
    $shown = 0
    foreach ($row in $Affected) {
        if ($shown -ge $max) { break }
        $cells = ''
        foreach ($c in $cols) {
            $val = if ($row.Contains($c)) { [string]$row[$c] } else { '' }
            $cells += '<td>' + (ConvertTo-HtmlEncoded $val) + '</td>'
        }
        $rowsHtml += "<tr>$cells</tr>"
        $shown++
    }
    $more = if ($Affected.Count -gt $max) { "<div class='more-note'>（仅展示前 $max 条，共 $($Affected.Count) 条）</div>" } else { '' }
    return "<table class='affected'><thead><tr>$thead</tr></thead><tbody>$rowsHtml</tbody></table>$more"
}

function New-HtmlReport {
    param([string]$Path)

    # 统计
    $counts = @{ Critical=0; High=0; Medium=0; Low=0; Info=0 }
    $riskFindings = @()
    $passedFindings = @()
    foreach ($f in $script:Findings) {
        $counts[$f.Severity]++
        if ($f.Passed -and $f.Severity -eq 'Info') { $passedFindings += $f } else { $riskFindings += $f }
    }
    # 风险项按严重度倒序、再按受影响数量倒序
    $riskFindings = $riskFindings | Sort-Object @{e={$script:SeverityRank[$_.Severity]};Descending=$true}, @{e={$_.Count};Descending=$true}

    $totalRisks = $counts.Critical + $counts.High + $counts.Medium + $counts.Low

    # 计算一个简单的健康分（满分100，按权重扣分，下限0）
    $score = 100 - ($counts.Critical*20 + $counts.High*10 + $counts.Medium*4 + $counts.Low*1)
    if ($score -lt 0) { $score = 0 }
    $scoreColor = if ($score -ge 85) { '#2e9e5b' } elseif ($score -ge 60) { '#d9822b' } else { '#c0392b' }
    $grade = if ($score -ge 85) { '良好' } elseif ($score -ge 60) { '需改进' } else { '高风险' }

    $sevColors = @{ Critical='#8e1b1b'; High='#c0392b'; Medium='#d9822b'; Low='#3a7bd5'; Info='#6c757d' }

    # 概要信息行
    $infoRows = ''
    foreach ($k in $script:DomainInfo.Keys) {
        $infoRows += "<tr><th>$(ConvertTo-HtmlEncoded $k)</th><td>$(ConvertTo-HtmlEncoded ([string]$script:DomainInfo[$k]))</td></tr>"
    }

    # 严重度统计卡片
    $cards = ''
    foreach ($sev in 'Critical','High','Medium','Low','Info') {
        $label = $script:SeverityText[$sev]
        $cards += @"
<div class='stat-card' style='border-top:4px solid $($sevColors[$sev])'>
  <div class='stat-num' style='color:$($sevColors[$sev])'>$($counts[$sev])</div>
  <div class='stat-label'>$label</div>
</div>
"@
    }

    # 风险明细
    $detailHtml = ''
    $idx = 0
    foreach ($f in $riskFindings) {
        $idx++
        $sevColor = $sevColors[$f.Severity]
        $sevLabel = $script:SeverityText[$f.Severity]
        $affectedHtml = Format-AffectedTable -Affected $f.Affected
        $descHtml = (ConvertTo-HtmlEncoded $f.Description) -replace "`n", '<br/>'
        $remHtml  = (ConvertTo-HtmlEncoded $f.Remediation) -replace "`n", '<br/>'
        $refHtml  = if ($f.Reference) { "<div class='ref'>参考：$(ConvertTo-HtmlEncoded $f.Reference)</div>" } else { '' }
        $countBadge = if ($f.Count -gt 0) { "<span class='count-badge'>$($f.Count) 项</span>" } else { '' }
        $remBlock = if ($f.Remediation) { "<div class='remediation'><div class='rem-title'>整改建议</div><div>$remHtml</div></div>" } else { '' }

        $detailHtml += @"
<div class='finding' id='f$idx'>
  <div class='finding-head' style='background:$sevColor'>
    <span class='sev-tag'>$sevLabel</span>
    <span class='finding-title'>$idx. $(ConvertTo-HtmlEncoded $f.Title)</span>
    $countBadge
    <span class='cat-tag'>$(ConvertTo-HtmlEncoded $f.Category)</span>
  </div>
  <div class='finding-body'>
    <div class='desc'>$descHtml</div>
    $refHtml
    $(if($affectedHtml){"<div class='affected-wrap'><div class='aff-title'>受影响对象</div>$affectedHtml</div>"})
    $remBlock
  </div>
</div>
"@
    }
    if ($riskFindings.Count -eq 0) {
        $detailHtml = "<div class='no-risk'>本次检查未发现明显风险项。请仍结合手工核查与持续监控。</div>"
    }

    # 通过项（折叠）
    $passedHtml = ''
    foreach ($f in $passedFindings) {
        $passedHtml += "<li><strong>$(ConvertTo-HtmlEncoded $f.Category)</strong> — $(ConvertTo-HtmlEncoded $f.Title)</li>"
    }

    # 目录
    $tocHtml = ''
    $i = 0
    foreach ($f in $riskFindings) {
        $i++
        $sevLabel = $script:SeverityText[$f.Severity]
        $tocHtml += "<li><a href='#f$i'><span class='toc-sev' style='background:$($sevColors[$f.Severity])'>$sevLabel</span> $(ConvertTo-HtmlEncoded $f.Title)</a></li>"
    }

    $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    $html = @"
<!DOCTYPE html>
<html lang='zh-CN'>
<head>
<meta charset='UTF-8'/>
<meta name='viewport' content='width=device-width, initial-scale=1.0'/>
<title>域环境安全检查整改报告</title>
<style>
* { box-sizing: border-box; }
body { font-family: -apple-system,'Segoe UI','Microsoft YaHei',sans-serif; margin:0; background:#f4f6f9; color:#222; line-height:1.6; }
.container { max-width:1100px; margin:0 auto; padding:24px; }
.header { background:linear-gradient(135deg,#1f3a5f,#2c5282); color:#fff; padding:32px; border-radius:10px; margin-bottom:24px; }
.header h1 { margin:0 0 8px; font-size:26px; }
.header .sub { opacity:.85; font-size:14px; }
.score-wrap { display:flex; gap:24px; align-items:center; margin-top:20px; flex-wrap:wrap; }
.score-circle { width:120px; height:120px; border-radius:50%; background:#fff; display:flex; flex-direction:column; align-items:center; justify-content:center; }
.score-num { font-size:38px; font-weight:700; line-height:1; }
.score-grade { font-size:13px; margin-top:4px; color:#444; }
.summary-line { font-size:15px; }
.section { background:#fff; border-radius:10px; padding:24px; margin-bottom:24px; box-shadow:0 1px 3px rgba(0,0,0,.08); }
.section h2 { margin-top:0; font-size:19px; border-left:4px solid #2c5282; padding-left:10px; }
.info-table, .affected { width:100%; border-collapse:collapse; font-size:14px; }
.info-table th { text-align:left; width:160px; color:#555; padding:6px 10px; vertical-align:top; }
.info-table td { padding:6px 10px; }
.stats { display:flex; gap:14px; flex-wrap:wrap; }
.stat-card { flex:1; min-width:120px; background:#fafbfc; border-radius:8px; padding:16px; text-align:center; box-shadow:0 1px 2px rgba(0,0,0,.05); }
.stat-num { font-size:30px; font-weight:700; }
.stat-label { font-size:13px; color:#666; margin-top:4px; }
.toc ul { list-style:none; padding-left:0; margin:0; }
.toc li { padding:5px 0; border-bottom:1px dashed #eee; }
.toc a { text-decoration:none; color:#2c5282; font-size:14px; }
.toc-sev, .sev-tag { color:#fff; padding:1px 8px; border-radius:10px; font-size:12px; margin-right:8px; display:inline-block; }
.finding { border:1px solid #e5e8ec; border-radius:8px; margin-bottom:18px; overflow:hidden; }
.finding-head { color:#fff; padding:10px 14px; display:flex; align-items:center; flex-wrap:wrap; gap:6px; }
.finding-title { font-weight:600; font-size:15px; }
.cat-tag { margin-left:auto; background:rgba(255,255,255,.2); padding:2px 10px; border-radius:10px; font-size:12px; }
.count-badge { background:rgba(0,0,0,.25); padding:2px 8px; border-radius:10px; font-size:12px; }
.finding-body { padding:16px; }
.desc { margin-bottom:12px; }
.ref { font-size:12px; color:#888; margin-bottom:12px; }
.aff-title, .rem-title { font-weight:600; font-size:13px; color:#444; margin-bottom:6px; }
.affected th, .affected td { border:1px solid #e5e8ec; padding:6px 10px; text-align:left; }
.affected th { background:#f0f3f7; }
.affected-wrap { margin:12px 0; overflow-x:auto; }
.affected-list { margin:0; padding-left:20px; }
.remediation { background:#eef7f0; border-left:4px solid #2e9e5b; padding:12px 14px; border-radius:0 6px 6px 0; margin-top:12px; }
.more-note { font-size:12px; color:#999; margin-top:6px; }
.no-risk { background:#eef7f0; padding:20px; border-radius:8px; text-align:center; color:#2e7d4f; }
.passed-list { columns:2; font-size:13px; color:#555; }
.footer { text-align:center; color:#999; font-size:12px; padding:20px; }
.disclaimer { background:#fff8e6; border:1px solid #f0d98c; border-radius:8px; padding:14px; font-size:13px; color:#7a5c00; margin-bottom:24px; }
</style>
</head>
<body>
<div class='container'>
  <div class='header'>
    <h1>域环境安全检查整改报告</h1>
    <div class='sub'>Active Directory Security Assessment Report · 生成时间 $generatedAt</div>
    <div class='score-wrap'>
      <div class='score-circle'>
        <div class='score-num' style='color:$scoreColor'>$score</div>
        <div class='score-grade'>$grade</div>
      </div>
      <div class='summary-line'>
        本次共执行 $($script:Findings.Count) 项检查，发现 <strong>$totalRisks</strong> 个风险项：
        严重 <strong style='color:#ffb3b3'>$($counts.Critical)</strong> ·
        高危 <strong style='color:#ffd0c4'>$($counts.High)</strong> ·
        中危 <strong style='color:#ffe6c4'>$($counts.Medium)</strong> ·
        低危 <strong style='color:#cfe0ff'>$($counts.Low)</strong><br/>
        健康评分为参考性指标，请优先处置『严重』与『高危』项。
      </div>
    </div>
  </div>

  <div class='disclaimer'>
    <strong>声明：</strong>本报告由自动化只读枚举生成，仅供授权范围内的内部安全自查与加固使用。工具不进行任何攻击、口令破解或配置修改。报告可能存在误报/漏报，整改前请结合人工核实；对生产环境的变更请先在测试环境验证。
  </div>

  <div class='section'>
    <h2>一、环境概要</h2>
    <table class='info-table'>$infoRows</table>
  </div>

  <div class='section'>
    <h2>二、风险统计</h2>
    <div class='stats'>$cards</div>
  </div>

  <div class='section toc'>
    <h2>三、风险项目录</h2>
    <ul>$tocHtml</ul>
  </div>

  <div class='section'>
    <h2>四、风险明细与整改建议</h2>
    $detailHtml
  </div>

  <div class='section'>
    <h2>五、已通过 / 基线检查项</h2>
    <ul class='passed-list'>$passedHtml</ul>
  </div>

  <div class='footer'>
    Generated by Invoke-ADSecurityCheck.ps1 · 仅限授权使用
  </div>
</div>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($Path, $html, [System.Text.Encoding]::UTF8)
}

#endregion


#region ========================= 主执行流程 =========================

function Invoke-Main {
    $banner = @'
============================================================
   域环境安全检查工具  (AD Security Assessment)
   只读枚举 · 无需域管理员权限 · 生成中文整改报告
============================================================
'@
    Write-Host $banner -ForegroundColor Cyan

    # 加载 HTML 编码所需程序集
    try { Add-Type -AssemblyName System.Web -ErrorAction Stop } catch {}

    # 处理 -Domain：若未显式指定 Server，则用域名作为无服务器绑定目标
    if ($Domain -and -not $Server) { Set-Variable -Name Server -Value $Domain -Scope Script }

    # 默认输出路径
    if (-not $OutputPath) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $OutputPath = Join-Path (Get-Location).Path "AD-Security-Report-$stamp.html"
    }

    # 初始化域上下文
    try {
        Initialize-DomainContext
    } catch {
        Write-Step "初始化域连接失败：$($_.Exception.Message)" 'ERR'
        Write-Host "`n请确认：1) 终端已加入域；2) 可访问域控；3) 或使用 -Server / -Domain / -Credential 指定连接参数。" -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Step "开始执行安全检查项 ..." 'RUN'
    Write-Host ""

    # 依次执行所有检查（每项内部已自带 try/catch，单项失败不影响整体）
    $checks = @(
        'Test-PasswordPolicy',
        'Test-MachineAccountQuota',
        'Test-KrbtgtPassword',
        'Test-DomainControllers',
        'Test-FunctionalLevelAndLegacyOs',
        'Test-DomainTrusts',
        'Test-AnonymousLdapAccess',
        'Test-AdcsTemplates',
        'Test-Kerberoastable',
        'Test-AsRepRoastable',
        'Test-WeakKerberosEncryption',
        'Test-UnconstrainedDelegation',
        'Test-ConstrainedDelegation',
        'Test-ResourceBasedDelegation',
        'Test-DangerousUacFlags',
        'Test-PasswordNeverExpires',
        'Test-FineGrainedPasswordPolicies',
        'Test-StaleAccounts',
        'Test-StaleComputers',
        'Test-PrivilegedOldPasswords',
        'Test-SidHistory',
        'Test-PrivilegedGroups',
        'Test-HighRiskGroups',
        'Test-ProtectedUsers',
        'Test-SensitiveNotDelegated',
        'Test-BuiltinAdminAndGuest',
        'Test-PreWindows2000Access',
        'Test-Laps',
        'Test-GmsaReadable',
        'Test-DCSyncRights',
        'Test-OrphanedAdminCount',
        'Test-DuplicateSpn',
        'Test-SecretsInAttributes',
        'Test-GppPassword'
    )
    foreach ($c in $checks) {
        try { & $c } catch { Write-Step "$c 执行异常: $($_.Exception.Message)" 'ERR' }
    }

    # 生成报告
    Write-Host ""
    Write-Step "正在生成 HTML 报告 ..." 'RUN'
    try {
        New-HtmlReport -Path $OutputPath
        Write-Step "报告已生成：$OutputPath" 'OK'
    } catch {
        Write-Step "报告生成失败：$($_.Exception.Message)" 'ERR'
    }

    # 控制台汇总
    $counts = @{ Critical=0; High=0; Medium=0; Low=0; Info=0 }
    foreach ($f in $script:Findings) { $counts[$f.Severity]++ }
    Write-Host ""
    Write-Host "----------------- 检查结果汇总 -----------------" -ForegroundColor Cyan
    Write-Host ("  严重 (Critical): {0}" -f $counts.Critical) -ForegroundColor Red
    Write-Host ("  高危 (High)    : {0}" -f $counts.High) -ForegroundColor Red
    Write-Host ("  中危 (Medium)  : {0}" -f $counts.Medium) -ForegroundColor Yellow
    Write-Host ("  低危 (Low)     : {0}" -f $counts.Low) -ForegroundColor DarkYellow
    Write-Host ("  信息 (Info)    : {0}" -f $counts.Info) -ForegroundColor Gray
    Write-Host "------------------------------------------------" -ForegroundColor Cyan

    # 尝试自动打开报告（仅交互式桌面会话）
    try {
        if ([Environment]::UserInteractive) { Invoke-Item $OutputPath -ErrorAction SilentlyContinue }
    } catch {}
}

# 入口
Invoke-Main

#endregion
