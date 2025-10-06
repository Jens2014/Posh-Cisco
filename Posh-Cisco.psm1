# Posh-Cisco PowerShell Cisco Module (shellstream-only robust filters)
# Maintained by Jens Kossmagk & GPT (2025) | License: GPLv3+

Import-Module Posh-SSH


function Get-Cisco-SSHResponse {
    [CmdletBinding(DefaultParameterSetName='Single')]
    param(
        # --- Open ---
        [Parameter(Mandatory=$true, ParameterSetName='Open')]
        [switch]$Open,

        # --- Close ---
        [Parameter(Mandatory=$true, ParameterSetName='Close')]
        [switch]$Close,

        # --- Host/Port/Cred (Open & Single) ---
        [Parameter(Mandatory=$true, ParameterSetName='Open')]
        [Parameter(Mandatory=$true, ParameterSetName='Single')]
        [string]$HostAddress,

        [Parameter(ParameterSetName='Open')]
        [Parameter(ParameterSetName='Single')]
        [int]$HostPort = 22,

        [Parameter(Mandatory=$true, ParameterSetName='Open')]
        [Parameter(Mandatory=$true, ParameterSetName='Single')]
        [pscredential]$Credential,

        [Parameter(ParameterSetName='Open')]
        [Parameter(ParameterSetName='Single')]
        [switch]$AcceptKey,

        [Parameter(ParameterSetName='Open')]
        [Parameter(ParameterSetName='Single')]
        [switch]$NoPaging,

        [Parameter(ParameterSetName='Open')]
        [Parameter(ParameterSetName='Single')]
        [switch]$GenericPrompt,

        # --- Session (Execute & Close) ---
        [Parameter(Mandatory=$true, ParameterSetName='Execute')]
        [Parameter(Mandatory=$true, ParameterSetName='Close')]
        [ValidateNotNull()]$SSHSession,

        # --- Commands (Execute) ---
        [Parameter(Mandatory=$true, ParameterSetName='Execute')]
        [string[]]$Commands,

        # --- Command (Single) ---
        [Parameter(Mandatory=$true, ParameterSetName='Single')]
        [string]$Command,

        # --- StripHeaderAt (Execute & Single) ---
        [Parameter(ParameterSetName='Execute')]
        [Parameter(ParameterSetName='Single')]
        [string]$StripHeaderAt,

        # --- Timeout (Open, Execute, Single) ---
        [Parameter(ParameterSetName='Open')]
        [Parameter(ParameterSetName='Execute')]
        [Parameter(ParameterSetName='Single')]
        [int]$TimeoutSec = 12
    )

    # ---------- Hilfsfunktionen (approved verbs) ----------
    function Remove-Ansi {
        param([string]$s)
        if (-not $s) { return $s }
        $s = [regex]::Replace($s, "\x1B\[[0-9;?]*[ -/]*[@-~]", "")      # CSI
        $s = [regex]::Replace($s, "\x1B\][^\x07\x1B]*(\x07|\x1B\\)", "") # OSC
        return $s
    }

    function ConvertTo-PlainText {
        param([string]$s)
        $s = Remove-Ansi $s
        $s = [regex]::Replace($s, "[\x00-\x1F\x7F]", "")
        return $s.TrimEnd()
    }

    function Receive-SSHUntilPrompt {
        param(
            [Parameter(Mandatory)][object]$Stream,
            [Parameter(Mandatory)][string]$PromptLineRegex,
            [Parameter(Mandatory)][string]$PromptSuffixRegex,
            [Parameter(Mandatory)][int]$TimeoutSec
        )
        $acc = @()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
            Start-Sleep -Milliseconds 80
            $chunk = $Stream.Read()
            if (-not $chunk) { continue }
            $rawLines = $chunk -split "\r?\n"
            foreach ($raw in $rawLines) {
                $vis = (ConvertTo-PlainText $raw)
                if ($vis -match $PromptLineRegex) { return ,$acc }
                $stripped = ($vis -replace $PromptSuffixRegex, '').TrimEnd()
                $acc += $stripped
            }
        }
        return ,$acc
    }

    function Set-SSHSessionPrompt {
        param(
            [Parameter(Mandatory)][object]$SSHSession,
            [switch]$GenericPrompt,
            [switch]$NoPaging,
            [int]$TimeoutSec = 12
        )
        # ShellStream anlegen, falls fehlt
        if (-not ($SSHSession | Get-Member -Name ShellStream -ErrorAction SilentlyContinue)) {
            $stream = $SSHSession.Session.CreateShellStream("dumb", 0, 0, 0, 0, 100000)
            $null = $stream.Read() # Banner flush
            Add-Member -InputObject $SSHSession -NotePropertyName ShellStream -NotePropertyValue $stream -Force
        } else {
            $stream = $SSHSession.ShellStream
        }

        # Prompt-Regex ermitteln (nur einmal)
        if (-not ($SSHSession | Get-Member -Name PromptLineRegex -ErrorAction SilentlyContinue)) {
            if ($GenericPrompt) {
                $promptLineRegex   = "^\s*\S+(\(config[^)]*\))?[#>]\s*$"
                $promptSuffixRegex = "(\S+(\(config[^)]*\))?[#>])\s*$"
                $promptPrefixExact = '^\s*\S+(\(config[^)]*\))?[#>]\s*'
                $hostName = $null
            } else {
                # Hostname detektieren
                $stream.Write("show running-config | include hostname`n")
                Start-Sleep -Milliseconds 200
                $hostChunk = $stream.Read()
                $HostNameRaw = ($hostChunk -split "\r?\n") | ForEach-Object { (ConvertTo-PlainText $_) }
                $hostName = $null
                foreach ($line in $HostNameRaw) {
                    if ($line -match '^hostname\s+(.+)$') { $hostName = $Matches[1]; break }
                }
                if (-not $hostName) { $hostName = '<HOST>' }
                $promptLineRegex   = "^\s*$([regex]::Escape($hostName))(\(config[^)]*\))?[#>]\s*$"
                $promptSuffixRegex = "($([regex]::Escape($hostName))(\(config[^)]*\))?[#>])\s*$"
                $promptPrefixExact = '^\s*' + [regex]::Escape($hostName) + '(\(config[^)]*\))?[#>]\s*'
                # Rest bis Prompt verwerfen
                $null = Receive-SSHUntilPrompt -Stream $stream -PromptLineRegex $promptLineRegex -PromptSuffixRegex $promptSuffixRegex -TimeoutSec $TimeoutSec
            }

            Add-Member -InputObject $SSHSession -NotePropertyName PromptLineRegex   -NotePropertyValue $promptLineRegex -Force
            Add-Member -InputObject $SSHSession -NotePropertyName PromptSuffixRegex -NotePropertyValue $promptSuffixRegex -Force
            Add-Member -InputObject $SSHSession -NotePropertyName PromptPrefixExact -NotePropertyValue $promptPrefixExact -Force
            Add-Member -InputObject $SSHSession -NotePropertyName HostName          -NotePropertyValue $hostName -Force
            Add-Member -InputObject $SSHSession -NotePropertyName GenericPrompt     -NotePropertyValue ([bool]$GenericPrompt) -Force
        }

        # Paging deaktivieren, wenn -NoPaging NICHT gesetzt ist
        if (-not $NoPaging) {
            $stream.Write("terminal length 0`n")
            $null = Receive-SSHUntilPrompt -Stream $stream -PromptLineRegex $SSHSession.PromptLineRegex -PromptSuffixRegex $SSHSession.PromptSuffixRegex -TimeoutSec $TimeoutSec
        }

        return $SSHSession
    }

    # ---------- Hauptlogik je ParameterSet ----------
    switch ($PSCmdlet.ParameterSetName) {
        # ---------------- OPEN ----------------
        'Open' {
            $session = $null
            try {
                $session = New-SSHSession -ComputerName $HostAddress -Port $HostPort -Credential $Credential -AcceptKey:$AcceptKey -ErrorAction Stop
                if (-not $session -or -not $session.Session) {
                    throw 'SSH-Session konnte nicht erstellt werden – Verbindung fehlgeschlagen oder Gerät inkompatibel.'
                }
                $null = Set-SSHSessionPrompt -SSHSession $session -GenericPrompt:$GenericPrompt -NoPaging:$NoPaging -TimeoutSec $TimeoutSec
                return $session
            } catch {
                if ($session) { try { Remove-SSHSession -SSHSession $session | Out-Null } catch {} }
                throw
            }
        }

        # --------------- EXECUTE ---------------
        'Execute' {
            # Stelle sicher, dass Stream & Prompt gesetzt sind (ändert Paging NICHT erneut)
            $session = Set-SSHSessionPrompt -SSHSession $SSHSession -GenericPrompt:([bool]$SSHSession.GenericPrompt) -NoPaging:$true -TimeoutSec $TimeoutSec
            $stream  = $session.ShellStream

            $results = @()

            foreach ($cmd in $Commands) {
                # Kommando senden
                $stream.Write("$cmd`n")
                $collected = Receive-SSHUntilPrompt -Stream $stream -PromptLineRegex $session.PromptLineRegex -PromptSuffixRegex $session.PromptSuffixRegex -TimeoutSec $TimeoutSec

                # Echo entfernen
                $echoIndex = -1
                for ($i = 0; $i -lt $collected.Count; $i++) {
                    $noPrefix = (($collected[$i] -replace $session.PromptPrefixExact, '')).Trim()
                    if ($noPrefix -eq $cmd) { $echoIndex = $i; break }
                }
                if ($echoIndex -ge 0) {
                    if ($echoIndex + 1 -lt $collected.Count) {
                        $collected = $collected[($echoIndex + 1)..($collected.Count - 1)]
                    } else {
                        $collected = @()
                    }
                } else {
                    # Fallback: erste Nicht-Leerzeile finden
                    $firstData = ($collected | Where-Object { ($_ -replace '^\s+$','') -ne '' } | Select-Object -First 1)
                    if ($firstData) {
                        $startIdx = [Array]::IndexOf($collected, $firstData)
                        if ($startIdx -gt 0) { $collected = $collected[$startIdx..($collected.Count - 1)] }
                    }
                }

                # Optionalen Header ab Schneidepunkt entfernen
                if ($StripHeaderAt) {
                    $idx = $null
                    for ($i = 0; $i -lt $collected.Count; $i++) {
                        if (($collected[$i]) -like ("$StripHeaderAt*")) { $idx = $i; break }
                    }
                    if ($null -ne $idx -and $idx -is [int] -and $idx -ge 0) {
                        $collected = $collected[$idx..($collected.Count - 1)]
                    }
                }

                $results += [pscustomobject]@{
                    Command = $cmd
                    Output  = $collected
                }
            }

            return ,$results
        }

        # ---------------- CLOSE ---------------
        'Close' {
            if ($SSHSession) {
                try { Remove-SSHSession -SSHSession $SSHSession | Out-Null } catch {}
            }
            return
        }

        # --------------- SINGLE (Kompatibilität) ---------------
        'Single' {
            $session = $null
            try {
                $session = New-SSHSession -ComputerName $HostAddress -Port $HostPort -Credential $Credential -AcceptKey:$AcceptKey -ErrorAction Stop
                if (-not $session -or -not $session.Session) {
                    throw "SSH-Session konnte nicht erstellt werden – Verbindung fehlgeschlagen oder Gerät inkompatibel."
                }
                $session = Set-SSHSessionPrompt -SSHSession $session -GenericPrompt:$GenericPrompt -NoPaging:$NoPaging -TimeoutSec $TimeoutSec
                $stream  = $session.ShellStream

                # Ein einzelnes Kommando
                $stream.Write("$Command`n")
                $collected = Receive-SSHUntilPrompt -Stream $stream -PromptLineRegex $session.PromptLineRegex -PromptSuffixRegex $session.PromptSuffixRegex -TimeoutSec $TimeoutSec

                # Echo entfernen
                $echoIndex = -1
                for ($i = 0; $i -lt $collected.Count; $i++) {
                    $noPrefix = (($collected[$i] -replace $session.PromptPrefixExact, '')).Trim()
                    if ($noPrefix -eq $Command) { $echoIndex = $i; break }
                }
                if ($echoIndex -ge 0) {
                    if ($echoIndex + 1 -lt $collected.Count) { $collected = $collected[($echoIndex + 1)..($collected.Count - 1)] } else { $collected = @() }
                } else {
                    $firstData = ($collected | Where-Object { ($_ -replace '^\s+$','') -ne '' } | Select-Object -First 1)
                    if ($firstData) {
                        $startIdx = [Array]::IndexOf($collected, $firstData)
                        if ($startIdx -gt 0) { $collected = $collected[$startIdx..($collected.Count - 1)] }
                    }
                }

                if ($StripHeaderAt) {
                    $idx = $null
                    for ($i = 0; $i -lt $collected.Count; $i++) {
                        if (($collected[$i]) -like ("$StripHeaderAt*")) { $idx = $i; break }
                    }
                    if ($null -ne $idx -and $idx -is [int] -and $idx -ge 0) {
                        $collected = $collected[$idx..($collected.Count - 1)]
                    }
                }

                return $collected
            }
            catch { throw }
            finally {
                if ($session) { try { Remove-SSHSession -SSHSession $session | Out-Null } catch {} }
            }
        }
    }
}


function Get-Cisco-StartupConfig {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey
    )
    $Command = 'show startup-config'
    $lines = @( Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt '!' )
    $lastEndIndex = -1; for ($i=0;$i -lt $lines.Count;$i++){ if ($lines[$i] -and ($lines[$i].Trim() -ceq 'end')){ $lastEndIndex = $i } }
    if ($lastEndIndex -ge 0) { return $lines[0..$lastEndIndex] } else { return $lines }
}

function Backup-Cisco-StartupConfig {
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey,
        [Parameter(Mandatory=$true)]  [string]$FilePath
    )
    Get-Cisco-StartupConfig -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey | Out-File -FilePath $FilePath -Encoding ascii
}

function Get-Cisco-RunningConfig {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$Full,
        [Parameter(Mandatory=$false)] [int]$TimeOutSec = 3,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey
    )
    $Command = 'show running-config'; if ($Full){ $Command = "$Command full" }
    $lines = @( Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -TimeoutSec $TimeOutSec -StripHeaderAt 'Current configuration' )
    $lastEndIndex = -1; for ($i=0;$i -lt $lines.Count;$i++){ if ($lines[$i] -and ($lines[$i].Trim() -ceq 'end')){ $lastEndIndex = $i } }
    if ($lastEndIndex -ge 0) { return $lines[0..$lastEndIndex] } else { return $lines }
}

function Backup-Cisco-RunningConfig {
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$Full,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey,
        [Parameter(Mandatory=$true)]  [string]$FilePath
    )
    Get-Cisco-RunningConfig -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -Full:$Full -AcceptKey:$AcceptKey | Out-File -FilePath $FilePath -Encoding ascii
}

function Get-Cisco-Interfaces {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey
    )
    $Command = 'show interfaces'
    return (Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt 'Vlan')
}

function Get-Cisco-InterfacesStatus {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey
    )
    $Command = 'show interfaces status'
    return (Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt 'Port ')
}

function Get-Cisco-Logging {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey
    )
    $Command = 'show logging'
    return (Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt 'Syslog ')
}

function Get-Cisco-LoggingOnboard {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey
    )
    $Command = 'show logging onboard'
    return (Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt 'PID: ')
}

function Get-Cisco-MacAddressTable {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey
    )
    $Command = 'show mac address-table'
    return (Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt 'Vlan ')
}

function Get-Cisco-ShowVersion {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey
    )
    $Command = 'show version'
    return (Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt 'Cisco IOS Software, ')
}

# --- Robust, ShellStream-only: SW Version ---  # final S/E
function Get-Cisco-Version {
    [CmdletBinding(DefaultParameterSetName='Execute')]
    [OutputType([string[]])]
    param(
        # --- Moduswahl ---
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [switch]$Single,

        # --- SINGLE-MODUS ---
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [string]$HostAddress,
        [Parameter(ParameterSetName='Single')]
        [int]$HostPort = 22,
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [pscredential]$Credential,
        [Parameter(ParameterSetName='Single')]
        [switch]$AcceptKey,
        [Parameter(ParameterSetName='Single')]
        [switch]$NoPaging = $true,
        [Parameter(ParameterSetName='Single')]
        [switch]$GenericPrompt = $true,

        # --- EXECUTE-MODUS ---
        [Parameter(ParameterSetName='Execute', Mandatory = $true)]
        [ValidateNotNull()]
        $SSHSession,

        # --- GEMEINSAM ---
        [Parameter(ParameterSetName='Single')]
        [Parameter(ParameterSetName='Execute')]
        [int]$TimeOutSec = 3
    )

    function Select-VersionLine {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [AllowNull()][AllowEmptyString()]
            [string[]] $Lines,
            # Optional: statt String ein Objekt mit Family & Originalzeile zurückgeben
            [switch] $ReturnObject
        )
        begin {
            $buffer = New-Object System.Collections.Generic.List[string]
        }
        process {
            foreach ($l in $Lines) {
                if ([string]::IsNullOrEmpty($l)) { continue }
                foreach ($s in ($l -split "`r?`n")) {
                    if ([string]::IsNullOrWhiteSpace($s)) { continue }
                    # ANSI/VT100-CSI/OSC entfernen + schmale Leerzeichen normalisieren
                    $s2 = $s -replace '\x1B\[[0-9;?]*[ -/]*[@-~]', ''    # CSI
                    $s2 = $s2 -replace '\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)', '' # OSC
                    $s2 = $s2 -replace '[\u00A0\u2007\u202F]', ' '
                    $buffer.Add($s2)
                }
            }
        }
        end {
            if ($buffer.Count -eq 0) { return $null }

            # Kandidaten vorfiltern (alles, was "version" enthält)
            $candidates = $buffer | Where-Object { $_ -match '(?i)\bversion\b' }

            # Korrigierte/robuste Muster (gemeinsames Capture: ([\w.\-()]+))
            $patterns = @(
                # 1) IOS XE
                @{ Family='IOS/IOS-XE'; Regex='(?im)^\s*C(?:isco\s+)?IOS\s*-?\s*XE\s*Software.*?\bVersion\s+([\w.\-()]+)'; },
                # 2) klassisches IOS (inkl. "Cisco IOS Software, IOS-XE Software, ... Version X")
                @{ Family='IOS/IOS-XE'; Regex='(?im)^\s*C(?:isco\s+)?IOS\s+Software.*?\bVersion\s+([\w.\-()]+)'; },
                # 3) NX-OS ("NXOS: version X" oder "system: version X")
                @{ Family='NX-OS';     Regex='(?im)^\s*(?:NXOS:|system:)\s*version\s+([\w.\-()]+)'; },
                # 4) ASA
                @{ Family='ASA';       Regex='(?im)^\s*C(?:isco\s+)?Adaptive\s+Security\s+Appliance.*?\bVersion\s+([\w.\-()]+)'; },
                # 5) IOS XR
                @{ Family='IOS-XR';    Regex='(?im)^\s*C(?:isco\s+)?IOS\s*XR\s*Software.*?\bVersion\s+([\w.\-()]+)'; },
                # 6) Fallback (irgendwo "Version: X" / "Version X")
                @{ Family='Unknown';   Regex='(?im)\bVersion(?:\s*[:=])?\s+([\w.\-()]+)'; }
            )

            foreach ($p in $patterns) {
                foreach ($line in $candidates) {
                    $m = [regex]::Match($line, $p.Regex)
                    if ($m.Success) {
                        $version = $m.Groups[1].Value.Trim()
                        if (-not $ReturnObject) { return $version }
                        return [pscustomobject]@{
                            Family = $p.Family
                            Version = $version
                            Line = $line.Trim()
                        }
                    }
                }
            }

            if ($ReturnObject) { return $null }
            return $null
        }
    }

    $Command = 'show version | i Cisco IOS'

    $lines = $null
    switch ($PSCmdlet.ParameterSetName) {
        'Single' {
            $lines = Get-Cisco-SSHResponse `
                -HostAddress $HostAddress `
                -HostPort $HostPort `
                -Credential $Credential `
                -AcceptKey:$AcceptKey `
                -Command $Command `
                -TimeoutSec $TimeOutSec `
                -NoPaging:$NoPaging `
                -GenericPrompt:$GenericPrompt
        }
        'Execute' {
            $res = Get-Cisco-SSHResponse `
                -SSHSession $SSHSession `
                -Commands $Command `
                -TimeoutSec $TimeOutSec
            $lines = if ($res -and $res.Count -ge 1) { $res[0].Output } else { @() }
        }
        default { throw "Unerwartetes ParameterSet: $($PSCmdlet.ParameterSetName)" }
    }

    return (Select-VersionLine -Lines $lines)
}

function Get-Cisco-Vlan {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey
    )
    $Command = 'show vlan'
    return (Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt 'VLAN ')
}

function Get-Cisco-BridgeDomain {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey,
        [Parameter(Mandatory=$false)] [int]$BridgeDomain,
        [Parameter(Mandatory=$false)] [string]$BridgeDomainName
    )
    $Command = 'show bridge-domain'
    if ($PSBoundParameters.ContainsKey('BridgeDomain')) { $Command += " $BridgeDomain" }
    elseif ($PSBoundParameters.ContainsKey('BridgeDomainName')) { $Command += " $BridgeDomainName" }
    return (Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt 'Bridge-domain ')
}

function Get-Cisco-Arp {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey,
        [Parameter(Mandatory=$false)]  [string]$VRF
    )
    $Command = 'show arp'
    if ($PSBoundParameters.ContainsKey('VRF')) { $Command += " vrf $VRF" }
    return (Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt 'Protocol ')
}

function Get-Cisco-IpArp {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey,
        [Parameter(Mandatory=$false)]  [string]$VRF
    )
    $Command = 'show ip arp'
    if ($PSBoundParameters.ContainsKey('VRF')) { $Command += " vrf $VRF" }
    return (Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt 'Protocol ')
}

# --- Robust, ShellStream-only: Uptime ---  # final S/E
function Get-Cisco-Uptime {
    [CmdletBinding(DefaultParameterSetName='Execute')]
    [OutputType([string[]])]
    param(
        # --- Moduswahl ---
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [switch]$Single,

        # --- SINGLE-MODUS ---
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [string]$HostAddress,
        [Parameter(ParameterSetName='Single')]
        [int]$HostPort = 22,
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [pscredential]$Credential,
        [Parameter(ParameterSetName='Single')]
        [switch]$AcceptKey,
        [Parameter(ParameterSetName='Single')]
        [switch]$NoPaging = $true,
        [Parameter(ParameterSetName='Single')]
        [switch]$GenericPrompt = $true,

        # --- EXECUTE-MODUS ---
        [Parameter(ParameterSetName='Execute', Mandatory = $true)]
        [ValidateNotNull()]
        $SSHSession,

        # --- GEMEINSAM ---
        [Parameter(ParameterSetName='Single')]
        [Parameter(ParameterSetName='Execute')]
        [int]$TimeOutSec = 3
    )

    function ConvertTo-PlainText { 
        param([string]$s)
        if(-not $s){ return $s }
        $s = [regex]::Replace($s, "\x1B\[[0-9;?]*[ -/]*[@-~]", "")
        $s = [regex]::Replace($s, "\x1B\][^\x07\x1B]*(\x07|\x1B\\)", "")
        $s = [regex]::Replace($s, "[\x00-\x1F\x7F]", "")
        return $s.TrimEnd()
    }
    function Select-UptimeLine {
        param([string[]]$Lines)
        $clean = $Lines |
            ForEach-Object { ConvertTo-PlainText $_ } |
            Where-Object   { $_ -and $_.Trim() -ne "" }

        $upt = $clean |
            ForEach-Object {
                if ($_ -match '(?i)\buptime\s+is\s+(?<UPT>[^\r\n]+)$') { $matches.UPT.Trim() }
            } |
            Select-Object -Last 1

        if ($upt) { return ,$upt }
        return $clean
    }

    $cmd = 'show version | i [Uu]ptime'

    $lines = $null
    switch ($PSCmdlet.ParameterSetName) {
        'Single' {
            $lines = Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential `
                     -AcceptKey:$AcceptKey -Command $cmd -TimeoutSec $TimeOutSec -NoPaging:$NoPaging -GenericPrompt:$GenericPrompt
        }
        'Execute' {
            $res = Get-Cisco-SSHResponse -SSHSession $SSHSession -Commands $cmd -TimeoutSec $TimeOutSec
            $lines = if ($res -and $res.Count -ge 1) { $res[0].Output } else { @() }
        }
        default { throw "Unerwartetes ParameterSet: $($PSCmdlet.ParameterSetName)" }
    }

    return (Select-UptimeLine -Lines $lines)
}

# --- Robust, ShellStream-only: SystemModelNumber --- # final S/E-Modus
function Get-Cisco-SystemModelNumber {
    [CmdletBinding(DefaultParameterSetName='Execute')]
    [OutputType([string[]])]
    param(
        # ---------- Moduswahl ----------
        [Parameter(ParameterSetName='Single', Mandatory=$true)]
        [switch]$Single,

        # ---------- SINGLE-MODUS ----------
        [Parameter(ParameterSetName='Single', Mandatory=$true)]
        [string]$HostAddress,

        [Parameter(ParameterSetName='Single')]
        [int]$HostPort = 22,

        [Parameter(ParameterSetName='Single', Mandatory=$true)]
        [pscredential]$Credential,

        [Parameter(ParameterSetName='Single')]
        [switch]$AcceptKey,

        [Parameter(ParameterSetName='Single')]
        [switch]$NoPaging,        # Wenn NICHT gesetzt -> "terminal length 0" wird gesendet

        [Parameter(ParameterSetName='Single')]
        [switch]$GenericPrompt,   # Generisches Prompt statt Hostname-Detektion

        # ---------- EXECUTE-MODUS ----------
        [Parameter(ParameterSetName='Execute', Mandatory=$true)]
        [ValidateNotNull()]
        $SSHSession,

        # ---------- GEMEINSAM ----------
        [Parameter(ParameterSetName='Single')]
        [Parameter(ParameterSetName='Execute')]
        [int]$TimeoutSec = 3
    )

    function ConvertTo-PlainText {
        param([string]$s)
        if (-not $s){ return $s }
        $s = [regex]::Replace($s, "\x1B\[[0-9;?]*[ -/]*[@-~]", "")      # CSI
        $s = [regex]::Replace($s, "\x1B\][^\x07\x1B]*(\x07|\x1B\\)", "") # OSC
        $s = [regex]::Replace($s, "[\x00-\x1F\x7F]", "")
        return $s.TrimEnd()
    }

    function Select-ModelLine {
        param([string[]]$Lines)

        # Zeilen bereinigen
        $clean = $Lines |
            ForEach-Object { ConvertTo-PlainText $_ } |
            Where-Object { $_ -and $_.Trim() -ne "" }

        # Modelle aus Zeilen extrahieren, die mit "cisco" beginnen
        $models = foreach ($l in $clean) {
            if ($l -match '^(?i)\s*cisco\s+(\S+)') {
                $matches[1]  # zweites Wort (= Modell)
            }
        }

        if ($models) { return ,$models }  # als Array (auch bei 1 Treffer)
        return $clean
    }

    # Einheitliches Kommando für die Modellerkennung
    $cmd = 'show version | i ^cisco'

    # --- Je nach Modus Get-Cisco-SSHResponse aufrufen ---
    $lines = $null

    switch ($PSCmdlet.ParameterSetName) {
        'Single' {
            # Open → Execute(1) → Close (durch Get-Cisco-SSHResponse)
            $lines = Get-Cisco-SSHResponse `
                -HostAddress $HostAddress `
                -HostPort $HostPort `
                -Credential $Credential `
                -AcceptKey:$AcceptKey `
                -Command $cmd `
                -TimeoutSec $TimeoutSec `
                -NoPaging:$NoPaging `
                -GenericPrompt:$GenericPrompt
        }

        'Execute' {
            # Gegen bestehende Session (Execute-Mode mit 1 Command)
            $res = Get-Cisco-SSHResponse `
                -SSHSession $SSHSession `
                -Commands $cmd `
                -TimeoutSec $TimeoutSec

            # Ausgabe des ersten (einzigen) Kommandos extrahieren
            if ($res -and $res.Count -ge 1) {
                $lines = $res[0].Output
            } else {
                $lines = @()
            }
        }

        default {
            throw "Unerwartetes ParameterSet: $($PSCmdlet.ParameterSetName)"
        }
    }

    return (Select-ModelLine -Lines $lines)
}

# --- Robust, ShellStream-only: HostName from running-config ---  # final S/E
function Get-Cisco-HostName {
    [CmdletBinding(DefaultParameterSetName='Execute')]
    [OutputType([string[]])]
    param(
        # --- Moduswahl ---
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [switch]$Single,

        # --- SINGLE-MODUS ---
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [string]$HostAddress,
        [Parameter(ParameterSetName='Single')]
        [int]$HostPort = 22,
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [pscredential]$Credential,
        [Parameter(ParameterSetName='Single')]
        [switch]$AcceptKey,
        [Parameter(ParameterSetName='Single')]
        [switch]$NoPaging = $true,
        [Parameter(ParameterSetName='Single')]
        [switch]$GenericPrompt = $true,

        # --- EXECUTE-MODUS ---
        [Parameter(ParameterSetName='Execute', Mandatory = $true)]
        [ValidateNotNull()]
        $SSHSession,

        # --- GEMEINSAM ---
        [Parameter(ParameterSetName='Single')]
        [Parameter(ParameterSetName='Execute')]
        [int]$TimeOutSec = 12
    )

    function ConvertTo-PlainText {
        param([string]$s)
        if (-not $s) { return $s }
        $s = [regex]::Replace($s, "\x1B\[[0-9;?]*[ -/]*[@-~]", "")   # CSI
        $s = [regex]::Replace($s, "\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)","") # OSC
        $s = [regex]::Replace($s, "[\x00-\x1F\x7F]", "")              # C0/DEL
        return $s.TrimEnd()
    }

    # Korrektes Pipe-Command
    $cmdStrict = 'show running-config | include ^[Hh]ostname'
    $cmdLoose  = 'show running-config | include [Hh]ostname'

    $lines = $null
    switch ($PSCmdlet.ParameterSetName) {
        'Single' {
            $lines = Get-Cisco-SSHResponse `
                -HostAddress $HostAddress `
                -HostPort $HostPort `
                -Credential $Credential `
                -AcceptKey:$AcceptKey `
                -Command $cmdStrict `
                -TimeoutSec $TimeOutSec `
                -NoPaging:$NoPaging `
                -GenericPrompt:$GenericPrompt
            if (-not $lines) { $lines = @() }
        }
        'Execute' {
    # kleine Helper-Funktion für Ein-Kommando-Aufrufe mit eigenem Timeout
    function Invoke-Cmd([string]$cmd, [int]$to) {
        $r = Get-Cisco-SSHResponse -SSHSession $SSHSession -Commands $cmd -TimeoutSec $to
        if ($r -and $r.Count -ge 1 -and $r[0].Output) { return $r[0].Output } else { return @() }
    }

    $cmdStrict = 'show running-config | include ^[Hh]ostname'
    $cmdLoose  = 'show running-config | include [Hh]ostname'

    # Attempt 1 – strikt, mit übergebenem Timeout
    $lines = Invoke-Cmd $cmdStrict $TimeOutSec

    # Attempt 2 – lockerer Include, gleicher Timeout
    if ($lines.Count -eq 0) {
        $lines = Invoke-Cmd $cmdLoose $TimeOutSec
    }

    # Attempt 3 – terminal length 0 (kurz) -> danach Show mit adaptiv erhöhtem Timeout
    if ($lines.Count -eq 0) {
        # sehr kurzer Timeout für TL0, blockiert nicht
        $tl0Timeout = [Math]::Max(1, [Math]::Min($TimeOutSec, 2))
        $null = Get-Cisco-SSHResponse -SSHSession $SSHSession -Commands 'terminal length 0' -TimeoutSec $tl0Timeout

        # adaptiv: WLC/IOS-XE kann bei 2s knapp sein -> min. 5s für den Show-Aufruf
        $adaptive = [Math]::Max($TimeOutSec, 5)
        $lines = Invoke-Cmd $cmdLoose $adaptive
    }

    # Attempt 4 – Falls Session HostName bereits kennt (nicht-generisches Prompt)
    if ($lines.Count -eq 0 -and $SSHSession -and ($SSHSession.PSObject.Properties['HostName']) -and $SSHSession.HostName) {
        return ,$SSHSession.HostName
    }
}
        default { throw "Unerwartetes ParameterSet: $($PSCmdlet.ParameterSetName)" }
    }

    # KEIN frühzeitiges "no lines" mehr

    # Bereinigen & Parsen
    $clean = $lines |
        ForEach-Object { ConvertTo-PlainText $_ } |
        Where-Object   { $_ -and $_.Trim() -ne "" }

    $hostnameLine = $clean |
        Where-Object { $_ -match '(?i)^\s*hostname\s+\S+' } |
        Select-Object -Last 1

    if (-not $hostnameLine) {
        # Letzte nicht-leere Zeile, die nicht nur Sternchen ist
        $fallback = $clean | Where-Object { $_ -notmatch '^\*+$' } | Select-Object -Last 1
        if ($fallback) { return ,$fallback }
        return @()
    }

    $m = [regex]::Match($hostnameLine, '(?i)^\s*hostname\s+(?<HN>\S+)')
    if ($m.Success) { return ,($m.Groups['HN'].Value.Trim()) }
    else { return ,$hostnameLine }
}

# --- Robust, ShellStream-only: Serial Number(s) from show version / inventory ---  # final S/E
function Get-Cisco-SerialNumber {
    [CmdletBinding(DefaultParameterSetName='Execute')]
    param(
        # --- Moduswahl ---
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [switch]$Single,

        # --- SINGLE-MODUS ---
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [string]$HostAddress,
        [Parameter(ParameterSetName='Single')]
        [int]$HostPort = 22,
        [Parameter(ParameterSetName='Single', Mandatory = $true)]
        [pscredential]$Credential,
        [Parameter(ParameterSetName='Single')]
        [switch]$AcceptKey,
        [Parameter(ParameterSetName='Single')]
        [switch]$NoPaging = $true,
        [Parameter(ParameterSetName='Single')]
        [switch]$GenericPrompt = $true,

        # --- EXECUTE-MODUS ---
        [Parameter(ParameterSetName='Execute', Mandatory = $true)]
        [ValidateNotNull()]
        $SSHSession,

        # --- GEMEINSAM ---
        [Parameter(ParameterSetName='Single')]
        [Parameter(ParameterSetName='Execute')]
        [int]$TimeOutSec = 3,

        # Ausgabeform
        [Parameter(ParameterSetName='Single')]
        [Parameter(ParameterSetName='Execute')]
        [switch]$AsObject
    )

    function _San([string]$s){
        if(-not $s){ return $s }
        $s = [regex]::Replace($s, "\x1B\[[0-9;?]*[ -/]*[@-~]", "")          # CSI
        $s = [regex]::Replace($s, "\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)", "")  # OSC
        $s = [regex]::Replace($s, "[\x00-\x1F\x7F]", "")                    # C0/DEL
        return $s.TrimEnd()
    }

    # Kommandos
    $cmd1 = 'show version | i [Ss]ystem [Ss]erial [Nn]umber'
    $cmd2 = 'show inventory | i ^NAME:|^PID:|SN:'

    $lines1 = @()
    $lines2 = @()

    switch ($PSCmdlet.ParameterSetName) {
        'Single' {
            # Versuch 1
            $lines1 = Get-Cisco-SSHResponse `
                -HostAddress $HostAddress `
                -HostPort $HostPort `
                -Credential $Credential `
                -AcceptKey:$AcceptKey `
                -Command $cmd1 `
                -TimeoutSec $TimeOutSec `
                -NoPaging:$NoPaging `
                -GenericPrompt:$GenericPrompt

            # Versuch 2 nur bei Bedarf
            if(-not $lines1 -or $lines1.Count -eq 0){
                $lines2 = Get-Cisco-SSHResponse `
                    -HostAddress $HostAddress `
                    -HostPort $HostPort `
                    -Credential $Credential `
                    -AcceptKey:$AcceptKey `
                    -Command $cmd2 `
                    -TimeoutSec $TimeOutSec `
                    -NoPaging:$NoPaging `
                    -GenericPrompt:$GenericPrompt
            }
        }
        'Execute' {
            $res = Get-Cisco-SSHResponse `
                -SSHSession $SSHSession `
                -Commands @($cmd1, $cmd2) `
                -TimeoutSec $TimeOutSec

            if($res -and $res.Count -ge 1){ $lines1 = $res[0].Output }
            if($res -and $res.Count -ge 2){ $lines2 = $res[1].Output }
        }
        default { throw "Unerwartetes ParameterSet: $($PSCmdlet.ParameterSetName)" }
    }

    # --- Parsing Teil 1: show version ---
    $clean1 = $lines1 | ForEach-Object { _San $_ } | Where-Object { $_ -ne "" }
    $out = @()
    foreach($l in $clean1){
        if($l -match '(?i)system\s+serial\s+number'){
            $m = [regex]::Match(
                $l,
                '(?i)system\s+serial\s+number\s*[:=]\s*(?<SN>\S+)'
            )
            if($m.Success){
                $sn = $m.Groups['SN'].Value.Trim()
                if(-not $AsObject){ $out += $sn }
                else{
                    $out += [pscustomobject]@{
                        Source       = 'version'
                        Name         = $null
                        ProductID    = $null
                        SN           = $sn
                        OriginalLine = $null
                    }
                }
            }
            else {
                if(-not $AsObject){ $out += $l }
                else{
                    $out += [pscustomobject]@{
                        Source       = 'version'
                        Name         = $null
                        ProductID    = $null
                        SN           = $null
                        OriginalLine = $l
                    }
                }
            }
        }
    }
    if($out.Count -gt 0){ return $out }

    # --- Parsing Teil 2: show inventory ---
    $clean2 = $lines2 | ForEach-Object { _San $_ } | Where-Object { $_ -ne "" }

    # Top-Level-Namen (anpassen nach Bedarf)
    $allowedPrefixes = @(
        'Switch System',
        'Switch1 System',
        'Switch 1 System',
        'Switch2 System',
        'Switch 2 System',
        'Switch Chassis',
        'Switch1 Chassis',
        'Switch 1 Chassis',
        'Switch2 Chassis',
        'Switch 2 Chassis',
        'Chassis 1',
        'Chassis 2'
    )

    # Regex-Optionen einmal bauen
    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase `
                    -bor [System.Text.RegularExpressions.RegexOptions]::Compiled

    # Matcher EINMAL bauen (kompiliert, case-insensitive), exakte Namensübereinstimmung
    $allowedMatchers = foreach($p in $allowedPrefixes){
        $pat = '^\s*' + [regex]::Escape($p) + '\s*$'
        New-Object -TypeName System.Text.RegularExpressions.Regex `
                   -ArgumentList $pat, $regexOptions
        # Alternative:
        # [System.Text.RegularExpressions.Regex]::new($pat, $regexOptions)
    }

    $currentName   = $null
    $acceptCurrent = $false

    foreach($l in $clean2){
        if($l -match '^\s*NAME:\s*"(?<NAME>[^"]+)"'){
            $currentName   = $Matches.NAME
            $acceptCurrent = $false

            foreach($rx in $allowedMatchers){
                if($rx.IsMatch($currentName)){ $acceptCurrent = $true; break }
            }
            continue
        }

        if($l -match '^\s*PID:'){
            $m = [regex]::Match(
                $l,
                '^\s*PID:\s*(?<PID>[^,]*)\s*,.*?\bSN:\s*(?<SN>\S+)',
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )
            if($m.Success){
                $prodId = $m.Groups['PID'].Value.Trim()
                $sn     = $m.Groups['SN'].Value.Trim()
                if($acceptCurrent){
                    if(-not $AsObject){ $out += $sn }
                    else{
                        $out += [pscustomobject]@{
                            Source       = 'inventory'
                            Name         = $currentName
                            ProductID    = if($prodId){ $prodId } else { $null }
                            SN           = $sn
                            OriginalLine = $null
                        }
                    }
                }
            } else {
                if($acceptCurrent){
                    if(-not $AsObject){ $out += $l }
                    else{
                        $out += [pscustomobject]@{
                            Source       = 'inventory'
                            Name         = $currentName
                            ProductID    = $null
                            SN           = $null
                            OriginalLine = $l
                        }
                    }
                }
                # Reset nach PID-Zeile
                $currentName   = $null
                $acceptCurrent = $false
            }
            continue
        }
    }

    if($out.Count -gt 0){ return $out }
    return @()
}

# --- Robust, ShellStream-only: ImageFiles from show version --- # final
function Get-Cisco-ImageFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]  [string]$HostAddress,
        [Parameter(Mandatory=$false)] [int]$HostPort = 22,
        [Parameter(Mandatory=$true)]  [pscredential]$Credential,
        [Parameter(Mandatory=$false)] [switch]$AcceptKey,
        [Parameter(Mandatory=$false)] [int]$TimeOutSec = 3,
        [Parameter(Mandatory=$false)] [switch]$AsObject
    )

    function _San([string]$s){
        if(-not $s){ return $s }
        $s = [regex]::Replace($s, "\x1B\[[0-9;?]*[ -/]*[@-~]", "")
        $s = [regex]::Replace($s, "\x1B][^\x07\x1B]*(\x07|\x1B\\)", "")
        $s = [regex]::Replace($s, "[\x00-\x1F\x7F]", "")
        return $s.TrimEnd()
    }

    $cmd   = 'show version | i System image file is'
    $lines = Get-Cisco-SSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential `
               -AcceptKey:$AcceptKey -Command $cmd -TimeoutSec $TimeOutSec -NoPaging -GenericPrompt
    $clean = $lines | ForEach-Object { _San $_ } | Where-Object { $_ -ne "" }


    $hits = foreach($l in $clean){
        # Beispiele:
        # System image file is "flash:/cat9k_iosxe.BLD.bin"
        # System image file is bootflash:/isr-image.bin

        # Greift sowohl "..." (liefert nur Inhalt ohne ") als auch unquoted
        if($l -match '(?i)^\s*System\s+image\s+file\s+is\s+(?:"(?<PATH>[^"\r\n]+)"|(?<PATH>[^"\s\r\n]+))'){
            $path = $Matches.PATH.Trim()

            # Storage (flash, bootflash, etc.) extrahieren
            $storage = $null
            if($path -match '^(?<STOR>[\w\-]+):'){
                $storage = $Matches.STOR
            }

            if(-not $AsObject){
                # Nur den Pfad ausgeben (ohne Anführungszeichen)
                $path
            } else {
                [pscustomobject]@{
                    Path    = $path
                    Storage = $storage
                    Raw     = $l
                }
            }
        }
    }


    if($hits){ return ,$hits }  # 1..N (VSS: potenziell 2)

    # Fallback (Diagnose):
    return $clean
}
