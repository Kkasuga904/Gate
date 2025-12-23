[CmdletBinding()]
param(
  [string]$ServerExe = "go",
  [string[]]$ServerArgs = @("run", ".", "mcp"),
  [string]$RequestsFile,
  [string[]]$Requests,
  [switch]$Pretty,
  [switch]$ShowOutgoing,
  [int]$TimeoutMs = 0
)

Set-StrictMode -Version Latest
if ($PSBoundParameters.ContainsKey('Verbose')) {
    $VerbosePreference = 'Continue'
}


function Escape-Arg([string]$Value) {
	if ($Value -match '[\s"]') {
		return '"' + ($Value -replace '"', '\"') + '"'
	}
	return $Value
}

function Normalize-Payload([string]$Value) {
	$trimmed = $Value.Trim()
	if ($trimmed.Length -gt 0 -and $trimmed[0] -eq [char]0xFEFF) {
		return $trimmed.Substring(1)
	}
	return $trimmed
}

function Get-Requests {
	if ($RequestsFile) {
		$lines = Get-Content -LiteralPath $RequestsFile
		$result = @()
		foreach ($line in $lines) {
			$trimmed = Normalize-Payload $line
			if ($trimmed -ne "") {
				$result += $trimmed
			}
		}
		if ($result.Count -eq 0) {
			throw "requests file is empty"
		}
		return [string[]]@($result)
	}
	if ($Requests) {
		$result = @()
		foreach ($req in @($Requests)) {
			$trimmed = Normalize-Payload $req
			if ($trimmed -ne "") {
				$result += $trimmed
			}
		}
		return [string[]]@($result)
	}
	throw "missing -RequestsFile or -Requests"
}

function Write-Frame($Stream, [string]$ReqPayload) {
	$cleanPayload = Normalize-Payload $ReqPayload
	if ($cleanPayload -eq "") {
		throw "refusing to send empty payload"
	}
	$payloadBytes = [Text.Encoding]::UTF8.GetBytes($cleanPayload)
	$header = [Text.Encoding]::ASCII.GetBytes("Content-Length: $($payloadBytes.Length)`r`n`r`n")
	$Stream.Write($header, 0, $header.Length)
	$Stream.Write($payloadBytes, 0, $payloadBytes.Length)
	$Stream.Flush()
}

function Read-Frame($Stream) {
	$maxHeaderBytes = 65536
	$headerBytes = New-Object System.Collections.Generic.List[byte]
	$tail = @()

	while ($true) {
		try {
			$byte = $Stream.ReadByte()
		} catch {
			throw "timeout waiting for MCP response (header)"
		}
		if ($byte -lt 0) {
			return $null
		}
		$headerBytes.Add([byte]$byte) | Out-Null
		if ($headerBytes.Count -gt $maxHeaderBytes) {
			throw "header too large (missing CRLFCRLF terminator)"
		}

		$tail += $byte
		if ($tail.Count -gt 4) {
			$tail = $tail[-4..-1]
		}
		if ($tail.Count -eq 4 -and $tail[0] -eq 13 -and $tail[1] -eq 10 -and $tail[2] -eq 13 -and $tail[3] -eq 10) {
			break
		}
	}

	$headerText = [Text.Encoding]::ASCII.GetString($headerBytes.ToArray())
	$trimmedHeader = $headerText.Trim()
	$preview = ($trimmedHeader -replace "`r", "") -replace "`n", "\n"
	if ($preview.Length -gt 200) {
		$preview = $preview.Substring(0, 200)
	}
	Write-Verbose "header: $preview"

	$m = [regex]::Match($trimmedHeader, '(?im)^Content-Length:\s*(\d+)\s*$')
	if (-not $m.Success) {
		throw "missing Content-Length (header preview: $preview)"
	}
	$length = [int]$m.Groups[1].Value
	Write-Verbose "content-length: $length"
	Write-Verbose "reading body $length bytes"
	$body = New-Object byte[] $length
	$offset = 0
	while ($offset -lt $length) {
		try {
			$read = $Stream.Read($body, $offset, $length - $offset)
		} catch {
			throw "timeout waiting for MCP response (body)"
		}
		if ($read -le 0) {
			throw "unexpected EOF while reading body"
		}
		$offset += $read
	}
	return [Text.Encoding]::UTF8.GetString($body)
}

function Apply-RequestId([string]$Payload, [int]$RequestId) {
	$result = $Payload.Replace('"{{request_id}}"', $RequestId.ToString())
	return $result.Replace("{{request_id}}", $RequestId.ToString())
}

function Get-RequestMethod([string]$Payload) {
	$m = [regex]::Match($Payload, '"method"\s*:\s*"([^"]+)"')
	if ($m.Success) {
		return $m.Groups[1].Value
	}
	return ""
}

function Write-OutgoingDiagnostics([string]$Payload, [int]$FrameNumber) {
	$payloadBytes = [Text.Encoding]::UTF8.GetBytes($Payload)
	$first = $Payload
	if ($first.Length -gt 120) {
		$first = $first.Substring(0, 120)
	}
	$sha = [System.Security.Cryptography.SHA256]::Create()
	try {
		$hash = $sha.ComputeHash($payloadBytes)
		$hashHex = ([System.BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
	} finally {
		$sha.Dispose()
	}
	$lines = @(
		"frame $FrameNumber payloadLengthBytes=$($payloadBytes.Length)",
		"frame $FrameNumber payloadFirst120=$first",
		"frame $FrameNumber payloadSha256=$hashHex"
	)
	foreach ($line in $lines) {
		if ($ShowOutgoing) {
			Write-Host $line
		} else {
			Write-Verbose $line
		}
	}
}

$requestPayloads = @(Get-Requests)
if ($requestPayloads.Count -eq 0) {
	throw "no requests to send"
}

$argsString = ($ServerArgs | ForEach-Object { Escape-Arg $_ }) -join " "
Write-Verbose "server: $ServerExe $argsString"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ServerExe
$psi.Arguments = $argsString
$psi.WorkingDirectory = (Get-Location).Path
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi
if (-not $proc.Start()) {
	throw "failed to start server process"
}

[System.Threading.Tasks.Task]::Run([Action]{
	try {
		$stream = $proc.StandardError.BaseStream
		$buffer = New-Object byte[] 4096
		while ($true) {
			$read = $stream.Read($buffer, 0, $buffer.Length)
			if ($read -le 0) {
				break
			}
		}
	} catch {
	}
}) | Out-Null

$stdinStream = $proc.StandardInput.BaseStream
$stdoutStream = $proc.StandardOutput.BaseStream
if ($TimeoutMs -gt 0) {
	try {
		$stdoutStream.ReadTimeout = $TimeoutMs
	} catch {
		Write-Verbose "stdout stream does not support ReadTimeout"
	}
}
$lastRequestId = $null

for ($i = 0; $i -lt $requestPayloads.Count; $i++) {
	$reqPayload = $requestPayloads[$i]
	if ($reqPayload -isnot [string]) {
		throw "payload is not string: $($reqPayload.GetType().FullName)"
	}
	if ($reqPayload.Length -lt 20) {
		throw "payload too short (likely char-iteration bug): '$reqPayload'"
	}
	$frameNumber = $i + 1
	$finalPayload = $reqPayload
	if ($finalPayload -match "{{request_id}}") {
		if (-not $lastRequestId) {
			throw "request_id placeholder used before any response"
		}
		$finalPayload = Apply-RequestId $finalPayload $lastRequestId
	}
	$finalPayload = Normalize-Payload $finalPayload
	if ($finalPayload -eq "") {
		throw "refusing to send empty payload"
	}
	if ($ShowOutgoing -or $VerbosePreference -ne "SilentlyContinue") {
		Write-OutgoingDiagnostics $finalPayload $frameNumber
	}
	$methodName = Get-RequestMethod $finalPayload
	$payloadBytes = [Text.Encoding]::UTF8.GetBytes($finalPayload)
	if ($payloadBytes.Length -lt 80 -and @("gate.execute_request", "gate.approve", "gate.deny") -contains $methodName) {
		throw "payload too small for $methodName (bytes=$($payloadBytes.Length))"
	}
	Write-Verbose "sending frame $frameNumber"
	Write-Frame $stdinStream $finalPayload
	Write-Verbose "waiting response $frameNumber"
	$respJson = Read-Frame $stdoutStream
	if ($null -eq $respJson) {
		break
	}
	Write-Verbose ("received frame {0} (bytes={1})" -f $frameNumber, $respJson.Length)

	if ($Pretty) {
		try {
			$parsed = $respJson | ConvertFrom-Json
			$respJson = $parsed | ConvertTo-Json -Depth 20
		} catch {
		}
	}
	Write-Output $respJson

	try {
		$respObj = $respJson | ConvertFrom-Json
		if ($respObj.result -and $respObj.result.request_id) {
			$lastRequestId = [int]$respObj.result.request_id
		}
	} catch {
	}
}

$stdinStream.Close()
$proc.WaitForExit()
