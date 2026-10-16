<#
.SYNOPSIS
    Builds the dpibypass Windows amd64 executable.

.DESCRIPTION
    Automates compilation of dpibypass for Windows amd64 with CGO disabled,
    applies reproducible compilation flags (-trimpath, linker stripping), stamps version
    metadata, executes a version smoke test, and calculates the SHA-256 checksum.

.PARAMETER OutFile
    Target path for the compiled binary (e.g. "bin\dpibypass.exe" or "custom.exe").
    When specified, overrides OutputDir and BinaryName.

.PARAMETER OutputDir
    Target directory where the compiled binary will be placed when OutFile is omitted. Defaults to "." (current directory).

.PARAMETER BinaryName
    Name of the output binary when OutFile is omitted. Defaults to "dpibypass.exe".

.PARAMETER RunTests
    When specified, executes automated tests ('go test -short -count=1 ./...') and static analysis
    ('go vet ./...') before building.

.PARAMETER Clean
    When specified, removes any pre-existing output binary matching the target before compiling.

.PARAMETER Reproducible
    When specified, enforces deterministic build metadata (uses SOURCE_DATE_EPOCH if set,
    or a fixed baseline timestamp) instead of dynamic local build time.

.PARAMETER CustomVersion
    Overrides the injected version string (defaults to "1.0.0-phase1").

.PARAMETER CustomCommit
    Overrides the injected Git commit identifier.

.PARAMETER CustomDate
    Overrides the injected build timestamp.
#>

[CmdletBinding()]
param (
    [string]$OutFile = "",
    [string]$OutputDir = ".",
    [string]$BinaryName = "dpibypass.exe",
    [switch]$RunTests,
    [switch]$Clean,
    [switch]$Reproducible,
    [string]$CustomVersion = "",
    [string]$CustomCommit = "",
    [string]$CustomDate = ""
)

$ErrorActionPreference = "Stop"

Write-Host "=== dpibypass Windows Build Automation ==="

# 1. Verify Go toolchain
$goCmd = Get-Command "go" -ErrorAction SilentlyContinue
if (-not $goCmd) {
    Write-Error "Go compiler ('go') not found in system PATH. Please install Go 1.26.0+."
    exit 1
}

$goVersionRaw = & go version
Write-Host "Toolchain: $goVersionRaw"

# Determine repository root
$repoRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($repoRoot)) {
    $repoRoot = (Get-Location).ProviderPath
}

# 2. Resolve target output path
$targetPath = ""
if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
    if ([System.IO.Path]::IsPathRooted($OutFile)) {
        $targetPath = [System.IO.Path]::GetFullPath($OutFile)
    } else {
        $targetPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Get-Location).ProviderPath, $OutFile))
    }
    $parentDir = [System.IO.Path]::GetDirectoryName($targetPath)
    if (-not [string]::IsNullOrWhiteSpace($parentDir)) {
        if (-not (Test-Path -Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }
    }
} else {
    $resolvedOutputDir = if ([System.IO.Path]::IsPathRooted($OutputDir)) {
        [System.IO.Path]::GetFullPath($OutputDir)
    } else {
        [System.IO.Path]::GetFullPath([System.IO.Path]::Combine((Get-Location).ProviderPath, $OutputDir))
    }
    if (-not (Test-Path -Path $resolvedOutputDir)) {
        New-Item -ItemType Directory -Path $resolvedOutputDir -Force | Out-Null
    }
    $targetPath = [System.IO.Path]::Combine($resolvedOutputDir, $BinaryName)
}

# 3. Optional clean
if ($Clean) {
    if (Test-Path -Path $targetPath) {
        $item = Get-Item -Path $targetPath
        $expectedName = [System.IO.Path]::GetFileName($targetPath)
        if (-not $item.PSIsContainer -and $item.Name -eq $expectedName) {
            Remove-Item -Path $targetPath -Force
            Write-Host "Cleaned existing binary: $targetPath"
        }
    }
}

# Push location to repository root for tests, git metadata, and compilation
Push-Location -Path $repoRoot
try {
    # 4. Optional pre-build validation
    if ($RunTests) {
        Write-Host "Running automated unit and integration tests (go test -short -count=1 ./...)..."
        & go test -short -count=1 ./...
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Pre-build test suite failed with exit code $LASTEXITCODE."
            exit $LASTEXITCODE
        }

        Write-Host "Running static analysis (go vet ./...)..."
        & go vet ./...
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Static analysis (go vet) failed with exit code $LASTEXITCODE."
            exit $LASTEXITCODE
        }
        Write-Host "Pre-build checks passed successfully."
    }

    # 5. Resolve build metadata
    $buildVersion = "1.0.0-phase1"
    if (-not [string]::IsNullOrWhiteSpace($CustomVersion)) {
        $buildVersion = $CustomVersion
    }

    $buildCommit = "untracked"
    if (-not [string]::IsNullOrWhiteSpace($CustomCommit)) {
        $buildCommit = $CustomCommit
    } else {
        $gitCmd = Get-Command "git" -ErrorAction SilentlyContinue
        if ($gitCmd) {
            $prevEAP = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                $gitHash = & git rev-parse --short HEAD 2>$null
                if ($LASTEXITCODE -eq 0 -and (-not [string]::IsNullOrWhiteSpace($gitHash))) {
                    $statusOut = & git status --porcelain 2>$null
                    if (-not [string]::IsNullOrWhiteSpace($statusOut)) {
                        $buildCommit = "$gitHash-dirty"
                    } else {
                        $buildCommit = $gitHash
                    }
                }
            } catch {
                $buildCommit = "untracked"
            } finally {
                $ErrorActionPreference = $prevEAP
            }
        }
    }

    $buildDate = ""
    if (-not [string]::IsNullOrWhiteSpace($CustomDate)) {
        $buildDate = $CustomDate
    } elseif ($Reproducible) {
        if (-not [string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH)) {
            try {
                $epochSec = [int64]$env:SOURCE_DATE_EPOCH
                $buildDate = [DateTimeOffset]::FromUnixTimeSeconds($epochSec).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            } catch {
                $buildDate = "2026-10-12T00:00:00Z"
            }
        } else {
            # Fixed deterministic timestamp for reproducible release builds
            $buildDate = "2026-10-12T00:00:00Z"
        }
    } else {
        $buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    # 6. Execute compilation
    Write-Host "Compiling Windows amd64 binary..."
    Write-Host "  Target      : $targetPath"
    Write-Host "  Version     : $buildVersion"
    Write-Host "  Commit      : $buildCommit"
    Write-Host "  Build Date  : $buildDate"
    Write-Host "  Reproducible: $($Reproducible.IsPresent)"

    $origCgo = $env:CGO_ENABLED
    $origGoos = $env:GOOS
    $origGoarch = $env:GOARCH

    try {
        $env:CGO_ENABLED = "0"
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"

        $ldflags = "-s -w -X main.version=$buildVersion -X main.commit=$buildCommit -X main.buildDate=$buildDate"

        if (Test-Path -Path $targetPath) {
            Remove-Item -Path "$targetPath.*.old" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $targetPath -Force -ErrorAction SilentlyContinue
            if (Test-Path -Path $targetPath) {
                $oldPath = "$targetPath.$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()).old"
                Move-Item -Path $targetPath -Destination $oldPath -Force -ErrorAction SilentlyContinue
            }
        }

        & go build -trimpath -ldflags $ldflags -o $targetPath ./cmd/dpibypass
        if ($LASTEXITCODE -ne 0) {
            Write-Error "go build failed with exit code $LASTEXITCODE."
            exit $LASTEXITCODE
        }
    } finally {
        $env:CGO_ENABLED = $origCgo
        $env:GOOS = $origGoos
        $env:GOARCH = $origGoarch
    }
} finally {
    Pop-Location
}

if (-not (Test-Path -Path $targetPath)) {
    Write-Error "Expected build artifact '$targetPath' was not created."
    exit 1
}

# 7. Smoke test compiled binary
Write-Host "Executing smoke test (& $targetPath version)..."
$smokeOutput = & $targetPath version
if ($LASTEXITCODE -ne 0) {
    Write-Error "Smoke test failed: binary returned exit code $LASTEXITCODE."
    exit $LASTEXITCODE
}
Write-Host "Smoke test passed: $smokeOutput"

# 8. Report artifact details and checksum
$fileItem = Get-Item -Path $targetPath
$hash = Get-FileHash -Path $targetPath -Algorithm SHA256
$sizeMB = [math]::Round($fileItem.Length / 1MB, 2)

Write-Host ""
Write-Host "================ Build Artifact Summary ================"
Write-Host "Binary File  : $($fileItem.FullName)"
Write-Host "Size         : $($fileItem.Length) bytes ($sizeMB MB)"
Write-Host "SHA-256 Hash : $($hash.Hash)"
Write-Host "Architecture : Windows amd64 (pure Go, CGO disabled)"
Write-Host "Version Tag  : $buildVersion"
Write-Host "Commit ID    : $buildCommit"
Write-Host "Timestamp    : $buildDate"
if ($Reproducible) {
    Write-Host "Mode         : Reproducible (fixed metadata)"
} else {
    Write-Host "Mode         : Standard (dynamic timestamp)"
}
Write-Host "========================================================"
Write-Host "Build completed successfully."
