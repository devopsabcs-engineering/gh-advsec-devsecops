#Requires -Version 7.0
<#
.SYNOPSIS
    Computes the deterministic semantic build version shared by all three CI/CD providers
    (GitHub Actions, Azure DevOps, GitLab CI).

.DESCRIPTION
    The version scheme is MAJOR.MINOR.PATCH starting at 1.0.0. The patch component is derived
    from the highest existing 'vMAJOR.MINOR.*' git tag plus one, so every tagged pipeline run on
    the default branch increments the patch by exactly one:

        (no tags)      -> 1.0.0
        v1.0.0 exists  -> 1.0.1
        v1.0.1 exists  -> 1.0.2  ...

    If the current commit (HEAD) is already tagged with a matching version, that version is reused
    so pipeline re-runs are idempotent and never produce a duplicate or skipped patch.

    The computation depends only on git tags, so it produces identical results on every provider
    without any external tooling. Pipelines must fetch the full history and tags (for example
    'fetch-depth: 0' on GitHub, 'fetch: 0' / unshallow on Azure DevOps, and 'GIT_DEPTH: 0' on
    GitLab) so the tag list is complete.

.PARAMETER Major
    Major version component. Defaults to 1.

.PARAMETER Minor
    Minor version component. Defaults to 0.

.PARAMETER CreateTag
    When set, creates the annotated tag 'vMAJOR.MINOR.PATCH' locally (if it does not already
    exist). Pushing the tag is left to the caller so provider-specific credentials are used.

.OUTPUTS
    System.String. The computed semantic version (for example '1.0.3').
#>
[CmdletBinding()]
param(
    [int]$Major = 1,
    [int]$Minor = 0,
    [switch]$CreateTag
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-NextBuildVersion {
    param(
        [int]$Major,
        [int]$Minor
    )

    $prefix = "v$Major.$Minor."
    $head = (& git rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($head)) {
        throw 'Unable to resolve HEAD commit. Run this script inside a git working tree with full history.'
    }
    $head = $head.Trim()

    # Reuse a version already tagged on HEAD to keep pipeline re-runs idempotent.
    $onHead = @(& git tag --points-at $head --list "$prefix*")
    $reusePatches = @(
        $onHead |
            ForEach-Object { $_.Substring($prefix.Length) } |
            Where-Object { $_ -match '^\d+$' } |
            ForEach-Object { [int]$_ }
    )
    if ($reusePatches.Count -gt 0) {
        $patch = ($reusePatches | Measure-Object -Maximum).Maximum
        return "$Major.$Minor.$patch"
    }

    # Otherwise take the highest existing patch for this MAJOR.MINOR and increment it.
    $allTags = @(& git tag --list "$prefix*")
    $patches = @(
        $allTags |
            ForEach-Object { $_.Substring($prefix.Length) } |
            Where-Object { $_ -match '^\d+$' } |
            ForEach-Object { [int]$_ }
    )
    if ($patches.Count -gt 0) {
        $next = ($patches | Measure-Object -Maximum).Maximum + 1
    }
    else {
        $next = 0
    }

    return "$Major.$Minor.$next"
}

$version = Get-NextBuildVersion -Major $Major -Minor $Minor

if ($CreateTag) {
    $tag = "v$version"
    $existing = @(& git tag --list $tag)
    if ($existing.Count -eq 0) {
        & git tag -a $tag -m "Release $tag" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create git tag $tag."
        }
    }
}

Write-Output $version
