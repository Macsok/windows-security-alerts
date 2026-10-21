<#
.SYNOPSIS
Creates a ZIP containing only the reviewed source package files.
.DESCRIPTION
Creates a ZIP containing only the reviewed source package files.
.PARAMETER OutputPath
Destination ZIP archive; an existing archive is not overwritten.
.EXAMPLE
.\tools\Export-SharePackage.ps1 -OutputPath .\dist\source.zip
#>
[CmdletBinding()]
param([string]$OutputPath='')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot
. "$PSScriptRoot/Get-ShareFiles.ps1"
& "$PSScriptRoot/Test-ShareReadiness.ps1" -Root $repo | Out-Host
if (!$OutputPath) { $OutputPath=Join-Path $repo 'dist/OSO-English.zip' }
$OutputPath=[IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $OutputPath) { throw 'The archive already exists. Choose a new -OutputPath to preserve it.' }
[void][IO.Directory]::CreateDirectory((Split-Path $OutputPath))
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[IO.Compression.ZipFile]::Open($OutputPath,[IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in Get-ShareFiles -Root $repo) {
        $relative=$file.FullName.Substring($repo.Length+1).Replace('\','/')
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$file.FullName,$relative,[IO.Compression.CompressionLevel]::Optimal)
    }
} finally { $archive.Dispose() }
[pscustomobject]@{Archive=$OutputPath;Scope='Source, documentation, tests, and synthetic examples only'}
