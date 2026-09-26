$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'node_setup.py'
if (Get-Command py.exe -ErrorAction SilentlyContinue) {
    & py.exe -3 $installer @args
} elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
    & python.exe $installer @args
} else {
    throw 'Install Python 3.10 or newer before running this installer.'
}
exit $LASTEXITCODE
