param([ValidateRange(0,4294967295)][long]$Seed=1028,[ValidateRange(1,1000)][int]$Count=200)
$ErrorActionPreference='Stop'
$repo = (git -C $PSScriptRoot rev-parse --show-toplevel)
if ($LASTEXITCODE -ne 0) { throw 'Cannot determine checkout root' }
$nodeExecutable = (Get-Command node -CommandType Application | Select-Object -First 1).Source
if (!$nodeExecutable) { throw 'Node executable not found' }
function Get-Evidence {
  $head = git -C $repo rev-parse HEAD
  if ($LASTEXITCODE -ne 0) { throw 'Cannot read Git HEAD' }
  $status = @(git -C $repo status --porcelain=v1 --untracked-files=all)
  if ($LASTEXITCODE -ne 0) { throw 'Cannot read Git status' }
  $files = @((Get-ChildItem -LiteralPath (Join-Path $repo 'sdks/javascript/src') -File -Recurse).FullName)
  $files += @('sdks/javascript/package.json','tests/test_seeded_corpus.mjs','tests/test_seeded_corpus_oracle.mjs','tests/seeded-corpus-oracle.mjs','tests/run_seeded_corpus.mjs','tests/run_seeded_corpus.ps1','examples/shadow/receipt-contract.mjs') | ForEach-Object { Join-Path $repo $_ }
  $hashes = @($files | Sort-Object | ForEach-Object { $file = Get-Item -LiteralPath $_; [ordered]@{path=[IO.Path]::GetRelativePath($repo,$file.FullName).Replace('\','/'); sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} })
  $nodeVersion = & $nodeExecutable --version
  if ($LASTEXITCODE -ne 0) { throw 'Cannot read Node version' }
  $sqliteVersion = & $nodeExecutable --no-warnings -e "const {DatabaseSync}=require('node:sqlite');const d=new DatabaseSync(':memory:');console.log(d.prepare('select sqlite_version() as version').get().version);d.close()"
  if ($LASTEXITCODE -ne 0) { throw 'Cannot read SQLite version' }
  $runtime = [ordered]@{nodeVersion=$nodeVersion;nodeExecutable=$nodeExecutable;nodeSha256=(Get-FileHash -LiteralPath $nodeExecutable -Algorithm SHA256).Hash.ToLowerInvariant();sqliteVersion=$sqliteVersion;nodeOptionsPresent=[bool]$env:NODE_OPTIONS;progressEnabled=($env:SAPI_CORPUS_PROGRESS -eq '1')}
  return [ordered]@{head=$head;dirty=($status.Count -gt 0);status=$status;files=$hashes;runtime=$runtime}
}
$before=Get-Evidence
[ordered]@{type='local_input_evidence_before';seed=$Seed;count=$Count;evidence=$before} | ConvertTo-Json -Depth 8 -Compress
$previousSeed=$env:SAPI_CORPUS_SEED; $previousCount=$env:SAPI_CORPUS_COUNT
try {
 $env:SAPI_CORPUS_SEED="$Seed"; $env:SAPI_CORPUS_COUNT="$Count"
 & $nodeExecutable (Join-Path $repo 'tests/test_seeded_corpus.mjs')
 $code=$LASTEXITCODE
} finally { $env:SAPI_CORPUS_SEED=$previousSeed; $env:SAPI_CORPUS_COUNT=$previousCount }
$after=Get-Evidence
$same=(ConvertTo-Json -InputObject $before -Depth 8 -Compress) -ceq (ConvertTo-Json -InputObject $after -Depth 8 -Compress)
[ordered]@{type='local_input_evidence_after';inputsUnchanged=$same;exitCode=$code;evidence=$after} | ConvertTo-Json -Depth 8 -Compress
if (!$same -or $code -ne 0) { exit 1 }
