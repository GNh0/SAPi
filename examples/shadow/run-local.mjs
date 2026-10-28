import {runMixed} from './mixed-runner.mjs';
import {createProcessComparison} from './process-comparison.mjs';
import {createEvidence} from './sqlite-evidence.mjs';
const args=process.argv.slice(2);
if (!((args.length===1 && args[0]==='--dry-run') || ((args.length===2||args.length===3) && args[0]==='--loopback' && (args.length===2||/^[1-7]$/.test(args[2]))))) {
  console.error('Disabled. Choose --dry-run or --loopback NEW_SQLITE_FILE [RUNS 1-7]'); process.exitCode=2;
} else {
  const dryRun=args[0]==='--dry-run';
  const runs=args.length===3?Number(args[2]):1;
  const evidence=dryRun?undefined:createEvidence(args[1]);
  const processComparison=dryRun?undefined:createProcessComparison({seed:1,runs});
  try {
    const result=await runMixed({enabled:true,dryRun,seed:1,runs,compare:processComparison?.compare,evidence});
    console.log(JSON.stringify(result,null,2));
    if (!dryRun && !result.pass) process.exitCode=1;
  } finally {evidence?.close();}
}
