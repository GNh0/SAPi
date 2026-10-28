// All new local artifacts must be direct children of this one workspace directory.
import {lstatSync,mkdirSync,realpathSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join,resolve,relative,isAbsolute,dirname} from 'node:path';
const workspace=fileURLToPath(new URL('../../../',import.meta.url));
const evidence=join(workspace,'evidence');
export const artifactRoot=join(evidence,'local-runs');
function inside(parent,child) {const rel=relative(parent,child);return !!rel&&!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+(process.platform==='win32'?'\\':'/'));}
function ensurePlainDirectory(p) {const s=lstatSync(p);if(!s.isDirectory()||s.isSymbolicLink()) throw Error('linked or invalid artifact directory');}
export function validateArtifactRoot(candidate=artifactRoot) {
  if(resolve(candidate)!==resolve(artifactRoot)) throw Error('artifact directory is fixed');
  ensurePlainDirectory(workspace);ensurePlainDirectory(evidence);
  const anchor=realpathSync(workspace), parent=realpathSync(evidence);
  if(!inside(anchor,parent)) throw Error('artifact directory outside workspace');
  try {ensurePlainDirectory(artifactRoot);} catch(e) {if(e.code!=='ENOENT') throw e;mkdirSync(artifactRoot);ensurePlainDirectory(artifactRoot);}
  if(!inside(parent,realpathSync(artifactRoot))) throw Error('artifact directory outside workspace');
  return artifactRoot;
}
export function validateArtifactFile(path) {
  const root=validateArtifactRoot();
  if(typeof path!=='string'||resolve(dirname(path))!==resolve(root)) throw Error('artifact file must be in fixed directory');
  return resolve(path);
}
