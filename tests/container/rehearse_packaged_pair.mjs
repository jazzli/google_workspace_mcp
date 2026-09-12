// Explicit opt-in, synthetic-only local qualification. No provider transport.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const PY = "/usr/local/bin/python3.11";
const LAUNCHER = "/opt/mcp-runtime/runtime_launcher.py";
const HELPER = "/opt/mcp-runtime/content_permission_migration.py";
const BASE = "sha256:933b5d014a64ec9ff4a6499f3b039659f29d59976b53e9689b09f9c99940f0b0";
const PREFIX = "packaged-rehearsal";
const LOCAL = /^sha256:[0-9a-f]{64}$/;
const provider = {
  project_id:"10000000-0000-4000-8000-000000000001",
  environment_id:"10000000-0000-4000-8000-000000000002",
  service_id:"10000000-0000-4000-8000-000000000003",
  volume_id:"10000000-0000-4000-8000-000000000004",
};
const ENV = Object.freeze({
  ...Object.fromEntries(Object.entries(provider).map(([k,v]) => ["RAILWAY_"+k.toUpperCase(),v])),
  RAILWAY_VOLUME_MOUNT_PATH:"/data", HOME:"/home/app", PORT:"8000",
  WORKSPACE_MCP_HOST:"127.0.0.1", WORKSPACE_EXTERNAL_URL:"http://127.0.0.1:8000",
  WORKSPACE_MCP_OAUTH_PROXY_DISK_DIRECTORY:"/data/oauth-proxy",
  WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND:"disk", WORKSPACE_MCP_PERMISSIONS:"calendar:readonly",
  WORKSPACE_MCP_STATELESS_MODE:"false", WORKSPACE_MCP_TRANSPORT:"streamable-http",
  TOOL_TIER:"core", TOOLS:"calendar", MCP_ENABLE_OAUTH21:"true",
  OAUTH2_ALLOW_INSECURE_TRANSPORT:"true", OAUTH2_ENABLE_DEBUG:"false", OAUTH2_ENABLE_LEGACY_AUTH:"false",
  WORKSPACE_MCP_ALLOWED_CLIENT_REDIRECT_URIS:"http://127.0.0.1:8000/oauth2callback",
  GOOGLE_OAUTH_REDIRECT_URI:"http://127.0.0.1:8000/oauth2callback",
  GOOGLE_OAUTH_CLIENT_ID:"123456789-rehearsal.apps.googleusercontent.com",
  GOOGLE_OAUTH_CLIENT_SECRET:"synthetic-rehearsal-client-secret",
  FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY:"synthetic-rehearsal-signing-key-0123456789abcdef",
});
const envArgs = () => Object.entries(ENV).flatMap(([k,v]) => ["--env",k+"="+v]);
const sha = data => createHash("sha256").update(data).digest("hex");
const canonical = obj => JSON.stringify(Object.fromEntries(Object.keys(obj).sort().map(k => [k,obj[k]])));
function validateContext(context) {
  assert.ok(["default","desktop-linux"].includes(context),"unsupported-docker-context");
  assert.ok(!process.env.DOCKER_HOST && !process.env.DOCKER_CONTEXT,"implicit-docker-override");
}
export function selectDockerContext(context,spawn=spawnSync) {
  validateContext(context);
  const read=spawn("docker",["context","inspect",context,"--format","{{json .Endpoints.docker.Host}}"],
    {encoding:"utf8",timeout:15000,killSignal:"SIGKILL",maxBuffer:8192});
  assert.ok(!read.error && read.status===0,"docker-context-unavailable");
  const endpoint=JSON.parse(read.stdout);
  assert.ok(typeof endpoint==="string" && /^unix:\/\/\/[^\s\x00-\x1f]+$/.test(endpoint),"nonlocal-docker-endpoint");
  const info=dockerTransport(["info","--format","{{.OSType}}/{{.Architecture}}"],{timeout:15000,context},spawn);
  assert.ok(!info.error && info.status===0 && /^linux\/(amd64|x86_64|arm64|aarch64)$/.test(info.stdout.trim()),"unsupported-docker-daemon");
  return context;
}
export function dockerTransport(args,{timeout,context="desktop-linux"},spawn=spawnSync) {
  validateContext(context);
  assert.ok(Number.isInteger(timeout) && timeout>0 && timeout<=120000,"invalid-docker-timeout");
  return spawn("docker",["--context",context,...args],
    {encoding:"utf8",timeout,killSignal:"SIGKILL",maxBuffer:8*1024*1024});
}

export class Harness {
  constructor(runtime, migration, invoke, clock=Date.now) {
    assert.ok(typeof runtime === "string" && LOCAL.test(runtime));
    assert.ok(typeof migration === "string" && LOCAL.test(migration) && runtime !== migration);
    this.runtime=runtime; this.migration=migration; this.clock=clock;
    this.deadline=clock()+600000; this.ceiling=120000;
    this.containers=new Set(); this.volumes=new Set();
    this.invoke=invoke ?? dockerTransport;
  }
  call(args, allowFailure=false) {
    const remaining=this.deadline-this.clock();
    if (remaining<=0) throw new Error("work-deadline");
    const result=this.invoke(args,{timeout:Math.min(remaining,this.ceiling)});
    if (result.error) throw new Error("docker-transport-failed");
    if (!allowFailure && result.status!==0) throw new Error("docker-"+args[0]+"-failed");
    return result;
  }
  register(kind,suffix) {
    assert.match(suffix,/^[a-z][a-z0-9-]{0,40}$/);
    assert.ok(this.containers.size+this.volumes.size<128,"resource-limit");
    const name=PREFIX+"-"+suffix+"-"+randomUUID();
    this[kind].add(name); return name;
  }
  container(suffix) { return this.register("containers",suffix); }
  volume(suffix) {
    const name=this.register("volumes",suffix);
    this.call(["volume","create",name]); return name;
  }
  transient(volume,code,{image=this.runtime,user="0:0",args=[],mounts=[]}={}) {
    const name=this.container("probe");
    const result=this.call(["run","--name",name,"--pull","never","--platform","linux/amd64",
      "--network","none","--user",user,...envArgs(),...(volume?["--mount","type=volume,src="+volume+",dst=/data"]:[]),
      ...mounts,"--entrypoint",PY,image,"-I","-S","-c",code,...args]);
    this.call(["rm",name]); return result.stdout.trim();
  }
  cleanup() {
    this.deadline=this.clock()+120000; this.ceiling=10000;
    const attempt=args => {try{return this.call(args,true);}catch{return {status:null};}};
    for (const name of this.containers) attempt(["rm","--force",name]);
    for (const name of this.volumes) attempt(["volume","rm",name]);
    const states=(kind,names) => [...names].map(name => {
      const result=attempt(kind==="container"
        ? ["container","ls","--all","--filter","name=^/"+name+"$","--format","{{.Names}}"]
        : ["volume","ls","--filter","name=^"+name+"$","--format","{{.Name}}"]);
      if(result.status!==0) return "unknown";
      const lines=result.stdout.trim().split("\n").filter(Boolean);
      return lines.length===0 ? "absent" : lines.every(v=>v===name) ? "present" : "unknown";
    });
    const cs=states("container",this.containers),vs=states("volume",this.volumes);
    const counts=xs=>Object.fromEntries(["absent","present","unknown"].map(k=>[k,xs.filter(v=>v===k).length]));
    return {containers:cs.length,volumes:vs.length,containerAbsence:counts(cs),volumeAbsence:counts(vs),
      verifiedAbsent:[...cs,...vs].every(v=>v==="absent"),
      ledger:{containers:[...this.containers],volumes:[...this.volumes]}};
  }
  finish(receipt) {
    receipt.cleanup=this.cleanup();
    if(!receipt.cleanup.verifiedAbsent) {
      receipt.failed=true;
      receipt.failureClass??="fixture-cleanup-incomplete";
      throw Object.assign(new Error("fixture-cleanup-incomplete"),{receipt});
    }
    return receipt;
  }
}

function operation(helperHash,seconds=600) {
  const op={operation_id:randomUUID(),mutate_until:Math.floor(Date.now()/1000)+seconds,...provider,
    runtime_image:"ghcr.io/jazzli/google_workspace_mcp@sha256:"+"1".repeat(64),
    migration_image:"ghcr.io/jazzli/google_workspace_mcp@sha256:"+"2".repeat(64),
    helper_sha256:helperHash};
  return {...op,manifest_sha256:sha(canonical(op))};
}
const migrationArgs=op=>[PY,"-I","-S",HELPER,...Object.entries(op).flatMap(([k,v])=>["--"+k.replaceAll("_","-"),String(v)])];
function start(h,volume,name,mode,op,mounts=[]) {
  const full=h.container(name), command=mode==="migration"?migrationArgs(op):[PY,"-I","-S",LAUNCHER,mode];
  h.call(["run","--detach","--name",full,"--pull","never","--platform","linux/amd64","--network","none",
    "--no-healthcheck","--user",mode==="run"?"1000:1000":"0:0",...envArgs(),
    "--mount","type=volume,src="+volume+",dst=/data",...mounts,
    "--entrypoint",command[0],mode==="migration"?h.migration:h.runtime,...command.slice(1)]);
  return full;
}
function state(h,name) {return JSON.parse(h.call(["inspect","--format","{{json .State}}",name]).stdout);}
async function ready(h,name,uid) {
  const end=Math.min(h.deadline,Date.now()+120000);
  while(Date.now()<end) {
    const s=state(h,name);
    if(!s.Running) {
      const logs=h.call(["logs",name],true);
      const code=(logs.stdout+logs.stderr).match(/(?:migration|runtime)-refused:[a-z-]+/)?.[0] ?? "unclassified-startup";
      throw new Error(code);
    }
    const top=h.call(["top",name,"-eo","pid,args"],true);
    const rows=top.stdout.trim().split("\n").slice(1);
    // Observe externally until migration has exec'd the app. No competing exec.
    if(top.status===0 && rows.length===1 && rows[0].trim().startsWith(s.Pid+" ") &&
       rows[0].includes("main.py --transport streamable-http --tool-tier core --tools calendar")) {
      const result=h.call(["exec","--user",uid+":"+uid,name,PY,"-I","-S","-c",
        "import urllib.request,urllib.error,json\nh=urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2).status\ntry: urllib.request.urlopen('http://127.0.0.1:8000/mcp',timeout=2);m=200\nexcept urllib.error.HTTPError as e:m=e.code\nprint(json.dumps({'health':h,'mcp':m}))"],true);
      if(result.status===0) {const resultData=JSON.parse(result.stdout);assert.deepEqual(resultData,{health:200,mcp:401});return resultData;}
    }
    await delay(250);
  }
  throw new Error("readiness-timeout");
}
function processBoundary(h,name,uid) {
  const code=[
    "import json,os,re",
    "s=open('/proc/1/status','rb').read()",
    "field=lambda name:re.search(rb'^'+name+rb':\\s*(.+)$',s,re.M).group(1).decode()",
    "env=dict(p.split(b'=',1) for p in open('/proc/1/environ','rb').read().split(b'\\0') if b'=' in p)",
    "print(json.dumps({k:field(k.encode()) for k in ('Uid','Gid','Groups','Umask','NoNewPrivs','CapInh','CapPrm','CapEff','CapBnd','CapAmb')}|{'home':env[b'HOME'].decode(),'command':open('/proc/1/cmdline','rb').read().decode().split('\\0')[:-1]}))",
  ].join("\n");
  const data=JSON.parse(h.call(["exec","--user",uid+":"+uid,name,PY,"-I","-S","-c",code]).stdout);
  assert.deepEqual(data.Uid.trim().split(/\s+/),Array(4).fill(String(uid)));
  assert.deepEqual(data.Gid.trim().split(/\s+/),Array(4).fill(String(uid)));
  assert.equal(data.NoNewPrivs,"1");assert.equal(data.Umask,"0077");assert.equal(data.home,"/home/app");
  assert.deepEqual(data.command.slice(0,5),["/app/.venv/bin/python","-B","main.py","--transport","streamable-http"]);
  if(uid===1000) {
    assert.deepEqual(data.Groups.trim().split(/\s+/),["1000"]);
    for(const key of ["CapInh","CapPrm","CapEff","CapAmb"]) assert.equal(BigInt("0x"+data[key]),0n);
  }
  return data;
}
function stop(h,name,signal="TERM") {
  h.call(["kill","--signal",signal,name]);
  const exit=Number(h.call(["wait",name]).stdout.trim());
  h.call(["rm",name]); return exit;
}
function setup(h,volume,count=0) {
  h.transient(volume,"import os,pathlib\nos.chmod('/data',0o755)\nr=pathlib.Path('/data/oauth-proxy');r.mkdir(mode=0o755)\nfor i in range("+count+"):\n p=r/('record-'+str(i));p.write_bytes(b'synthetic encrypted fixture');p.chmod(0o644)");
}
function snapshot(h,volume) {
  return JSON.parse(h.transient(volume,[
    "import hashlib,json,pathlib,stat",
    "r=pathlib.Path('/data/oauth-proxy');h=hashlib.sha256();owners=set();modes=set();count=0",
    "for p in sorted(r.rglob('*')):",
    " s=p.lstat();owners.add(s.st_uid);modes.add(stat.S_IMODE(s.st_mode))",
    " if stat.S_ISREG(s.st_mode):h.update(str(p.relative_to(r)).encode()+b'\\0'+p.read_bytes());count+=1",
    "j=pathlib.Path('/data/.content-permission-migration');jh=hashlib.sha256();states=[]",
    "if j.exists():",
    " for p in sorted(j.rglob('journal.json')): b=p.read_bytes();jh.update(b);states.append(json.loads(b)['status'])",
    "print(json.dumps({'count':count,'recordsSha256':h.hexdigest(),'owners':sorted(owners),'modes':sorted(modes),'journalSha256':jh.hexdigest(),'journalStates':states}))",
  ].join("\n")));
}
function expectRefusal(h,volume,op,code,mounts=[]) {
  const name=start(h,volume,"refusal","migration",op,mounts);
  assert.notEqual(Number(h.call(["wait",name]).stdout.trim()),0);
  const logs=h.call(["logs",name],true);
  assert.ok((logs.stdout+logs.stderr).includes("migration-refused:"+code),"wrong-refusal-classification");
  h.call(["rm",name]);
}

async function faults(h,helperHash,probe) {
  const result={};
  const expired=h.volume("expired");setup(h,expired,3);
  const expiredBefore=snapshot(h,expired);
  expectRefusal(h,expired,operation(helperHash,-1),"mutation-window-closed");
  assert.deepEqual(snapshot(h,expired),expiredBefore);
  result.expiredFresh="refused-without-store-or-journal-effect";

  const boundary=h.volume("boundary");setup(h,boundary,511);
  const before=snapshot(h,boundary), op=operation(helperHash);
  const bounded=start(h,boundary,"boundary","migration",op);
  result.boundaryHttp=await ready(h,bounded,1000);
  result.boundaryProcess=processBoundary(h,bounded,1000);
  assert.equal(stop(h,bounded),0);
  const after=snapshot(h,boundary);
  assert.equal(after.recordsSha256,before.recordsSha256);
  assert.deepEqual(after.owners,[1000]);assert.deepEqual(after.modes,[0o600]);
  result.boundaryEntries=512;

  const nested=h.volume("nested");
  const mounts=["--mount","type=volume,src="+nested+",dst=/data/oauth-proxy/nested"];
  const relation=h.transient(boundary,"import os;print(os.stat('/data/oauth-proxy').st_dev==os.stat('/data/oauth-proxy/nested').st_dev)",{mounts});
  assert.equal(relation,"True");
  expectRefusal(h,boundary,operation(helperHash),"mount-unqualified",mounts);
  result.sameDeviceNestedMount="refused";

  // The crash fixture includes a real factory-created encrypted DCR record
  // plus 480 harmless metadata stress records to widen the interruption window.
  const crash=h.volume("crash");setup(h,crash,480);
  const baseline=start(h,crash,"crash-baseline","root-compat");
  await ready(h,baseline,0);
  const factory=(name,label)=>JSON.parse(h.call(["exec","--user","0:0","--workdir","/app",
    "--env","CONTENT_STORAGE_SYNTHETIC_REHEARSAL=1","--env","CONTENT_PACKAGED_EXPECTED_UID=0",
    name,"/app/.venv/bin/python","-B","-c",probe,label]).stdout);
  const seed=factory(baseline,"root-baseline");
  assert.equal(stop(h,baseline),0);
  const crashBefore=snapshot(h,crash), crashOp=operation(helperHash);
  const candidate=start(h,crash,"crash","migration",crashOp);
  let mixed=false;
  const end=Date.now()+30000;
  while(Date.now()<end) {
    if(!state(h,candidate).Running) break;
    // Read-only observer in a separate PID namespace, never a competing writer.
    const current=snapshot(h,crash);
    if(current.owners.includes(0) && current.owners.includes(1000) &&
       current.journalStates.includes("pending")) {mixed=true;break;}
    if(current.journalStates.includes("serving")) break;
    await delay(50);
  }
  assert.ok(mixed,"SIGKILL-window-not-observed");
  assert.equal(stop(h,candidate,"KILL"),137);
  const killed=snapshot(h,crash);
  assert.equal(killed.recordsSha256,crashBefore.recordsSha256);
  assert.deepEqual(killed.owners,[0,1000]);
  assert.deepEqual(killed.journalStates,["pending"]);
  expectRefusal(h,crash,crashOp,"incomplete-journal");
  assert.deepEqual(snapshot(h,crash),killed);
  expectRefusal(h,crash,operation(helperHash),"incomplete-journal");
  assert.deepEqual(snapshot(h,crash),killed);
  const fallback=start(h,crash,"crash-fallback","root-compat");
  const http=await ready(h,fallback,0), process=processBoundary(h,fallback,0);
  const storage=factory(fallback,"migration");
  assert.equal(storage.beforeSha256,seed.afterSha256);
  assert.equal(stop(h,fallback),0);
  const recovered=snapshot(h,crash);
  assert.equal(recovered.journalSha256,killed.journalSha256);
  assert.deepEqual(recovered.journalStates,["pending"]);
  result.interruptedFallback={signal:"SIGKILL",mixedOwnershipObserved:true,
    originalBytesPreserved:true,pendingReplayRejected:true,freshOperationBlocked:true,
    pendingJournalUnchanged:true,http,process,storage};
  return result;
}

export async function rehearse(runtime,migration,{context="desktop-linux"}={}) {
  // Read-only preflight; no fixtures may be created before local endpoint validation.
  selectDockerContext(context);
  const h=new Harness(runtime,migration,(args,options)=>dockerTransport(args,{...options,context}));
  const receipt={runtimeLocalImageId:runtime,migrationLocalImageId:migration,published:false,
    network:"none",googleAccess:false,boundary:"PID1-HTTP-and-separate-synthetic-provider-not-live-OAuth",stages:[]};
  const began=Date.now();
  try {
    const images=[BASE,runtime,migration].map(i=>JSON.parse(h.call(["image","inspect",i]).stdout)[0]);
    assert.equal(images[0].Id,BASE);
    for(let i=1;i<3;i++) {
      assert.deepEqual(images[i].RootFS.Layers.slice(0,-1),images[i-1].RootFS.Layers);
      assert.equal(images[i].Config.User,"1000:1000");
      assert.equal(images[i].Architecture,"amd64");
      assert.deepEqual(images[i].Config.Entrypoint,[PY,"-I","-S",LAUNCHER]);
      assert.deepEqual(images[i].Config.Cmd,["run"]);
    }
    // Image-code bytes only. R must not contain the metadata engine.
    receipt.launcherSha256=h.transient(null,"import hashlib,pathlib\np=pathlib.Path('"+LAUNCHER+"');assert p.stat().st_uid==0 and not p.stat().st_mode&0o022;assert not pathlib.Path('"+HELPER+"').exists();print(hashlib.sha256(p.read_bytes()).hexdigest())");
    receipt.helperSha256=h.transient(null,"import hashlib,pathlib\np=pathlib.Path('"+HELPER+"');assert p.stat().st_uid==0 and not p.stat().st_mode&0o022;print(hashlib.sha256(p.read_bytes()).hexdigest())",{image:migration});
    const volume=h.volume("storage");setup(h,volume);
    const probe=readFileSync(new URL("./packaged_storage_probe.py",import.meta.url),"utf8");
    let op, previous;
    for(const [label,mode,uid] of [
      ["root-baseline","root-compat",0],["migration","migration",1000],
      ["completed-restart","migration",1000],["nonroot-final","run",1000],
      ["final-replacement","run",1000],["root-fallback","root-compat",0],
      ["fresh-migration","migration",1000],["final-return","run",1000],
    ]) {
      if(label==="migration") op=operation(receipt.helperSha256,25);
      if(label==="completed-restart") {
        // Short synthetic expiry; serving app was already stopped normally.
        while(Date.now()<=op.mutate_until*1000) await delay(250);
      }
      if(label==="fresh-migration") {
        const before=snapshot(h,volume);
        expectRefusal(h,volume,op,"metadata-drift");
        assert.deepEqual(snapshot(h,volume),before);
        op=operation(receipt.helperSha256);
      }
      const beforeMigration=mode==="migration"?snapshot(h,volume):null;
      const name=start(h,volume,label,mode,op);
      const http=await ready(h,name,uid), process=processBoundary(h,name,uid);
      if(beforeMigration) assert.equal(snapshot(h,volume).recordsSha256,beforeMigration.recordsSha256);
      const observation=JSON.parse(h.call(["exec","--user",uid+":"+uid,"--workdir","/app",
        "--env","CONTENT_STORAGE_SYNTHETIC_REHEARSAL=1","--env","CONTENT_PACKAGED_EXPECTED_UID="+uid,
        name,"/app/.venv/bin/python","-B","-c",probe,label]).stdout);
      if(previous) assert.equal(observation.beforeSha256,previous.afterSha256,"encrypted-record-drift");
      previous=observation;
      if(label==="migration") {
        while(Date.now()<=op.mutate_until*1000) await delay(250);
        assert.deepEqual(await ready(h,name,uid),{health:200,mcp:401});
        receipt.servingSurvivesMutationExpiry=true;
      }
      if(label==="final-return") {
        const negative=JSON.parse(h.call(["exec","--user","1000:1000","--workdir","/app",
          "--env","CONTENT_STORAGE_SYNTHETIC_REHEARSAL=1","--env","CONTENT_PACKAGED_EXPECTED_UID=1000",
          name,"/app/.venv/bin/python","-B","-c",probe,"wrong-key"]).stdout);
        assert.equal(negative.wrongKeyRejected,true);receipt.wrongKeyRejected=true;
      }
      const signalExit=stop(h,name);assert.equal(signalExit,0);
      receipt.stages.push({label,http,process,storage:observation,signalExit});
    }
    receipt.finalSnapshot=snapshot(h,volume);
    receipt.faults=await faults(h,receipt.helperSha256,probe);
    receipt.elapsedMs=Date.now()-began;
  } catch(error) {
    receipt.failed=true;
    // Error messages from assertions could include fixture fields: classify only.
    receipt.failureClass=error instanceof assert.AssertionError ? "assertion-failed" : error.message;
    receipt.failureLocation=error.stack?.match(/rehearse_packaged_pair\.mjs:(\d+:\d+)/)?.[1] ?? "unavailable";
    throw Object.assign(new Error("packaged-rehearsal-failed"),{receipt});
  } finally {
    h.finish(receipt);
  }
  return receipt;
}

if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  if(process.argv.length!==6 || process.argv[2]!=="--docker-context") {console.error("two-exact-local-image-IDs-required");process.exitCode=1;}
  else rehearse(process.argv[4],process.argv[5],{context:process.argv[3]}).then(r=>console.log(JSON.stringify(r,null,2))).catch(e=>{
    console.error(JSON.stringify(e.receipt??{failed:true,failureClass:"invalid-rehearsal-input"},null,2));
    process.exitCode=1;
  });
}
