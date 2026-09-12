import assert from "node:assert/strict";
import test from "node:test";
import { Harness, dockerTransport, selectDockerContext } from "./rehearse_packaged_pair.mjs";

const runtime = "sha256:" + "1".repeat(64), migration = "sha256:" + "2".repeat(64);
const response = (status=0, stdout="") => ({status, stdout, stderr:""});
test("accepts only exact local config IDs and never probes a mutable reference", () => {
  for (const r of ["latest", "ghcr.io/a/b:tag", null, runtime+"x"])
    assert.throws(() => new Harness(r, migration, () => assert.fail("no Docker")));
  assert.throws(() => new Harness(runtime, runtime, () => assert.fail("no Docker")));
});
test("registers uncertain creates before invoking Docker and reconciles cleanup", () => {
  let h, registered;
  h = new Harness(runtime, migration, args => {
    if (args[0] === "volume" && args[1] === "create") {
      registered = args[2];
      assert.ok(h.volumes.has(registered));
      throw new Error("uncertain-create");
    }
    return response();
  });
  assert.throws(() => h.volume("test"), /uncertain-create/);
  assert.equal(h.cleanup().verifiedAbsent, true);
  assert.ok(registered);
});
test("failed queries are unknown, successful exact presence is not absence", () => {
  for (const state of ["unknown", "present", "absent"]) {
    const h = new Harness(runtime, migration, args => {
      if (args.includes("ls")) return state === "unknown" ? response(1) :
        response(0, state === "present" ? [...h.containers][0]+"\n" : "");
      return response(1);
    });
    h.container("test");
    const result = h.cleanup();
    assert.equal(result.containerAbsence[state], 1);
    assert.equal(result.verifiedAbsent, state === "absent");
  }
});
test("work expiry stops new calls but cleanup gets an independent bounded budget", () => {
  let now = 1000, removals = 0;
  const h = new Harness(runtime, migration, (args, options) => {
    assert.ok(options.timeout > 0 && options.timeout <= 10000);
    if (args[0] === "rm") removals++;
    return response();
  }, () => now);
  h.container("test"); h.deadline = now - 1;
  assert.throws(() => h.call(["run"]), /work-deadline/);
  assert.equal(h.cleanup().verifiedAbsent, true);
  assert.equal(removals, 1);
});
test("unsafe names and resource explosion fail before mutation", () => {
  const h = new Harness(runtime, migration, () => response());
  assert.throws(() => h.container("../outside"));
  for (let i=0; i<128; i++) h.container("test");
  assert.throws(() => h.container("test"));
});
test("Docker timeouts use a hard kill, not an ignorable termination signal", () => {
  dockerTransport(["inspect","synthetic"],{timeout:30},(command,args,options)=>{
    assert.equal(command,"docker");
    assert.equal(options.timeout,30);
    assert.equal(options.killSignal,"SIGKILL");
    return response();
  });
});
test("cleanup-only failure retains its complete receipt and resource ledger", () => {
  const h=new Harness(runtime,migration,()=>response(1));
  h.container("test");
  const receipt={published:false};
  assert.throws(()=>h.finish(receipt),error=>{
    assert.equal(error.receipt,receipt);
    assert.equal(error.receipt.cleanup.containerAbsence.unknown,1);
    assert.equal(error.receipt.cleanup.ledger.containers.length,1);
    return true;
  });
});

test("CI transport explicitly selects default and rejects overrides", () => {
  dockerTransport(["image","inspect",runtime],{timeout:5000,context:"default"},(cmd,args,opts)=>{
    assert.deepEqual(args.slice(0,2),["--context","default"]);
    assert.equal(opts.timeout,5000);return response();
  });
  assert.throws(()=>dockerTransport([],{timeout:10,context:"--host=x"},()=>assert.fail("unexpected call")));
});

test("preflight checks the selected local Unix endpoint before Docker info", () => {
  const seen=[];
  assert.equal(selectDockerContext("default",(cmd,args,opts)=>{
    seen.push(args);assert.equal(opts.timeout,15000);
    return response(0,args[0]==="context"?'"unix:///var/run/docker.sock"':"linux/x86_64\n");
  }),"default");
  assert.deepEqual(seen[1],["--context","default","info","--format","{{.OSType}}/{{.Architecture}}"]);
  for(const endpoint of ['"tcp://remote:2375"','"ssh://remote"','"unix://relative"','"unix:///tmp/unsafe socket"',"bad-json"])
    assert.throws(()=>selectDockerContext("default",(cmd,args)=>{
      assert.equal(args[0],"context");return response(0,endpoint);
    }));
});

test("environment overrides fail before context inspection", () => {
  for(const key of ["DOCKER_HOST","DOCKER_CONTEXT"]) {
    const saved=process.env[key];process.env[key]="remote";
    try {assert.throws(()=>selectDockerContext("default",()=>assert.fail("unexpected call")),/implicit-docker-override/);}
    finally {if(saved===undefined) delete process.env[key]; else process.env[key]=saved;}
  }
});
