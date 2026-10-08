import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [directory, rawStatus] = process.argv.slice(2);
if (!directory || rawStatus === undefined) throw new Error("usage: ci-ton-release-summary.mjs ARTIFACT_DIR EXIT_STATUS");
const status = Number(rawStatus);
const stdout = await readFile(join(directory, "cargo.stdout"), "utf8").catch(() => "");
const command = (await readFile(join(directory, "command.txt"), "utf8").catch(() => "")).trim();
const startedAtKst = (await readFile(join(directory, "started-at-kst.txt"), "utf8").catch(() => "")).trim() || null;
const finishedAtKst = (await readFile(join(directory, "finished-at-kst.txt"), "utf8").catch(() => "")).trim() || null;
const target = "tests::transport_wire_tests::ton_depth_limit_and_trace_traversal_are_worker_safe_over_http";
const targetLines = stdout.split("\n").filter((line) => line.includes(`test ${target} ... ok`)).length;
const passSummaries = [...stdout.matchAll(/test result: ok\. 1 passed; 0 failed/g)].length;
const resourcePrefix = "ton-child-resource-evidence: ";
const resourceLine = stdout.split("\n").find((line) => line.includes(resourcePrefix));
let childResource;
try { childResource = JSON.parse(resourceLine.slice(resourceLine.indexOf(resourcePrefix) + resourcePrefix.length)); } catch {}
const missing = [];
if (status !== 0) missing.push(`cargo test exit status ${status}`);
if (!startedAtKst || !finishedAtKst) missing.push("gate start/end KST timestamps were not recorded");
if (targetLines < 2) missing.push(`expected top-level and isolated child target output; observed ${targetLines}`);
if (passSummaries < 2) missing.push(`expected both top-level and isolated child 1-passed summaries; observed ${passSummaries}`);
if (!childResource) missing.push("isolated child resource evidence was absent or unreadable");
if (childResource && childResource.rss_within_budget !== true) missing.push("isolated child exceeded its recorded RSS budget");
if (childResource && childResource.rss_budget_bytes !== 512 * 1024 * 1024) missing.push("isolated child RSS budget did not equal 512 MiB");
if (childResource && childResource.resource_source !== "/usr/bin/time -l (bytes)") missing.push("child RSS was not measured by macOS /usr/bin/time -l");
const summary = {
  status: missing.length === 0 ? "pass" : "fail",
  command,
  exitStatus: status,
  startedAtKst,
  finishedAtKst,
  sourceIdentityFile: "source-identity.txt",
  targetTest: target,
  topLevelPassed: status === 0 && targetLines >= 2 ? 1 : 0,
  isolatedChildPassed: status === 0 && targetLines >= 2 && passSummaries >= 2 ? 1 : 0,
  exactTargetOutputOccurrences: targetLines,
  onePassedSummaryOccurrences: passSummaries,
  childResourceEvidence: childResource ?? null,
  resourceAccounting: {
    outerTimeCommand: "/usr/bin/time -l cargo test ...",
    outerRawResourceLog: "cargo.stderr",
    childResourceSource: childResource?.resource_source ?? null,
    osRssLimitEnforced: childResource?.rss_limit_enforced_by_os ?? null,
  },
  missingSignals: missing,
  classification: "targeted macOS release lifecycle test only; no full-suite duplication",
};
const report = [
  "# macOS TON release lifecycle gate",
  "",
  `- 결과: ${summary.status === "pass" ? "PASS" : "FAIL"}`,
  `- 실행: \`${command}\``,
  `- Cargo exit status: ${status}`,
  `- 상위 정확 target test: ${summary.topLevelPassed} passed`,
  `- isolated child 정확 target: ${summary.isolatedChildPassed} passed (상위의 child-status assertion 및 원본 stdout 기준)`,
  `- 정확 target 출력 횟수: ${targetLines}`,
  `- 1 passed summary 관측 횟수: ${passSummaries}`,
  `- Child RSS evidence: ${childResource ? `${childResource.peak_rss_bytes} bytes / ${childResource.rss_budget_bytes} bytes; OS hard limit=${childResource.rss_limit_enforced_by_os}` : "없음"}`,
  "- /usr/bin/time -l 원본: cargo.stderr",
  "- 실행 stdout 원본: cargo.stdout",
  "- Source identity: source-identity.txt",
  "- 범위: 이 targeted lifecycle test만 실행; full suite는 반복하지 않음",
  "",
  `- 근거: finished-at-kst.txt · ${finishedAtKst ?? "시각 증거 없음"}`,
  "",
  ...(missing.length ? ["## 미충족", "", ...missing.map((item) => `- ${item}`), ""] : []),
].join("\n");
await writeFile(join(directory, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
await writeFile(join(directory, "CI-REPORT.md"), report);
console.log(JSON.stringify(summary, null, 2));
if (missing.length) process.exitCode = 1;
