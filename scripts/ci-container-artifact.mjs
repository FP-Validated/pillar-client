import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createReadStream } from "node:fs";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";

const [action, requestedDirectory] = process.argv.slice(2);
if (!requestedDirectory || !["prepare", "finalize", "report"].includes(action)) {
  throw new Error("usage: ci-container-artifact.mjs prepare|finalize|report ARTIFACT_DIR");
}
const directory = resolve(requestedDirectory);
const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();
const timestamp = () => {
  const now = new Date();
  const kst = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Asia/Seoul",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }).format(now);
  return { utc: now.toISOString(), kst: `${kst} KST` };
};
const workflowSource = () => ({
  workflowCommit: process.env.GITHUB_SHA ?? "",
  checkedOutHead: git("rev-parse", "HEAD"),
  checkedOutTree: git("rev-parse", "HEAD^{tree}"),
  pullRequestHead: process.env.GITHUB_PR_HEAD_SHA || null,
  pullRequestBase: process.env.GITHUB_PR_BASE_SHA || null,
  ref: process.env.GITHUB_REF ?? "",
  event: process.env.GITHUB_EVENT_NAME ?? "",
  runId: process.env.GITHUB_RUN_ID ?? "",
  runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? "",
  gitStatus: git("status", "--short", "--branch"),
  dirtyPaths: git("status", "--porcelain=v1", "--untracked-files=all").split("\n").filter(Boolean),
});
const readJson = async (path) => readFile(path, "utf8").then(JSON.parse).catch(() => null);
const readText = async (path) => readFile(path, "utf8").then((text) => text.trim()).catch(() => null);

if (action === "prepare") {
  await mkdir(directory, { recursive: true });
  const source = workflowSource();
  const preparedAt = timestamp();
  await writeFile(join(directory, "source-identity.json"), JSON.stringify({ source, preparedAt }, null, 2) + "\n");
  await writeFile(join(directory, "source-identity.txt"), [
    "# CI source identity",
    `preparedAtUtc=${preparedAt.utc}`,
    `preparedAtKst=${preparedAt.kst}`,
    `workflowCommit=${source.workflowCommit}`,
    `checkedOutHead=${source.checkedOutHead}`,
    `checkedOutTree=${source.checkedOutTree}`,
    `pullRequestHead=${source.pullRequestHead ?? ""}`,
    `pullRequestBase=${source.pullRequestBase ?? ""}`,
    `ref=${source.ref}`,
    `event=${source.event}`,
    `runId=${source.runId}`,
    `runAttempt=${source.runAttempt}`,
    `gitStatus=${source.gitStatus}`,
    `dirtyPaths=${source.dirtyPaths.length}`,
    ...source.dirtyPaths.map((path) => `dirtyPath=${path}`),
    "",
  ].join("\n"));
  if (source.dirtyPaths.length) throw new Error(`refusing image source claim from dirty checkout (${source.dirtyPaths.length} tracked/untracked paths)`);
} else if (action === "finalize") {
  const [rawInspect, sourceRecord] = await Promise.all([
    readFile(join(directory, "image-inspect.json"), "utf8").then(JSON.parse),
    readFile(join(directory, "source-identity.json"), "utf8").then(JSON.parse),
  ]);
  const image = rawInspect[0];
  const sourceAfter = workflowSource();
  if (JSON.stringify(sourceAfter) !== JSON.stringify(sourceRecord.source)) {
    throw new Error("checkout identity changed between artifact preparation and image save");
  }
  const labels = image?.Config?.Labels ?? {};
  const sourceRevision = labels["org.opencontainers.image.revision"] ?? null;
  if (sourceRevision !== sourceRecord.source.workflowCommit) {
    throw new Error(`image revision ${sourceRevision} does not match workflow SHA ${sourceRecord.source.workflowCommit}`);
  }
  if (!image?.Id || !image?.Os || !image?.Architecture) throw new Error("image inspect is missing ID or platform");
  const imageTar = join(directory, "pillar-client-ci.tar");
  const tarStats = await stat(imageTar);
  if (tarStats.size <= 0) throw new Error("saved image tar is empty");
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(imageTar)) hash.update(chunk);
  const metadata = {
    candidateTag: "pillar-client:ci",
    imageId: image.Id,
    platform: { os: image.Os, architecture: image.Architecture, variant: image.Variant ?? null },
    sourceRevision,
    labels,
    source: sourceRecord.source,
    sourcePreparedAt: sourceRecord.preparedAt,
    imageFinalizedAt: timestamp(),
    tar: { file: "pillar-client-ci.tar", sha256: hash.digest("hex"), bytes: tarStats.size },
    registryPush: false,
    deployment: false,
  };
  await writeFile(join(directory, "image-metadata.json"), JSON.stringify(metadata, null, 2) + "\n");
} else {
  const reportGeneratedAt = timestamp();
  const [sourceRecord, image, buildStatus, saveStatus, preflight, buildFinishedAt, saveFinishedAt, preflightFinishedAt] = await Promise.all([
    readJson(join(directory, "source-identity.json")),
    readJson(join(directory, "image-metadata.json")),
    readText(join(directory, "docker-build-exit-status.txt")),
    readText(join(directory, "save-identify-exit-status.txt")),
    readJson(join(directory, "container-preflight-result.json")),
    readText(join(directory, "docker-build-finished-at-kst.txt")),
    readText(join(directory, "save-identify-finished-at-kst.txt")),
    readText(join(directory, "container-preflight-finished-at-kst.txt")),
  ]);
  const imageArchive = await stat(join(directory, "pillar-client-ci.tar")).then((file) => file.size > 0).catch(() => false);
  const imageArtifactReady = buildStatus === "0" && saveStatus === "0" && imageArchive && Boolean(image?.imageId && image?.tar?.sha256);
  const preflightPassed = preflight?.stepPassed === true;
  const evidenceStage = preflightFinishedAt ? "container-preflight-finished-at-kst.txt"
    : saveFinishedAt ? "save-identify-finished-at-kst.txt"
      : buildFinishedAt ? "docker-build-finished-at-kst.txt" : "source-identity.json preparedAt";
  const evidenceFinishedAt = preflightFinishedAt ?? saveFinishedAt ?? buildFinishedAt ?? sourceRecord?.preparedAt?.kst ?? null;
  const report = [
    "# 컨테이너 candidate 이미지 증거",
    "",
    `- Container gate 상태: ${imageArtifactReady && preflightPassed ? "PASS" : "FAIL/증거 불완전"}`,
    `- Docker build exit status: ${buildStatus ?? "기록 없음"}`,
    `- Inspect/save/finalize exit status: ${saveStatus ?? "기록 없음"}`,
    `- 설정누락 사전검사: ${preflightPassed ? "expected refusal 확인" : "통과 증거 없음/실패"}`,
    `- Candidate tar 보존: ${imageArchive ? "있음" : "없음"}`,
    ...(image ? [
      `- Candidate tag: ${image.candidateTag}`,
      `- Image ID: ${image.imageId}`,
      `- Platform: ${image.platform.os}/${image.platform.architecture}${image.platform.variant ? `/${image.platform.variant}` : ""}`,
      `- OCI source revision: ${image.sourceRevision}`,
      `- Candidate tar SHA-256: ${image.tar.sha256}`,
      `- Candidate tar bytes: ${image.tar.bytes}`,
      `- Image metadata finalization: ${image.imageFinalizedAt.kst}`,
    ] : []),
    ...(sourceRecord?.source ? [
      `- CI workflow SHA: ${sourceRecord.source.workflowCommit}`,
      `- Checkout HEAD: ${sourceRecord.source.checkedOutHead}`,
      `- Checkout tree: ${sourceRecord.source.checkedOutTree}`,
      `- PR head/base SHA: ${sourceRecord.source.pullRequestHead ?? "없음"} / ${sourceRecord.source.pullRequestBase ?? "없음"}`,
      `- Ref/event/run: ${sourceRecord.source.ref} / ${sourceRecord.source.event} / ${sourceRecord.source.runId}.${sourceRecord.source.runAttempt}`,
      `- Source identity prepare: ${sourceRecord.preparedAt.kst}`,
    ] : []),
    "- Registry push/deployment: 수행하지 않음",
    `- 보고서 생성 시각: ${reportGeneratedAt.kst}`,
    "",
    `근거: ${evidenceStage} · ${evidenceFinishedAt ?? "시각 미상"}`,
    "",
  ].join("\n");
  await writeFile(join(directory, "image-report-generated-at.json"), JSON.stringify(reportGeneratedAt, null, 2) + "\n");
  await writeFile(join(directory, "BUILD-REPORT.md"), report);
}
