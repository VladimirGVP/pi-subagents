import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { test } from "node:test";
import {
	inspectResources,
	parseResourceInspectionArgs,
	ResourceInspectionError,
} from "../../src/api/resource-inspection.ts";
import { discoverAgentSnapshot } from "../../src/agents/agents.ts";

const tempRoot =
	process.env.PI_SUBAGENTS_TEMP_ROOT ?? path.resolve(".pi/tmp/T12/worker");
fs.mkdirSync(tempRoot, { recursive: true });
const write = (file: string, content: string) => {
	fs.mkdirSync(path.dirname(file), { recursive: true });
	fs.writeFileSync(file, content);
};

test("resource-inspection arguments are exact, bounded and nonduplicated", () => {
	const valid = [
		"--cwd",
		"/project",
		"--agent-dir",
		"/config",
		"--project-trust",
		"trusted",
	];
	assert.deepEqual(parseResourceInspectionArgs(valid), {
		cwd: "/project",
		agentDir: "/config",
		projectTrust: "trusted",
	});
	for (const invalid of [
		[],
		[...valid, "--help"],
		["--cwd", "x", "--cwd", "y", "--project-trust", "trusted"],
		["--secret", "x", ...valid.slice(2)],
		["--cwd", "", ...valid.slice(2)],
		[...valid.slice(0, 5), "maybe"],
		["--cwd", "x".repeat(4097), ...valid.slice(2)],
	]) {
		assert.throws(
			() => parseResourceInspectionArgs(invalid),
			(error) =>
				error instanceof ResourceInspectionError &&
				error.code === "invalid_arguments",
		);
	}
});

test("resource-inspection API refuses ambient live state without changing environment", async () => {
	const before = { ...process.env };
	await assert.rejects(
		inspectResources({ cwd: "/", agentDir: "/", projectTrust: "trusted" }),
		ResourceInspectionError,
	);
	assert.deepEqual({ ...process.env }, before);
});

test("discoverAgentSnapshot opt-in retains same-source losers without changing default projection", () => {
	const root = fs.mkdtempSync(path.join(tempRoot, "snapshot-"));
	const previous = {
		HOME: process.env.HOME,
		PI_CODING_AGENT_DIR: process.env.PI_CODING_AGENT_DIR,
		PI_OFFLINE: process.env.PI_OFFLINE,
	};
	try {
		const cwd = path.join(root, "project");
		const agentDir = path.join(root, "config");
		process.env.HOME = path.join(root, "home");
		process.env.PI_CODING_AGENT_DIR = agentDir;
		process.env.PI_OFFLINE = "1";
		write(path.join(agentDir, "settings.json"), "{}");
		const packages = ["one", "two"].map((name) => path.join(root, name));
		write(path.join(cwd, ".pi/settings.json"), JSON.stringify({ packages }));
		for (const pkg of packages) {
			write(
				path.join(pkg, "package.json"),
				JSON.stringify({
					name: path.basename(pkg),
					"pi-subagents": { agents: ["agents"] },
				}),
			);
			write(
				path.join(pkg, "agents/collision.md"),
				"---\nname: collision\ndescription: fixture\n---\nSECRET",
			);
		}
		for (const dir of [".agents", ".pi/agents"])
			write(
				path.join(cwd, dir, "collision.md"),
				"---\nname: collision\ndescription: fixture\n---\nSECRET",
			);
		const normal = discoverAgentSnapshot(cwd, "both", undefined, {
			includeChains: false,
		});
		const inspected = discoverAgentSnapshot(cwd, "both", undefined, {
			includeChains: false,
			includeCandidateMetadata: true,
		});
		assert.equal(Object.hasOwn(normal, "candidates"), false);
		assert.deepEqual(inspected.effective, normal.effective);
		assert.deepEqual(inspected.all, normal.all);
		assert.equal(
			inspected.candidates?.filter((candidate) => candidate.name === "collision")
				.length,
			4,
		);
		assert.equal(
			normal.all.package.filter((agent) => agent.name === "collision").length,
			1,
		);
		assert.equal(
			normal.all.project.filter((agent) => agent.name === "collision").length,
			1,
		);
		assert.equal(
			normal.effective.agents.find((agent) => agent.name === "collision")
				?.filePath,
			path.join(cwd, ".pi/agents/collision.md"),
		);
		assert.ok(!JSON.stringify(inspected.candidates).includes("SECRET"));
	} finally {
		for (const [key, value] of Object.entries(previous)) {
			if (value === undefined) delete process.env[key];
			else process.env[key] = value;
		}
		fs.rmSync(root, { recursive: true, force: true });
	}
});
