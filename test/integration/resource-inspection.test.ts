import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { test } from "node:test";

const cwd = process.cwd();
const tempRoot =
	process.env.PI_SUBAGENTS_TEMP_ROOT ?? path.resolve(".pi/tmp/T12/worker");
fs.mkdirSync(tempRoot, { recursive: true });
const sdkRoot =
	process.env.PI_SUBAGENTS_PI_CODING_AGENT_PACKAGE_ROOT ??
	path.resolve(
		path.dirname(process.execPath),
		"../lib/node_modules/@earendil-works/pi-coding-agent",
	);
const hasSdk = fs.existsSync(
	path.join(sdkRoot, "dist/core/package-manager.js"),
);
const write = (file: string, content: string) => {
	fs.mkdirSync(path.dirname(file), { recursive: true });
	fs.writeFileSync(file, content);
};
type FixtureJson =
	| string
	| number
	| boolean
	| null
	| FixtureJson[]
	| { [key: string]: FixtureJson };
const json = (file: string, value: FixtureJson) =>
	write(file, JSON.stringify(value));
const agent = (name: string) =>
	`---\nname: ${name}\ndescription: fixture\n---\nPRIVATE_PROMPT_SENTINEL`;
const skill =
	"---\nname: shared-skill\ndescription: fixture\n---\nPRIVATE_SKILL_SENTINEL";
const brainstormingSkill =
	"---\nname: brainstorming\ndescription: fixture\n---\nPRIVATE_SKILL_SENTINEL";
const mebibyte = 1024 * 1024;

function writeSizedFile(file: string, size: number) {
	write(file, "x".repeat(size));
	assert.equal(fs.lstatSync(file).size, size);
}

function fixture() {
	const root = fs.mkdtempSync(path.join(tempRoot, "inspector-"));
	const project = path.join(root, "project");
	const config = path.join(root, "config");
	const home = path.join(root, "home");
	const candidate = path.join(root, "workbench");
	const commit = "a".repeat(40);
	const managedSource = `git:https://github.com/acme/managed-fixture@${commit}`;
	const manifestlessSource = `git:https://github.com/acme/manifestless-fixture@${commit}`;
	const managed = path.join(config, "git/github.com/acme/managed-fixture");
	const manifestless = path.join(
		config,
		"git/github.com/acme/manifestless-fixture",
	);
	fs.mkdirSync(home, { recursive: true });
	fs.mkdirSync(path.join(project, ".git"), { recursive: true });
	json(path.join(config, "settings.json"), {
		packages: [managedSource, manifestlessSource],
	});
	json(path.join(project, ".pi/settings.json"), { packages: [candidate] });
	for (const pkg of [candidate, managed]) {
		json(path.join(pkg, "package.json"), {
			name: path.basename(pkg),
			version: "1.0.0",
			pi: { skills: ["skills"], extensions: ["extension.mjs"] },
			"pi-subagents": { agents: ["agents"] },
		});
		for (const name of ["dogfood", "codex-image", "techlead"])
			write(path.join(pkg, "agents", `${name}.md`), agent(name));
		write(path.join(pkg, "skills/shared-skill/SKILL.md"), skill);
		write(
			path.join(pkg, "extension.mjs"),
			"throw new Error('EXTENSION_EXECUTED_SENTINEL');",
		);
	}
	write(
		path.join(manifestless, "skills/brainstorming/SKILL.md"),
		brainstormingSkill,
	);
	for (const name of ["dogfood", "codex-image", "techlead"]) {
		write(path.join(project, ".pi/agents", `${name}.md`), agent(name));
		write(path.join(project, ".agents", `${name}.md`), agent(name));
	}
	write(path.join(project, "AGENTS.md"), "PRIVATE_CONTEXT_SENTINEL");
	write(path.join(config, "AGENTS.md"), "PRIVATE_GLOBAL_CONTEXT_SENTINEL");
	// A valid-but-secret file exists; inspection must not even read it.
	write(path.join(config, "auth.json"), "PRIVATE_CREDENTIAL_SENTINEL");
	const guard = path.join(root, "guard.mjs");
	write(
		guard,
		`import fs from 'node:fs'; import cp from 'node:child_process'; import net from 'node:net'; import http from 'node:http'; import https from 'node:https'; import {syncBuiltinESMExports} from 'node:module';
const attempts=[]; const deny=(kind)=>(...args)=>{attempts.push(kind);throw Error('FORBIDDEN_'+kind)};
for(const key of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[key]=deny('child');
for(const key of ['writeFileSync','writeFile','appendFileSync','appendFile','mkdirSync','mkdir','unlinkSync','unlink','renameSync','rename','rmSync','rm'])fs[key]=deny('write');
for(const key of ['writeFile','appendFile','mkdir','unlink','rename','rm'])fs.promises[key]=deny('write');
net.connect=deny('network');net.createConnection=deny('network');net.Socket.prototype.connect=deny('network');http.request=deny('network');http.get=deny('network');https.request=deny('network');https.get=deny('network');globalThis.fetch=deny('network');
const read=fs.readFileSync;fs.readFileSync=function(file,...rest){if(String(file).endsWith('/auth.json'))return deny('auth')();return read.call(this,file,...rest)};
syncBuiltinESMExports();process.on('exit',()=>process.stderr.write('GUARD:'+JSON.stringify(attempts)+'\\n'));
`,
	);
	return {
		root,
		project,
		config,
		home,
		candidate,
		managed,
		manifestless,
		managedSource,
		guard,
	};
}

function run(
	f: ReturnType<typeof fixture>,
	args?: string[],
	overrides?: Record<string, string>,
) {
	return spawnSync(
		process.execPath,
		[
			"--import",
			f.guard,
			path.join(cwd, "resource-inspector.mjs"),
			...(args ?? [
				"--cwd",
				f.project,
				"--agent-dir",
				f.config,
				"--project-trust",
				"trusted",
			]),
		],
		{
			cwd,
			env: {
				...process.env,
				HOME: f.home,
				USERPROFILE: f.home,
				PI_SUBAGENT_EXTRA_AGENT_DIRS: "",
				PI_SUBAGENTS_PI_CODING_AGENT_PACKAGE_ROOT: sdkRoot,
				NODE_OPTIONS: "",
				...overrides,
			},
			encoding: "utf8",
			timeout: 15000,
			killSignal: "SIGKILL",
			maxBuffer: 2 * 1024 * 1024,
		},
	);
}

function unmanagedSdk(f: ReturnType<typeof fixture>): string {
	const root = path.join(f.root, "unmanaged-sdk");
	const sdkEntry = pathToFileURL(path.join(sdkRoot, "dist/index.js")).href;
	write(
		path.join(root, "dist/index.js"),
		`import * as sdk from ${JSON.stringify(sdkEntry)};
export * from ${JSON.stringify(sdkEntry)};
export class DefaultPackageManager extends sdk.DefaultPackageManager {
	getInstalledPath(source, scope) {
		return source.includes("unmanaged-fixture")
			? process.env.INSPECTOR_UNMANAGED_PATH
			: super.getInstalledPath(source, scope);
	}
}`,
	);
	return root;
}

function errorCode(stderr: string): string {
	return JSON.parse(stderr.split("\n", 1)[0]!).error;
}

function snapshot(root: string): string[] {
	const result: string[] = [];
	function visit(dir: string) {
		for (const name of fs.readdirSync(dir).sort()) {
			const file = path.join(dir, name);
			const stat = fs.lstatSync(file);
			result.push(
				`${path.relative(root, file)}:${stat.mode}:${stat.mtimeMs}:${stat.size}`,
			);
			if (stat.isDirectory()) visit(file);
			else if (stat.isFile())
				result.push(
					createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
				);
		}
	}
	visit(root);
	return result;
}

function freeze(root: string, frozen: boolean) {
	for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
		const file = path.join(root, entry.name);
		if (entry.isDirectory()) freeze(file, frozen);
		if (!entry.isSymbolicLink())
			fs.chmodSync(
				file,
				frozen
					? entry.isDirectory()
						? 0o555
						: 0o444
					: entry.isDirectory()
						? 0o755
						: 0o644,
			);
	}
	fs.chmodSync(root, frozen ? 0o555 : 0o755);
}

test("resource-inspection CLI composes real managed/local packages, retains collisions and never executes or mutates", {
	skip:
		!hasSdk &&
		"Real Pi SDK unavailable; set PI_SUBAGENTS_PI_CODING_AGENT_PACKAGE_ROOT",
}, () => {
	const f = fixture();
	try {
		writeSizedFile(
			path.join(f.candidate, "skills", "real-size-sidecar.bin"),
			1_100_013,
		);
		writeSizedFile(
			path.join(f.candidate, "skills", "two-mebibyte-sidecar.bin"),
			2 * mebibyte,
		);
		freeze(f.root, true);
		const before = snapshot(f.root);
		const result = run(f);
		assert.equal(result.error, undefined);
		assert.equal(result.status, 0, result.stderr);
		assert.equal(result.stderr, "GUARD:[]\n");
		const output = JSON.parse(result.stdout);
		assert.equal(output.mode, "config_effective");
		assert.equal(output.cwd, fs.realpathSync(f.project));
		assert.equal(
			output.settingsPaths.global,
			path.join(f.config, "settings.json"),
		);
		assert.equal(
			output.settingsPaths.project,
			path.join(f.project, ".pi/settings.json"),
		);
		assert.equal(output.agents.runtimeRegistry, "host_required");
		assert.equal(output.agents.sessionCapabilityCeiling, "host_required");
		for (const name of ["dogfood", "codex-image", "techlead"]) {
			const winner = path.join(f.project, ".pi/agents", `${name}.md`);
			assert.equal(
				output.agents.effective.find(
					(agent: { name: string }) => agent.name === name,
				).filePath,
				winner,
			);
			const candidates = output.agents.candidates.filter(
				(agent: { name: string }) => agent.name === name,
			);
			assert.equal(candidates.length, 4);
			assert.ok(
				candidates.every(
					(agent: { winnerPath: string }) => agent.winnerPath === winner,
				),
			);
			assert.ok(
				candidates.some(
					(agent: { filePath: string }) =>
						agent.filePath === path.join(f.candidate, "agents", `${name}.md`),
				),
			);
		}
		assert.equal(
			output.skills.effective[0].filePath,
			path.join(f.candidate, "skills/shared-skill/SKILL.md"),
		);
		assert.equal(
			output.skills.diagnostics[0].collision.loserPath,
			path.join(f.managed, "skills/shared-skill/SKILL.md"),
		);
		assert.ok(
			output.skills.effective.some(
				(skill: { filePath: string }) =>
					skill.filePath ===
					path.join(f.manifestless, "skills/brainstorming/SKILL.md"),
			),
		);
		assert.ok(
			output.projectContextPaths.includes(path.join(f.project, "AGENTS.md")),
		);
		assert.ok(
			output.projectContextPaths.every((entry: string) => path.isAbsolute(entry)),
		);
		assert.ok(
			!/PRIVATE_|EXTENSION_EXECUTED|systemPrompt|description/.test(result.stdout),
		);
		assert.deepEqual(snapshot(f.root), before);
	} finally {
		freeze(f.root, false);
		fs.rmSync(f.root, { recursive: true, force: true });
	}
});

test("resource-inspection negative CLI fixtures fail closed before child/network/auth or writes", {
	skip: !hasSdk && "Real Pi SDK unavailable",
}, () => {
	const cases: Array<{
		name: string;
		change: (f: ReturnType<typeof fixture>) => void;
		expected?: string;
		runOverrides?: (f: ReturnType<typeof fixture>) => Record<string, string>;
	}> = [
		{
			name: "missing managed npm",
			change: (f) =>
				json(path.join(f.config, "settings.json"), {
					packages: ["npm:missing-fixture"],
				}),
		},
		{
			name: "version mismatch",
			change: (f) =>
				json(path.join(f.config, "settings.json"), {
					packages: ["npm:managed-fixture@2.0.0"],
				}),
		},
		{
			name: "missing pinned git install",
			change: (f) =>
				json(path.join(f.config, "settings.json"), {
					packages: [
						`git:https://github.com/acme/missing-fixture@${"b".repeat(40)}`,
					],
				}),
			expected: "missing_package_source",
		},
		{
			name: "wrong git scope/root",
			change: (f) => {
				const source = `git:https://github.com/acme/project-only@${"c".repeat(40)}`;
				write(path.join(f.project, ".pi/git/github.com/acme/project-only/skills/x/SKILL.md"), skill);
				json(path.join(f.config, "settings.json"), { packages: [source] });
			},
			expected: "missing_package_source",
		},
		{
			name: "unmanaged Git path returned by SDK",
			change: (f) =>
				json(path.join(f.config, "settings.json"), {
					packages: [
						`git:https://github.com/acme/unmanaged-fixture@${"d".repeat(40)}`,
					],
				}),
			expected: "unmanaged_package_source",
			runOverrides: (f) => ({
				PI_SUBAGENTS_PI_CODING_AGENT_PACKAGE_ROOT: unmanagedSdk(f),
				INSPECTOR_UNMANAGED_PATH: f.candidate,
			}),
		},
		{
			name: "symlinked managed Git path",
			change: (f) => {
				const source = `git:https://github.com/acme/symlink-fixture@${"e".repeat(40)}`;
				fs.symlinkSync(
					f.managed,
					path.join(f.config, "git/github.com/acme/symlink-fixture"),
				);
				json(path.join(f.config, "settings.json"), { packages: [source] });
			},
			expected: "symlink_not_supported",
		},
		...[
			"main",
			"v1.0.0",
			"abcdef0",
			undefined,
		].map((ref) => ({
			name: `unsupported Git ref ${ref ?? "missing"}`,
			change: (f: ReturnType<typeof fixture>) =>
				json(path.join(f.config, "settings.json"), {
					packages: [
						`git:https://github.com/acme/managed-fixture${ref ? `@${ref}` : ""}`,
					],
				}),
			expected: "unsupported_package_source",
		})),
		{
			name: "missing local",
			change: (f) =>
				json(path.join(f.config, "settings.json"), {
					packages: [path.join(f.root, "missing")],
				}),
		},
		{
			name: "local package missing manifest",
			change: (f) => fs.rmSync(path.join(f.candidate, "package.json")),
			expected: "missing_resource",
		},
		{
			name: "ordinary node_modules package missing manifest",
			change: (f) =>
				write(
					path.join(
						f.config,
						"npm/node_modules/ordinary-missing-manifest/skills/ordinary/SKILL.md",
					),
					skill,
				),
			expected: "missing_resource",
		},
		{
			name: "scoped node_modules package missing manifest",
			change: (f) =>
				write(
					path.join(
						f.config,
						"npm/node_modules/@scope/scoped-missing-manifest/skills/scoped/SKILL.md",
					),
					skill,
				),
			expected: "missing_resource",
		},
		{
			name: "malformed settings",
			change: (f) =>
				write(path.join(f.config, "settings.json"), "{PRIVATE_ERROR_SENTINEL"),
		},
		{
			name: "malformed settings shape",
			change: (f) => json(path.join(f.config, "settings.json"), { packages: 42 }),
		},
		{
			name: "malformed package",
			change: (f) =>
				write(path.join(f.candidate, "package.json"), "{PRIVATE_ERROR_SENTINEL"),
		},
		{
			name: "malformed trust",
			change: (f) =>
				json(path.join(f.config, "trust.json"), { "/": "PRIVATE_ERROR_SENTINEL" }),
		},
		{
			name: "malformed skill",
			change: (f) =>
				write(
					path.join(f.candidate, "skills/shared-skill/SKILL.md"),
					"---\nname: shared-skill\n---\nPRIVATE_ERROR_SENTINEL",
				),
		},
		{
			name: "malformed agent",
			change: (f) =>
				write(
					path.join(f.candidate, "agents/techlead.md"),
					"---\nname: techlead\ndescription: fixture\nrunner: invalid\n---\nPRIVATE_ERROR_SENTINEL",
				),
		},
		{
			name: "credential path",
			change: (f) =>
				json(path.join(f.config, "settings.json"), {
					skills: [path.join(f.config, "auth.json")],
				}),
		},
		{
			name: "symlink",
			change: (f) =>
				fs.symlinkSync(f.managed, path.join(f.project, ".pi/agents/link")),
		},
		{
			name: "home crawl",
			change: (f) =>
				json(path.join(f.config, "settings.json"), {
					subagents: { agentScanDirs: [f.home] },
				}),
		},
		{
			name: "depth limit",
			change: (f) =>
				write(
					path.join(f.candidate, "agents", ...Array(14).fill("nested"), "deep.md"),
					agent("deep"),
				),
		},
		{
			name: "per-file limit",
			change: (f) =>
				writeSizedFile(
					path.join(f.candidate, "skills", "too-large-sidecar.bin"),
					2 * mebibyte + 1,
				),
			expected: "input_limit",
		},
		{
			name: "aggregate limit",
			change: (f) => {
				for (let index = 0; index < 8; index++)
					writeSizedFile(
						path.join(f.candidate, "skills", `aggregate-sidecar-${index}.bin`),
						2 * mebibyte,
					);
			},
			expected: "input_limit",
		},
	];
	for (const entry of cases) {
		const f = fixture();
		try {
			entry.change(f);
			const overrides = entry.runOverrides?.(f);
			const before = snapshot(f.root);
			const result = run(f, undefined, overrides);
			assert.equal(result.error, undefined, entry.name);
			assert.equal(result.status, 2, `${entry.name}: ${result.stderr}`);
			if (entry.expected)
				assert.equal(errorCode(result.stderr), entry.expected, entry.name);
			assert.equal(result.stdout, "", entry.name);
			assert.match(
				result.stderr,
				/^\{"error":"[a-z_]+"\}\nGUARD:\[\]\n$/,
				entry.name,
			);
			assert.deepEqual(snapshot(f.root), before, entry.name);
		} finally {
			fs.rmSync(f.root, { recursive: true, force: true });
		}
	}
});

test("resource-inspection CLI rejects unknown/duplicate/empty arguments with no partial output", () => {
	const f = fixture();
	try {
		for (const args of [
			["--unknown", "PRIVATE_SECRET"],
			["--cwd", "x", "--cwd", "y", "--project-trust", "trusted"],
			["--cwd", "", "--agent-dir", f.config, "--project-trust", "trusted"],
			[
				"--cwd",
				f.project,
				"--agent-dir",
				f.config,
				"--project-trust",
				"untrusted",
			],
		]) {
			const result = run(f, args);
			assert.equal(result.status, 2);
			assert.equal(result.stdout, "");
			assert.match(result.stderr, /^\{"error":"[a-z_]+"\}\nGUARD:\[\]\n$/);
		}
	} finally {
		fs.rmSync(f.root, { recursive: true, force: true });
	}
});
