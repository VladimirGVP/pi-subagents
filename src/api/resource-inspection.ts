import { Type, type Static } from "typebox";
import { Compile } from "typebox/compile";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { inspectAgentSnapshot } from "../agents/resource-inspection.ts";
import { findConfiguredProjectRoot } from "../agents/agents.ts";
import {
	getAgentDir,
	getConfigDirName,
	getProjectConfigDir,
	PI_CODING_AGENT_PACKAGE_ROOT_ENV,
} from "../shared/utils.ts";

export interface ResourceInspectionOptions {
	cwd: string;
	agentDir: string;
	projectTrust: "trusted" | "untrusted";
}

export class ResourceInspectionError extends Error {
	readonly code: string;
	constructor(code: string) {
		super(code);
		this.code = code;
	}
}

function fail(code: string): never {
	throw new ResourceInspectionError(code);
}

export function parseResourceInspectionArgs(
	args: readonly string[],
): ResourceInspectionOptions {
	if (args.length !== 6) fail("invalid_arguments");
	const values = new Map<string, string>();
	for (let index = 0; index < args.length; index += 2) {
		const key = args[index]!;
		const value = args[index + 1]!;
		if (
			!["--cwd", "--agent-dir", "--project-trust"].includes(key) ||
			values.has(key) ||
			!value.trim() ||
			value.startsWith("--") ||
			value.length > 4096
		)
			fail("invalid_arguments");
		values.set(key, value);
	}
	const projectTrust = values.get("--project-trust");
	if (projectTrust !== "trusted" && projectTrust !== "untrusted")
		fail("invalid_arguments");
	return {
		cwd: values.get("--cwd")!,
		agentDir: values.get("--agent-dir")!,
		projectTrust,
	};
}

// Parse supported config surfaces once; retain other settings for the official settings parser.
const Paths = Type.Array(
	Type.String({ minLength: 1, maxLength: 4096, pattern: "\\S" }),
	{ maxItems: 256 },
);
const ResourceFields = {
	extensions: Type.Optional(Paths),
	skills: Type.Optional(Paths),
	prompts: Type.Optional(Paths),
	themes: Type.Optional(Paths),
};
const PackageEntry = Type.Object({
	source: Type.String({ minLength: 1, maxLength: 4096 }),
	autoload: Type.Optional(Type.Boolean()),
	...ResourceFields,
});
const Subagents = Type.Object({
	agentScanDirs: Type.Optional(Paths),
	agents: Type.Optional(Paths),
	chains: Type.Optional(Paths),
});
const Config = Type.Object({
	...ResourceFields,
	name: Type.Optional(Type.String()),
	version: Type.Optional(Type.String()),
	packages: Type.Optional(
		Type.Array(
			Type.Union([Type.String({ minLength: 1, maxLength: 4096 }), PackageEntry]),
			{ maxItems: 256 },
		),
	),
	subagents: Type.Optional(Subagents),
	"pi-subagents": Type.Optional(Subagents),
	pi: Type.Optional(
		Type.Object({ ...ResourceFields, subagents: Type.Optional(Subagents) }),
	),
});
type InspectionConfig = Static<typeof Config>;
const configValidator = Compile(Config);
const sourceValidator = Compile(Type.String());
const trustValidator = Compile(
	Type.Record(Type.String(), Type.Union([Type.Boolean(), Type.Null()])),
);
const resourceKinds = ["extensions", "skills", "prompts", "themes"] as const;
type PackageScope = "user" | "project";

interface PinnedGitSource {
	host: string;
	repositoryPath: string;
}

function isSafeGitPathPart(value: string): boolean {
	return (
		value.length > 0 &&
		value !== "." &&
		value !== ".." &&
		!/[\\\0]/.test(value)
	);
}

/** Accept only source spellings that the public SDK resolves as managed Git packages. */
function parsePinnedGitSource(source: string): PinnedGitSource | undefined {
	const match = /^git:(.+)@([a-fA-F0-9]{40})$/.exec(source);
	if (!match || /[#\s]/.test(match[1]!)) return undefined;
	const repository = match[1]!;
	let host: string;
	let repositoryPath: string;
	const scpLike = /^git@([^:]+):(.+)$/.exec(repository);
	if (scpLike) {
		host = scpLike[1]!;
		repositoryPath = scpLike[2]!;
	} else if (/^(https?|ssh|git):\/\//.test(repository)) {
		try {
			const parsed = new URL(repository);
			if (parsed.username || parsed.password) return undefined;
			host = parsed.hostname;
			repositoryPath = parsed.pathname.replace(/^\/+/, "");
		} catch {
			return undefined;
		}
	} else {
		const slash = repository.indexOf("/");
		if (slash < 1) return undefined;
		host = repository.slice(0, slash);
		repositoryPath = repository.slice(slash + 1);
		if (host !== "localhost" && !host.includes(".")) return undefined;
	}
	repositoryPath = repositoryPath.replace(/\.git$/, "");
	const parts = repositoryPath.split("/");
	if (
		!isSafeGitPathPart(host) ||
		parts.length < 2 ||
		!parts.every(isSafeGitPathPart)
	)
		return undefined;
	return { host, repositoryPath };
}

/** Prevalidation is a bounded, conservative admission check, not an alternative resource resolver. */
class InspectionBoundary {
	private entries = 0;
	private bytes = 0;
	private checked = new Set<string>();
	private readonly liveHome = os.userInfo().homedir;

	checkPath(input: string): string {
		const resolved = path.resolve(input);
		if (resolved.length > 4096) fail("input_limit");
		const liveAgent = path.join(this.liveHome, ".pi", "agent");
		if (
			resolved === liveAgent ||
			resolved.startsWith(`${liveAgent}${path.sep}`) ||
			resolved
				.split(path.sep)
				.some((part) =>
					[".ssh", ".aws", ".gnupg", ".codex", ".claude"].includes(part),
				) ||
			/^(auth|credentials|keys)\.json$/i.test(path.basename(resolved))
		)
			fail("forbidden_path");
		let current = resolved;
		while (true) {
			if (fs.lstatSync(current, { throwIfNoEntry: false })?.isSymbolicLink())
				fail("symlink_not_supported");
			const parent = path.dirname(current);
			if (parent === current) break;
			current = parent;
		}
		return resolved;
	}

	file(input: string, required = false): string | undefined {
		const resolved = this.checkPath(input);
		if (!fs.existsSync(resolved)) {
			if (required) fail("missing_resource");
			return undefined;
		}
		const stat = fs.lstatSync(resolved);
		if (!stat.isFile()) fail("invalid_resource");
		fs.accessSync(resolved, fs.constants.R_OK);
		if (!this.checked.has(resolved)) {
			this.checked.add(resolved);
			this.bytes += stat.size;
			if (
				++this.entries > 4096 ||
				stat.size > 2 * 1024 * 1024 ||
				this.bytes > 16 * 1024 * 1024
			)
				fail("input_limit");
		}
		return resolved;
	}

	json(input: string, required = false): InspectionConfig {
		const file = this.file(input, required);
		const parsed: unknown = file ? JSON.parse(fs.readFileSync(file, "utf8")) : {};
		if (!configValidator.Check(parsed)) fail("invalid_config");
		return parsed;
	}

	tree(input: string, required = false, depth = 0): void {
		const resolved = this.checkPath(input);
		if (!fs.existsSync(resolved)) {
			if (required) fail("missing_resource");
			return;
		}
		if (!fs.lstatSync(resolved).isDirectory()) {
			this.file(resolved, true);
			return;
		}
		if (
			resolved === os.homedir() ||
			resolved === this.liveHome ||
			resolved === path.parse(resolved).root
		)
			fail("unbounded_root");
		if (depth > 12) fail("input_limit");
		if (this.checked.has(resolved)) return;
		this.checked.add(resolved);
		if (++this.entries > 4096) fail("input_limit");
		const entries = fs.readdirSync(resolved);
		if (entries.length > 1024) fail("input_limit");
		for (const entry of entries)
			this.tree(path.join(resolved, entry), true, depth + 1);
	}

	resource(input: string, base: string): string {
		// Patterns and negations require a separately bounded expansion contract.
		if (
			input.trim() !== input ||
			/[!*?{}[\]]/.test(input) ||
			input.includes("\0")
		)
			fail("unsupported_resource_pattern");
		const expanded = input.startsWith("~/")
			? path.join(os.homedir(), input.slice(2))
			: input;
		const resolved = path.resolve(base, expanded);
		this.tree(resolved, true);
		return resolved;
	}

	package(root: string, allowMissingManifest = false): void {
		const admitted = this.checkPath(root);
		if (!fs.existsSync(admitted)) fail("missing_resource");
		if (!fs.lstatSync(admitted).isDirectory()) fail("invalid_resource");
		const manifest = path.join(admitted, "package.json");
		if (!fs.existsSync(manifest)) {
			if (!allowMissingManifest) fail("missing_resource");
			for (const kind of resourceKinds) this.tree(path.join(admitted, kind));
			return;
		}
		const pkg = this.json(manifest, true);
		const pi = pkg.pi ?? {};
		for (const kind of resourceKinds) {
			if (pi[kind] !== undefined)
				for (const entry of pi[kind]) this.resource(entry, admitted);
			this.tree(path.join(admitted, kind));
		}
		for (const raw of [pkg["pi-subagents"], pi.subagents]) {
			if (raw === undefined) continue;
			for (const kind of ["agents", "chains"] as const)
				for (const entry of raw[kind] ?? []) this.resource(entry, admitted);
		}
	}

	managedGitPackage(
		source: string,
		scope: PackageScope,
		cwd: string,
		agentDir: string,
		packageManager: { getInstalledPath(source: string, scope: PackageScope): string | undefined },
	): void {
		const parsed = parsePinnedGitSource(source);
		if (!parsed) fail("unsupported_package_source");
		const root = packageManager.getInstalledPath(source, scope);
		if (!root || !fs.existsSync(root) || !fs.statSync(root).isDirectory())
			fail("missing_package_source");
		const expected = path.resolve(
			scope === "user" ? agentDir : path.join(cwd, ".pi"),
			"git",
			parsed.host,
			parsed.repositoryPath,
		);
		const admitted = this.checkPath(root);
		if (admitted !== expected || fs.realpathSync(admitted) !== expected)
			fail("unmanaged_package_source");
		this.package(admitted, true);
	}

	settings(
		file: string,
		packageManager?: { getInstalledPath(source: string, scope: PackageScope): string | undefined },
		scope?: PackageScope,
		cwd?: string,
		agentDir?: string,
	): InspectionConfig {
		const settings = this.json(file);
		const base = path.dirname(file);
		for (const kind of resourceKinds)
			for (const entry of settings[kind] ?? []) this.resource(entry, base);
		for (const entry of settings.subagents?.agentScanDirs ?? [])
			this.resource(entry, process.cwd());
		if (settings.packages !== undefined) {
			for (const item of settings.packages) {
				const entry = sourceValidator.Check(item) ? { source: item } : item;
				const source = entry.source;
				if (source.startsWith("npm:")) {
					const match =
						/^npm:((?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)(?:@(\d+\.\d+\.\d+))?$/.exec(
							source,
						);
					if (!match) fail("unsupported_package_source");
					const root = path.join(base, "npm", "node_modules", match[1]!);
					const pkg = this.json(path.join(root, "package.json"), true);
					if (
						!pkg.version ||
						!/^\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?$/.test(pkg.version) ||
						(match[2] && pkg.version !== match[2])
					)
						fail("missing_package_version");
					this.package(root);
				} else if (source.startsWith("git:")) {
					if (!packageManager || !scope || !cwd || !agentDir)
						fail("unsupported_package_source");
					this.managedGitPackage(source, scope, cwd, agentDir, packageManager);
				} else {
					if (
						!(
							path.isAbsolute(source) ||
							source.startsWith("./") ||
							source.startsWith("../") ||
							source.startsWith("~/")
						)
					)
						fail("unsupported_package_source");
					const root = source.startsWith("~/")
						? path.join(os.homedir(), source.slice(2))
						: path.resolve(base, source);
					this.package(root);
				}
			}
		}
		return settings;
	}

	configResources(base: string): void {
		for (const kind of ["agents", "skills", "extensions", "prompts", "themes"])
			this.tree(path.join(base, kind));
		const modules = this.checkPath(path.join(base, "npm", "node_modules"));
		if (fs.existsSync(modules)) {
			const names = fs.readdirSync(modules);
			if (names.length > 256) fail("input_limit");
			for (const name of names) {
				if (name.startsWith(".")) continue;
				const root = this.checkPath(path.join(modules, name));
				if (name.startsWith("@")) {
					const scoped = fs.readdirSync(root);
					if (scoped.length > 256) fail("input_limit");
					for (const child of scoped) this.package(path.join(root, child));
				} else this.package(root);
			}
		}
	}
}

interface ResolvedResource {
	path: string;
	enabled: boolean;
	metadata: { source: string; scope: string; origin: string };
}
interface Skill {
	name: string;
	filePath: string;
}
interface SkillDiagnostic {
	type: string;
	path?: string;
	collision?: { name: string; winnerPath: string; loserPath: string };
}
interface InspectionSdk {
	SettingsManager: {
		fromStorage(
			storage: {
				withLock(
					scope: "global" | "project",
					fn: (current: string | undefined) => string | undefined,
				): void;
			},
			options: { projectTrusted: boolean },
		): object;
	};
	DefaultPackageManager: new (options: {
		cwd: string;
		agentDir: string;
		settingsManager: object;
	}) => {
		getInstalledPath(source: string, scope: PackageScope): string | undefined;
		resolve(
			onMissing: () => Promise<"error">,
		): Promise<{ skills: ResolvedResource[] }>;
	};
	loadSkills(options: {
		cwd: string;
		agentDir: string;
		skillPaths: string[];
		includeDefaults: boolean;
	}): { skills: Skill[]; diagnostics: SkillDiagnostic[] };
	loadProjectContextFiles(options: {
		cwd: string;
		agentDir: string;
	}): { path: string; content: string }[];
}

async function loadSdk(): Promise<InspectionSdk> {
	const root = process.env[PI_CODING_AGENT_PACKAGE_ROOT_ENV];
	const entry = root
		? pathToFileURL(path.join(root, "dist", "index.js")).href
		: createRequire(import.meta.url).resolve("@earendil-works/pi-coding-agent");
	// SAFETY: this is the official SDK public entry, checked for the required read-only primitives below.
	const sdk = (await import(entry)) as InspectionSdk;
	if (
		!sdk.DefaultPackageManager ||
		!sdk.DefaultPackageManager.prototype.getInstalledPath ||
		!sdk.SettingsManager.fromStorage ||
		!sdk.loadSkills ||
		!sdk.loadProjectContextFiles
	)
		fail("unsupported_pi_sdk");
	return sdk;
}

/** Config-effective inspection in an isolated, already-offline process; never creates a live session. */
export async function inspectResources(options: ResourceInspectionOptions) {
	try {
		const parsed = parseResourceInspectionArgs([
			"--cwd",
			options.cwd,
			"--agent-dir",
			options.agentDir,
			"--project-trust",
			options.projectTrust,
		]);
		if (
			process.env.PI_OFFLINE !== "1" ||
			!process.env.HOME ||
			!process.env.PI_CODING_AGENT_DIR ||
			process.env.PI_SUBAGENT_EXTRA_AGENT_DIRS
		)
			fail("isolated_environment_required");
		const boundary = new InspectionBoundary();
		const cwd = fs.realpathSync(boundary.checkPath(parsed.cwd));
		const agentDir = fs.realpathSync(boundary.checkPath(parsed.agentDir));
		if (!fs.statSync(cwd).isDirectory() || !fs.statSync(agentDir).isDirectory())
			fail("invalid_directory");
		if (
			path.resolve(getAgentDir()) !== agentDir ||
			os.homedir() === os.userInfo().homedir
		)
			fail("isolated_environment_required");
		if (getConfigDirName() !== ".pi") fail("unsupported_config_directory");
		// The package snapshot does not implement Pi's untrusted-project policy. Never invent one here.
		if (parsed.projectTrust !== "trusted")
			fail("untrusted_snapshot_requires_host");
		const globalSettingsPath = path.join(agentDir, "settings.json");
		const projectSettingsPath = path.join(
			getProjectConfigDir(cwd),
			"settings.json",
		);
		const globalSettings = boundary.json(globalSettingsPath, true);
		const projectSettings = boundary.json(projectSettingsPath, true);
		const sdk = await loadSdk();
		const settingsManager = sdk.SettingsManager.fromStorage(
			{
				withLock(scope, fn) {
					if (
						fn(
							JSON.stringify(scope === "global" ? globalSettings : projectSettings),
						) !== undefined
					)
						fail("settings_write_forbidden");
				},
			},
			{ projectTrusted: true },
		);
		const packageManager = new sdk.DefaultPackageManager({
			cwd,
			agentDir,
			settingsManager,
		});
		boundary.settings(globalSettingsPath, packageManager, "user", cwd, agentDir);
		boundary.settings(projectSettingsPath, packageManager, "project", cwd, agentDir);
		boundary.configResources(agentDir);
		boundary.tree(path.join(os.homedir(), ".agents"));
		const trustFile = boundary.file(path.join(agentDir, "trust.json"));
		if (
			trustFile &&
			!trustValidator.Check(JSON.parse(fs.readFileSync(trustFile, "utf8")))
		)
			fail("invalid_trust");
		let ancestor = cwd;
		let ancestors = 0;
		let foundGit = false;
		while (true) {
			if (++ancestors > 64) fail("input_limit");
			if (ancestor !== cwd)
				boundary.settings(path.join(getProjectConfigDir(ancestor), "settings.json"));
			boundary.configResources(getProjectConfigDir(ancestor));
			boundary.tree(path.join(ancestor, ".agents"));
			for (const filename of [
				"AGENTS.override.md",
				"AGENTS.md",
				"AGENTS.MD",
				"CLAUDE.md",
				"CLAUDE.MD",
			])
				boundary.file(path.join(ancestor, filename));
			// Linked worktree context resolution reads outside the validated ancestor chain.
			const git = boundary.checkPath(path.join(ancestor, ".git"));
			if (!foundGit && fs.existsSync(git)) {
				if (!fs.statSync(git).isDirectory()) fail("unsupported_worktree_context");
				foundGit = true;
			}
			const parent = path.dirname(ancestor);
			if (parent === ancestor) break;
			ancestor = parent;
		}
		for (const filename of [
			"AGENTS.override.md",
			"AGENTS.md",
			"AGENTS.MD",
			"CLAUDE.md",
			"CLAUDE.MD",
		])
			boundary.file(path.join(agentDir, filename));
		const projectRoot = findConfiguredProjectRoot(cwd) ?? cwd;
		if (fs.existsSync(path.join(projectRoot, "package.json")))
			boundary.package(projectRoot);
		boundary.tree(fileURLToPath(new URL("../../agents", import.meta.url)), true);
		const resolved = await packageManager.resolve(async () => "error");
		const skillPaths = resolved.skills
			.filter((resource) => resource.enabled)
			.map((resource) => resource.path);
		for (const skillPath of skillPaths) boundary.tree(skillPath, true);
		const skills = sdk.loadSkills({
			cwd,
			agentDir,
			skillPaths,
			includeDefaults: false,
		});
		if (skills.diagnostics.some((diagnostic) => diagnostic.type !== "collision"))
			fail("invalid_skills");
		const result = {
			mode: "config_effective" as const,
			cwd,
			agentDir,
			settingsPaths: { global: globalSettingsPath, project: projectSettingsPath },
			projectTrust: {
				trusted: true,
				source: "explicit_override",
				persisted: false,
			},
			agents: inspectAgentSnapshot(cwd),
			skills: {
				effective: skills.skills.map(({ name, filePath }) => ({ name, filePath })),
				resources: resolved.skills.map(({ path: filePath, enabled }) => ({
					filePath,
					enabled,
				})),
				diagnostics: skills.diagnostics.map(
					({ type, path: filePath, collision }) => {
						const diagnostic: SkillDiagnostic = { type, path: filePath };
						if (collision)
							diagnostic.collision = {
								name: collision.name,
								winnerPath: collision.winnerPath,
								loserPath: collision.loserPath,
							};
						return diagnostic;
					},
				),
			},
			projectContextPaths: sdk
				.loadProjectContextFiles({ cwd, agentDir })
				.map((file) => file.path),
		};
		if (Buffer.byteLength(JSON.stringify(result)) > 1024 * 1024)
			fail("output_limit");
		return result;
	} catch (error) {
		if (error instanceof ResourceInspectionError) throw error;
		throw new ResourceInspectionError("inspection_failed");
	}
}
