import { clearAgentDiscoveryCache, discoverAgentSnapshot } from "./agents.ts";

/** Called only after the inspector has validated every discovery input. No host registry is consulted. */
export function inspectAgentSnapshot(cwd: string) {
	clearAgentDiscoveryCache();
	const snapshot = discoverAgentSnapshot(cwd, "both", undefined, {
		includeChains: false,
		includeCandidateMetadata: true,
	});
	if (
		snapshot.all.agentDiagnostics?.length ||
		snapshot.effective.directories.some(
			(directory) =>
				directory.state === "unreadable" || directory.state === "not-directory",
		)
	) {
		throw new Error("invalid_agents");
	}
	const effective = snapshot.effective.agents.map(
		({ name, source, filePath }) => ({ name, source, filePath }),
	);
	return {
		effective,
		candidates: (snapshot.candidates ?? []).map((candidate) => {
			const winner = effective.find((agent) => agent.name === candidate.name);
			return {
				...candidate,
				effective:
					winner?.filePath === candidate.filePath &&
					winner.source === candidate.source,
				winnerPath: winner?.filePath ?? null,
			};
		}),
		directories: snapshot.effective.directories,
		settingsPaths: {
			global: snapshot.all.userSettingsPath,
			project: snapshot.all.projectSettingsPath,
		},
		runtimeRegistry: "host_required" as const,
		sessionCapabilityCeiling: "host_required" as const,
	};
}
