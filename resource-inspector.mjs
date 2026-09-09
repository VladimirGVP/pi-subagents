#!/usr/bin/env node

// Separate executable: the existing pi-subagents installer remains unchanged.
import {
	inspectResources,
	parseResourceInspectionArgs,
	ResourceInspectionError,
} from "./src/api/resource-inspection.ts";

try {
	const options = parseResourceInspectionArgs(process.argv.slice(2));
	// This dedicated process never constructs a session. The API itself never changes the environment.
	process.env.PI_OFFLINE = "1";
	process.env.PI_CODING_AGENT_DIR = options.agentDir;
	const result = await inspectResources(options);
	process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
	const code =
		error instanceof ResourceInspectionError ? error.code : "inspection_failed";
	process.stderr.write(`${JSON.stringify({ error: code })}\n`);
	process.exitCode = 2;
}
