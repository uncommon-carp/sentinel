import type { Reporter, RunResult } from "../core/types.js";

export function markdownReporter(): Reporter {
  return {
    name: "markdown",
    render(result: RunResult): string {
      const counts = result.findings.reduce<Record<string, number>>((acc, f) => {
        acc[f.severity] = (acc[f.severity] ?? 0) + 1;
        return acc;
      }, {});

      const lines: string[] = [];
      lines.push(`# Sentinel Report`);
      lines.push("");
      lines.push(`- Target: \`${result.meta.targetBaseUrl}\``);
      lines.push(`- Started: ${result.meta.startedAt}`);
      if (result.meta.finishedAt) lines.push(`- Finished: ${result.meta.finishedAt}`);
      if (typeof result.meta.durationMs === "number") lines.push(`- Duration: ${result.meta.durationMs}ms`);
      lines.push("");

      lines.push(`## Summary`);
      lines.push("");
      lines.push(`- Critical: ${counts.critical ?? 0}`);
      lines.push(`- High: ${counts.high ?? 0}`);
      lines.push(`- Medium: ${counts.medium ?? 0}`);
      lines.push(`- Low: ${counts.low ?? 0}`);
      lines.push(`- Info: ${counts.info ?? 0}`);
      lines.push("");

      lines.push(`## Findings`);
      lines.push("");
      lines.push(`| Severity | Suite | Title |`);
      lines.push(`| --- | --- | --- |`);
      for (const f of result.findings) {
        lines.push(`| ${f.severity} | ${f.suite} | ${f.title.replaceAll("|", "\\|")} |`);
      }
      lines.push("");

      return lines.join("\n");
    }
  };
}
