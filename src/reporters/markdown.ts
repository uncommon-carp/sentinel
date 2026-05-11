import type { Reporter, RunResult, Finding } from '../core/types.js';

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
};

const SEVERITY_LABELS = ['critical', 'high', 'medium', 'low', 'info'] as const;

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function owaspSortKey(category: string): number {
  return parseInt(category.match(/API(\d+)/)?.[1] ?? '99', 10);
}

function sortedByseverity(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99)
  );
}

export function markdownReporter(): Reporter {
  return {
    name: 'markdown',
    render(result: RunResult): string {
      const { findings, meta } = result;
      const lines: string[] = [];

      // Header + scan metadata
      lines.push('# Sentinel Report');
      lines.push('');
      lines.push(`- **Target:** \`${meta.targetBaseUrl}\``);
      lines.push(`- **Scanned:** ${meta.startedAt}`);
      if (meta.finishedAt) lines.push(`- **Finished:** ${meta.finishedAt}`);
      if (typeof meta.durationMs === 'number') lines.push(`- **Duration:** ${meta.durationMs}ms`);
      lines.push(`- **Version:** ${meta.version}`);
      lines.push('');

      // Severity summary table
      const counts = findings.reduce<Record<string, number>>((acc, f) => {
        acc[f.severity] = (acc[f.severity] ?? 0) + 1;
        return acc;
      }, {});

      lines.push('## Summary');
      lines.push('');
      lines.push('| Severity | Count |');
      lines.push('| --- | --- |');
      for (const sev of SEVERITY_LABELS) {
        const n = counts[sev] ?? 0;
        if (n > 0) lines.push(`| ${cap(sev)} | ${n} |`);
      }
      lines.push(`| **Total** | **${findings.length}** |`);
      lines.push('');

      // OWASP coverage table — only rendered when any finding has an owasp field
      const owaspCounts = new Map<string, number>();
      for (const f of findings) {
        if (f.owasp) owaspCounts.set(f.owasp, (owaspCounts.get(f.owasp) ?? 0) + 1);
      }
      if (owaspCounts.size > 0) {
        const sorted = [...owaspCounts.entries()].sort(
          (a, b) => owaspSortKey(a[0]) - owaspSortKey(b[0])
        );
        lines.push('## OWASP Coverage');
        lines.push('');
        lines.push('| Category | Findings |');
        lines.push('| --- | --- |');
        for (const [category, count] of sorted) {
          lines.push(`| ${category} | ${count} |`);
        }
        lines.push('');
      }

      // Per-finding sections, sorted by severity
      lines.push('## Findings');
      lines.push('');

      if (findings.length === 0) {
        lines.push('No findings.');
        lines.push('');
        return lines.join('\n');
      }

      for (const f of sortedByseverity(findings)) {
        lines.push('---');
        lines.push('');
        lines.push(`### [${cap(f.severity)}] ${f.title}`);
        const meta_parts = [`\`${f.id}\``, `Suite: ${f.suite}`];
        if (f.owasp) meta_parts.push(f.owasp);
        lines.push(meta_parts.join(' | '));
        lines.push('');
        lines.push(f.description);
        lines.push('');
        if (f.whyItMatters) {
          lines.push(`> **Why it matters:** ${f.whyItMatters}`);
          lines.push('');
        }
        if (f.remediation) {
          lines.push(`**Remediation:** ${f.remediation}`);
          lines.push('');
        }
      }

      return lines.join('\n');
    }
  };
}
