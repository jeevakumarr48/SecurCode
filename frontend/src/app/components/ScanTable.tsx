import { Link } from "react-router";
import { duration, timeAgo } from "../lib/format";
import type { Scan } from "../lib/types";
import { EmptyState, StatusBadge, Table } from "./ui";

export function ScanTable({ scans, orgId }: { scans: Scan[]; orgId: string }) {
  if (scans.length === 0) return <EmptyState title="No scans yet" />;
  return (
    <Table head={["Scan", "Project", "Status", "Source", "Findings", "Started", "Duration"]}>
      {scans.map((scan) => (
        <tr key={scan.id}>
          <td><Link className="font-mono text-[12px] text-accent" to={`/orgs/${orgId}/scans/${scan.id}`}>{scan.id.slice(0, 8)}</Link></td>
          <td>{scan.project_name}</td>
          <td><StatusBadge status={scan.status} /></td>
          <td className="text-muted">{scan.trigger} · {scan.branch ?? scan.source_type}</td>
          <td className="tabular">{scan.summary.total ?? "—"}{scan.summary.new ? <span className="text-xs text-faint"> ({scan.summary.new} new)</span> : null}</td>
          <td className="text-muted">{timeAgo(scan.created_at)}</td>
          <td className="tabular text-muted">{duration(scan.duration_ms)}</td>
        </tr>
      ))}
    </Table>
  );
}
