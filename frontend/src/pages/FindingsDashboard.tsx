import { useState } from "react"
import { useParams, useSearchParams } from "react-router-dom"
import { useFindings } from "@/api/hooks"
import { SeverityBadge } from "@/components/ui/severity-badge"
import type { Finding } from "@/types/api"

const PAGE_SIZE = 20

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

function sortFindings(findings: Finding[], by: string, dir: "asc" | "desc") {
  return [...findings].sort((a, b) => {
    let cmp = 0
    if (by === "severity") {
      cmp = (severityOrder[a.current_severity] ?? 99) - (severityOrder[b.current_severity] ?? 99)
    } else if (by === "title") {
      cmp = a.current_title.localeCompare(b.current_title)
    } else {
      cmp = new Date(a.last_seen_at).getTime() - new Date(b.last_seen_at).getTime()
    }
    return dir === "desc" ? -cmp : cmp
  })
}

export function FindingsDashboard() {
  const { slug } = useParams<{ slug: string }>()
  const [searchParams, setSearchParams] = useSearchParams()

  const severity = searchParams.get("severity") ?? ""
  const status = searchParams.get("status") ?? ""
  const offset = parseInt(searchParams.get("offset") ?? "0", 10)

  const [sortBy, setSortBy] = useState("severity")
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc")

  const { data: findings, isLoading, isError, error, refetch } = useFindings(slug ?? "", {
    severity: severity || undefined,
    status: status || undefined,
    offset,
    limit: PAGE_SIZE,
  })

  function updateFilter(key: string, value: string) {
    const next = new URLSearchParams(searchParams)
    if (value) {
      next.set(key, value)
    } else {
      next.delete(key)
    }
    next.set("offset", "0")
    setSearchParams(next)
  }

  function toggleSort(column: string) {
    if (sortBy === column) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"))
    } else {
      setSortBy(column)
      setSortDir(column === "severity" ? "desc" : "asc")
    }
  }

  function goToPage(newOffset: number) {
    const next = new URLSearchParams(searchParams)
    next.set("offset", String(newOffset))
    setSearchParams(next)
  }

  const sorted = findings ? sortFindings(findings, sortBy, sortDir) : []

  const sortIndicator = (col: string) => {
    if (sortBy !== col) return ""
    return sortDir === "asc" ? " ▲" : " ▼"
  }

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="bg-muted h-10 animate-pulse rounded" />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-destructive text-sm">{error?.message ?? "Failed to load findings"}</p>
        <button className="text-primary text-sm underline hover:no-underline" onClick={() => refetch()}>
          Retry
        </button>
      </div>
    )
  }

  if (!findings?.length) {
    return (
      <div className="flex flex-col items-center gap-2 py-16">
        <p className="text-muted-foreground text-sm">No findings found</p>
        <p className="text-muted-foreground text-xs">Ingest a scan report to see findings</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <select
          className="border-input bg-background rounded-md border px-3 py-1 text-sm"
          value={severity}
          onChange={(e) => updateFilter("severity", e.target.value)}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          className="border-input bg-background rounded-md border px-3 py-1 text-sm"
          value={status}
          onChange={(e) => updateFilter("status", e.target.value)}
        >
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="confirmed">Confirmed</option>
          <option value="false_positive">False Positive</option>
          <option value="wont_fix">Won't Fix</option>
        </select>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-border border-b text-left">
              <th
                className="cursor-pointer px-3 py-2 font-medium"
                onClick={() => toggleSort("severity")}
              >
                Severity{sortIndicator("severity")}
              </th>
              <th className="px-3 py-2 font-medium">Kind</th>
              <th
                className="cursor-pointer px-3 py-2 font-medium"
                onClick={() => toggleSort("title")}
              >
                Title{sortIndicator("title")}
              </th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th
                className="cursor-pointer px-3 py-2 font-medium"
                onClick={() => toggleSort("last_seen")}
              >
                Last Seen{sortIndicator("last_seen")}
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f) => (
              <tr key={f.id} className="border-border hover:bg-muted/50 border-b">
                <td className="px-3 py-2">
                  <SeverityBadge severity={f.current_severity} />
                </td>
                <td className="text-muted-foreground px-3 py-2">{f.finding_kind}</td>
                <td className="px-3 py-2">{f.current_title}</td>
                <td className="px-3 py-2 capitalize">{f.triage_status}</td>
                <td className="text-muted-foreground px-3 py-2">
                  {new Date(f.last_seen_at).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between">
        <button
          className="text-muted-foreground hover:text-foreground disabled:opacity-50 text-sm"
          disabled={offset === 0}
          onClick={() => goToPage(Math.max(0, offset - PAGE_SIZE))}
        >
          Previous
        </button>
        <span className="text-muted-foreground text-xs">
          {offset + 1}–{offset + sorted.length}
        </span>
        <button
          className="text-muted-foreground hover:text-foreground disabled:opacity-50 text-sm"
          disabled={sorted.length < PAGE_SIZE}
          onClick={() => goToPage(offset + PAGE_SIZE)}
        >
          Next
        </button>
      </div>
    </div>
  )
}
