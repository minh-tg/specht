import { useMe, useProjects } from "@/api/hooks";
import { useAuth } from "@/auth/useAuth";
import { type Command, currentProjectSlug } from "@/lib/commands";
import { nextTheme, useTheme } from "@/lib/theme";
import { useMemo } from "react";
import { useLocation, useNavigate } from "react-router-dom";

const PROJECT_PAGES: readonly { path: string; label: string; keywords?: string; }[] = [
  { path: "findings", label: "Findings", keywords: "vulnerabilities issues" },
  { path: "reports", label: "Reports", keywords: "scans history" },
  { path: "access", label: "Access & Members", keywords: "people teams invite" },
  { path: "policy", label: "Policy", keywords: "severity floor template" },
  { path: "waivers", label: "Waivers", keywords: "exceptions approve" },
  { path: "insights", label: "Insights", keywords: "charts age overdue" },
  { path: "watcher", label: "Watcher", keywords: "cve feed" },
  { path: "setup", label: "CI setup", keywords: "pipeline github action key" },
  { path: "reports/upload", label: "Upload a report", keywords: "ingest scan file" },
];

/**
 * What the palette offers right now: the pages of the project you are in, the other projects, the
 * places everyone can go, the ones only an admin can, and the two things to do. A command for a
 * place you cannot use is left out rather than shown and refused.
 */
export function useCommands(): Command[] {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const { logout } = useAuth();
  const { theme, setTheme } = useTheme();
  const { data: me } = useMe();
  const { data: projects } = useProjects();
  const isAdmin = me?.role === "admin";
  const slug = currentProjectSlug(pathname);

  return useMemo(() => {
    const go = (to: string) => () => navigate(to);
    const list: Command[] = [];

    if (slug) {
      for (const page of PROJECT_PAGES) {
        list.push({
          id: `project:${page.path}`,
          group: "This project",
          label: page.label,
          keywords: page.keywords,
          run: go(`/${encodeURIComponent(slug)}/${page.path}`),
        });
      }
    }

    for (const project of projects ?? []) {
      if (project.slug === slug) continue;
      list.push({
        id: `open:${project.slug}`,
        group: "Projects",
        label: project.name || project.slug,
        hint: project.slug,
        run: go(`/${encodeURIComponent(project.slug)}/findings`),
      });
    }

    list.push({ id: "go:home", group: "Go to", label: "All projects", run: go("/") });
    list.push({ id: "go:teams", group: "Go to", label: "Teams", run: go("/teams") });
    if (isAdmin) {
      list.push({ id: "go:new", group: "Go to", label: "New project", run: go("/projects/new") });
      list.push({
        id: "go:admin",
        group: "Go to",
        label: "Admin",
        keywords: "people server retention",
        run: go("/admin"),
      });
      list.push({
        id: "go:keys",
        group: "Go to",
        label: "API keys",
        keywords: "tokens",
        run: go("/api-keys"),
      });
    }

    list.push({
      id: "do:theme",
      group: "Do",
      label: `Switch theme (now ${theme})`,
      keywords: "dark light mode appearance",
      run: () => setTheme(nextTheme(theme)),
    });
    list.push({
      id: "do:logout",
      group: "Do",
      label: "Sign out",
      keywords: "logout log out",
      run: logout,
    });
    return list;
  }, [slug, projects, isAdmin, theme, setTheme, logout, navigate]);
}
