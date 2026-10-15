import { usePrefetchOnIntent } from "@/lib/usePrefetchOnIntent";
import type { QueryClient } from "@tanstack/react-query";
import type { ComponentProps } from "react";
import { Link } from "react-router-dom";

type PrefetchLinkProps =
  & Omit<
    ComponentProps<typeof Link>,
    "onPointerEnter" | "onPointerLeave" | "onFocus" | "onBlur"
  >
  & {
    /** Warms the cache for the page this link opens. Runs after the pointer rests on the link. */
    readonly warm: (queryClient: QueryClient) => Promise<unknown>;
  };

/** A router link that fetches its target page's first data on intent. See `usePrefetchOnIntent`. */
export function PrefetchLink({ warm, ...props }: PrefetchLinkProps) {
  return <Link {...props} {...usePrefetchOnIntent(warm)} />;
}
