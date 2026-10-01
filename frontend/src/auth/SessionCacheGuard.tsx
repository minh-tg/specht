import { useAuth } from "@/auth/useAuth";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

/**
 * Clears every cached query when the signed-in account changes: on sign-out,
 * on a session that ends or fails to refresh, and when someone else signs in.
 *
 * The query client lives as long as the page does. Without this, the next
 * person to sign in without a reload would be served the previous account's
 * cached profile (and the admin-only controls it enables) and cached project
 * and finding data until each entry went stale. A token refresh keeps the same
 * user id, so it does not clear anything.
 */
export function SessionCacheGuard() {
  const { userId } = useAuth();
  const queryClient = useQueryClient();
  const previous = useRef(userId);

  useEffect(() => {
    if (previous.current === userId) return;
    previous.current = userId;
    queryClient.clear();
  }, [userId, queryClient]);

  return null;
}
