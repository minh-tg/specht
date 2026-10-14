import { useMutation } from "@tanstack/react-query";
import { apiFetch } from "./client";

/** A one-time link for a locked-out account. The link is relative and is shown once. */
export interface PasswordResetLink {
  link: string;
  expires_at: string;
}

/** Asks the server for a reset link for one account. Global admins only. */
export function useCreateResetLink() {
  return useMutation({
    mutationFn: (userId: string) =>
      apiFetch<PasswordResetLink>(`/api/v1/users/${encodeURIComponent(userId)}/reset-link`, {
        method: "POST",
        body: JSON.stringify({}),
      }),
  });
}

/** Sets a new password from the token in a reset link. The page is signed out, so no redirect. */
export function useResetPassword() {
  return useMutation({
    mutationFn: ({ token, password }: { token: string; password: string; }) =>
      apiFetch<void>("/api/v1/auth/reset", {
        method: "POST",
        body: JSON.stringify({ token, password }),
        skipAuthRedirect: true,
      }),
  });
}
