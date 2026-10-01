import { APIError } from "@/api/client";
import { markSsoAttempt } from "@/auth/sso";
import { useAuth } from "@/auth/useAuth";
import { type SubmitEvent, useState } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { safeRedirect } from "./safeRedirect";

export function Login() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const redirect = safeRedirect(searchParams.get("redirect"));
  const ssoHref = redirect === "/"
    ? "/api/v1/auth/sso/login"
    : `/api/v1/auth/sso/login?redirect=${encodeURIComponent(redirect)}`;

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (auth.token) {
    return <Navigate to="/" replace />;
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await auth.login(email, password);
      navigate(redirect, { replace: true });
    } catch (err) {
      if (err instanceof APIError && err.status === 401) {
        setError("Invalid email or password");
      } else {
        setError("Login failed. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto flex min-h-[60vh] max-w-sm items-center justify-center px-4">
      <form onSubmit={handleSubmit} className="w-full space-y-4">
        <h1 className="text-2xl font-bold">Sign in</h1>

        {error && (
          <p className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-sm">
            {error}
          </p>
        )}

        <div>
          <label htmlFor="login-email" className="text-sm font-medium">
            Email
          </label>
          <input
            id="login-email"
            type="email"
            autoComplete="email"
            required
            className="border-input bg-background mt-1 block w-full rounded-md border px-3 py-2 text-sm"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>

        <div>
          <label htmlFor="login-password" className="text-sm font-medium">
            Password
          </label>
          <input
            id="login-password"
            type="password"
            autoComplete="current-password"
            required
            className="border-input bg-background mt-1 block w-full rounded-md border px-3 py-2 text-sm"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <button
          type="submit"
          disabled={submitting}
          className="bg-primary text-primary-foreground hover:bg-primary/90 w-full rounded-md px-4 py-2 text-sm font-medium disabled:opacity-50"
        >
          {submitting ? "Signing in..." : "Sign in"}
        </button>

        <a
          href={ssoHref}
          onClick={() => markSsoAttempt()}
          className="border-input text-foreground hover:bg-accent block w-full rounded-md border px-4 py-2 text-center text-sm font-medium"
        >
          Sign in with SSO
        </a>
      </form>
    </div>
  );
}
