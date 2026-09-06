import { APIError } from "@/api/client";
import { useAuth } from "@/auth/useAuth";
import { type FormEvent, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

export function safeRedirect(redirect: string | null): string {
  if (!redirect) return "/";
  if (!redirect.startsWith("/")) return "/";
  const second = redirect[1];
  // Block "//evil.com" (protocol-relative) and "/\evil.com" (backslash trick).
  if (second === "/" || second === "\\") return "/";
  return redirect;
}

export function Login() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const redirect = safeRedirect(searchParams.get("redirect"));

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (auth.token) {
    navigate("/", { replace: true });
    return null;
  }

  async function handleSubmit(e: FormEvent) {
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
      </form>
    </div>
  );
}
