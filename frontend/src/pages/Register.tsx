import { APIError, apiFetch } from "@/api/client";
import { useAuth } from "@/auth/useAuth";
import type { RegisterResponse } from "@/types/api";
import { type SubmitEvent, useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";

export function Register() {
  const auth = useAuth();
  const navigate = useNavigate();

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
      await apiFetch<RegisterResponse>("/api/v1/auth/register", {
        method: "POST",
        body: JSON.stringify({ email, password }),
        skipAuthRedirect: true,
      });
      navigate("/login", { replace: true });
    } catch (err) {
      if (err instanceof APIError) {
        setError(err.message);
      } else {
        setError("Registration failed. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto flex min-h-[60vh] max-w-sm items-center justify-center px-4">
      <form onSubmit={handleSubmit} className="w-full space-y-4">
        <h1 className="text-2xl font-bold">Create account</h1>

        {error && (
          <p className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-sm">
            {error}
          </p>
        )}

        <div>
          <label htmlFor="reg-email" className="text-sm font-medium">
            Email
          </label>
          <input
            id="reg-email"
            type="email"
            autoComplete="email"
            required
            className="border-input bg-background mt-1 block w-full rounded-md border px-3 py-2 text-sm"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>

        <div>
          <label htmlFor="reg-password" className="text-sm font-medium">
            Password
          </label>
          <input
            id="reg-password"
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
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
          {submitting ? "Creating account..." : "Create account"}
        </button>

        <p className="text-muted-foreground text-center text-sm">
          Already have an account?{" "}
          <Link to="/login" className="text-action underline underline-offset-2 hover:no-underline">
            Sign in
          </Link>
        </p>
      </form>
    </div>
  );
}
