import { APIError } from "@/api/client";
import { useCapabilities } from "@/api/hooks";
import { markSsoAttempt } from "@/auth/sso";
import { useAuth } from "@/auth/useAuth";
import { AuthLayout } from "@/components/AuthLayout";
import { FormField } from "@/components/FormField";
import { Button } from "@/components/ui/button";
import { buttonVariants } from "@/components/ui/button-variants";
import { cn } from "@/lib/utils";
import { InfoIcon } from "lucide-react";
import { type SubmitEvent, useState } from "react";
import { Link, Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { safeRedirect } from "./safeRedirect";

export function Login() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const capabilities = useCapabilities();
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
  // A server with no account sends everyone to set it up first.
  if (capabilities.data?.setup.required) {
    return <Navigate to="/setup" replace />;
  }

  // Until the server has said what it offers, the extras stay out, so they never flash in and
  // vanish. If it cannot be asked, offer what the page always offered.
  const known = capabilities.isSuccess;
  const failed = capabilities.isError;
  const registrationOpen = known ? capabilities.data.registration.enabled : failed;
  const ssoOffered = known ? capabilities.data.sso.enabled : failed;
  const inviteOnly = known && !capabilities.data.registration.enabled;

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
        setError("Sign in failed. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout
      eyebrow="Specht"
      title="Sign in"
      subtitle="Use the account you were given for this server."
    >
      <form onSubmit={handleSubmit} className="grid gap-4">
        {error && (
          <p
            role="alert"
            className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-sm"
          >
            {error}
          </p>
        )}
        <FormField
          label="Email"
          id="login-email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <FormField
          label="Password"
          id="login-password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Button type="submit" size="lg" disabled={submitting} className="h-10 w-full text-base">
          {submitting ? "Signing in..." : "Sign in"}
        </Button>
        {ssoOffered && (
          <>
            <div
              aria-hidden="true"
              className="text-muted-foreground flex items-center gap-3 text-[0.8125rem] before:h-px before:flex-1 before:bg-border after:h-px after:flex-1 after:bg-border"
            >
              or
            </div>
            <a
              href={ssoHref}
              onClick={() => markSsoAttempt()}
              className={cn(
                buttonVariants({ variant: "outline", size: "lg" }),
                "h-10 w-full text-base",
              )}
            >
              Sign in with SSO
            </a>
          </>
        )}
      </form>
      {registrationOpen && (
        <p className="text-muted-foreground mt-5 text-[0.8125rem]">
          New here?{" "}
          <Link to="/register" className="text-action underline underline-offset-4">
            Create an account
          </Link>
        </p>
      )}
      {inviteOnly && (
        <p className="bg-muted text-muted-foreground mt-5 flex items-start gap-2.5 rounded-md px-3.5 py-3 text-[0.8125rem]">
          <InfoIcon aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          Registration is closed on this server. To join a project, open the invite link a project
          manager sent you.
        </p>
      )}
    </AuthLayout>
  );
}
