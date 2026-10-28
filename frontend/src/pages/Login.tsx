import { APIError, SESSION_REUSED_REASON } from "@/api/client";
import { useCapabilities } from "@/api/hooks";
import { markSsoAttempt } from "@/auth/sso";
import { useAuth } from "@/auth/useAuth";
import { AuthLayout } from "@/components/AuthLayout";
import { FormField } from "@/components/FormField";
import { INLINE_LINK } from "@/components/inlineLink";
import { Button } from "@/components/ui/button";
import { buttonVariants } from "@/components/ui/button-variants";
import { tooManyAttemptsMessage, tooManyAttemptsWait, useRetryWait } from "@/lib/retryWait";
import { playCue } from "@/lib/sound";
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
  const sessionRevoked = searchParams.get("reason") === SESSION_REUSED_REASON;
  const ssoHref = redirect === "/"
    ? "/api/v1/auth/sso/login"
    : `/api/v1/auth/sso/login?redirect=${encodeURIComponent(redirect)}`;

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const retry = useRetryWait(() => setError(null));

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
    if (retry.waiting) return;
    setError(null);
    setSubmitting(true);
    try {
      await auth.login(email, password);
      navigate(redirect, { replace: true });
    } catch (err) {
      playCue("error");
      const waitSeconds = tooManyAttemptsWait(err);
      if (waitSeconds !== null) {
        setError(tooManyAttemptsMessage(waitSeconds));
        retry.start(waitSeconds);
      } else if (err instanceof APIError && err.status === 401) {
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
        {sessionRevoked && !error && (
          <p
            role="status"
            className="bg-muted text-foreground rounded-md px-3 py-2 text-body"
          >
            You were signed out because this session's sign-in token was used twice. If that was not
            you, change your password after you sign in again.
          </p>
        )}
        {error && (
          <p
            role="alert"
            className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-body"
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
        <Button
          type="submit"
          size="lg"
          disabled={submitting || retry.waiting}
          className="h-10 w-full text-control"
        >
          {submitting ? "Signing in..." : "Sign in"}
        </Button>
        {auth.ssoBrowserMismatch && (
          <div
            role="alert"
            className="bg-destructive/10 text-destructive grid gap-3 rounded-md px-3 py-2 text-body"
          >
            <p>Start sign-in again from this browser.</p>
            <a
              href={ssoHref}
              onClick={() => markSsoAttempt()}
              className={cn(
                buttonVariants({ variant: "outline" }),
                "justify-self-start",
              )}
            >
              Sign in with SSO
            </a>
          </div>
        )}
        {ssoOffered && !auth.ssoBrowserMismatch && (
          <>
            <div
              aria-hidden="true"
              className="text-muted-foreground flex items-center gap-3 text-meta before:h-px before:flex-1 before:bg-border after:h-px after:flex-1 after:bg-border"
            >
              or
            </div>
            <a
              href={ssoHref}
              onClick={() => markSsoAttempt()}
              className={cn(
                buttonVariants({ variant: "outline", size: "lg" }),
                "h-10 w-full text-control",
              )}
            >
              Sign in with SSO
            </a>
          </>
        )}
      </form>
      {registrationOpen && (
        <p className="text-muted-foreground mt-5 text-meta">
          New here?{" "}
          <Link to="/register" className={INLINE_LINK}>
            Create an account
          </Link>
        </p>
      )}
      {inviteOnly && (
        <p className="bg-muted text-muted-foreground mt-5 flex items-start gap-2.5 rounded-md px-3.5 py-3 text-meta">
          <InfoIcon aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          Registration is closed on this server. To join a project, open the invite link a project
          manager sent you.
        </p>
      )}
    </AuthLayout>
  );
}
