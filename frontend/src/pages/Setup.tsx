import { APIError } from "@/api/client";
import { queryKeys, useCapabilities } from "@/api/hooks";
import { useSetup } from "@/api/pageRequests";
import { useAuth } from "@/auth/useAuth";
import { AuthLayout } from "@/components/AuthLayout";
import { ErrorState } from "@/components/ErrorState";
import { FormField } from "@/components/FormField";
import { PasswordField } from "@/components/PasswordField";
import { SkeletonLines } from "@/components/SkeletonLines";
import { Button } from "@/components/ui/button";
import { hiddenEmailCharactersMessage } from "@/lib/emailCharacters";
import { isPasswordValid, passwordPolicyMessage, passwordUserInputs } from "@/lib/passwordRules";
import { useQueryClient } from "@tanstack/react-query";
import { type SubmitEvent, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";

/**
 * First run of a new server: prove access with the token the server printed, then create the
 * administrator. The page exists only while the server has no account.
 */
export function Setup() {
  const auth = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const capabilities = useCapabilities();
  const setup = useSetup();

  const [token, setToken] = useState("");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (auth.token) return <Navigate to="/" replace />;
  const server = capabilities.data;
  if (!server) {
    return (
      <AuthLayout eyebrow="New server" title="Set up Specht">
        {capabilities.isError
          ? (
            <ErrorState
              title="Could not reach the server."
              onRetry={() => void capabilities.refetch()}
            />
          )
          : <SkeletonLines label="Checking the server" />}
      </AuthLayout>
    );
  }
  if (!server.setup.required) return <Navigate to="/login" replace />;

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    setTokenError(null);
    setPasswordError(null);
    setFormError(null);
    if (!isPasswordValid(password)) {
      setPasswordError("Choose a password that meets the requirements.");
      return;
    }
    setSubmitting(true);
    try {
      const session = await setup.mutateAsync({
        token: token.trim(),
        email: email.trim(),
        password,
        ...(name.trim() ? { display_name: name.trim() } : {}),
      });
      auth.adopt(session);
      await queryClient.invalidateQueries({ queryKey: queryKeys.capabilities() });
      navigate("/", { replace: true });
    } catch (err) {
      const policy = passwordPolicyMessage(err);
      const hidden = hiddenEmailCharactersMessage(err);
      if (policy) {
        setPasswordError(policy);
      } else if (hidden) {
        setFormError(hidden);
      } else if (err instanceof APIError && err.code === "invalid_setup_token") {
        setTokenError(
          "That token does not match the one this server printed. Copy it again from the log.",
        );
      } else if (err instanceof APIError && err.status === 404) {
        // Another visitor finished setup first.
        await queryClient.invalidateQueries({ queryKey: queryKeys.capabilities() });
        navigate("/login", { replace: true });
        return;
      } else if (err instanceof APIError && err.status === 400) {
        setFormError(err.message);
      } else {
        setFormError("Setup failed. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout
      eyebrow="New server · First run"
      title="Set up Specht"
      subtitle="No account exists on this server yet. Create the administrator and you are in. This screen goes away once the first account exists."
    >
      <form onSubmit={handleSubmit} noValidate className="grid gap-6">
        {formError && (
          <p
            role="alert"
            className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-sm"
          >
            {formError}
          </p>
        )}
        <fieldset className="grid gap-4 border-t-2 border-foreground pt-5">
          <legend className="sr-only">Prove you run this server</legend>
          <h2 className="text-section font-semibold" aria-hidden="true">
            <span className="text-muted-foreground mr-3 font-mono text-sm font-normal">01</span>
            Prove you run this server
          </h2>
          <FormField
            label="Setup token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            required
            inputClassName="font-mono"
            hint={
              <>
                The server wrote it to its log when it started: look for{" "}
                <code>setup_token=</code>. Running it yourself? Set <code>SETUP_TOKEN</code>{" "}
                to choose one.
              </>
            }
            error={tokenError}
          />
        </fieldset>
        <fieldset className="grid gap-4 border-t border-border pt-5">
          <legend className="sr-only">Create the administrator</legend>
          <h2 className="text-section font-semibold" aria-hidden="true">
            <span className="text-muted-foreground mr-3 font-mono text-sm font-normal">02</span>
            Create the administrator
          </h2>
          <FormField
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
            required
          />
          <FormField
            label={
              <>
                Name <span className="text-muted-foreground font-normal">(optional)</span>
              </>
            }
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoComplete="name"
          />
          <PasswordField
            label="Password"
            rulesId="setup-password-rules"
            userInputs={passwordUserInputs(email, name)}
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setPasswordError(null);
            }}
            required
            error={passwordError}
          />
        </fieldset>
        <Button type="submit" size="lg" disabled={submitting} className="h-10 w-full text-base">
          {submitting ? "Creating…" : "Create administrator"}
        </Button>
        <p className="text-muted-foreground text-[0.8125rem]">
          Later, bring people in from a project's Access page with invite links. No email server is
          needed.
        </p>
      </form>
    </AuthLayout>
  );
}
