import { APIError } from "@/api/client";
import { useCapabilities } from "@/api/hooks";
import { useRegister } from "@/api/pageRequests";
import { useAuth } from "@/auth/useAuth";
import { AuthLayout } from "@/components/AuthLayout";
import { FormField } from "@/components/FormField";
import { PasswordField } from "@/components/PasswordField";
import { Button } from "@/components/ui/button";
import { hiddenEmailCharactersMessage } from "@/lib/emailCharacters";
import { isPasswordValid, passwordPolicyMessage, passwordUserInputs } from "@/lib/passwordRules";
import { type SubmitEvent, useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";

export function Register() {
  const auth = useAuth();
  const navigate = useNavigate();
  const capabilities = useCapabilities();
  const register = useRegister();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (auth.token) {
    return <Navigate to="/" replace />;
  }
  if (capabilities.data?.setup?.required) {
    return <Navigate to="/setup" replace />;
  }
  // The server says registration is closed: sign in, or open an invite link.
  if (capabilities.data?.registration?.enabled === false) {
    return <Navigate to="/login" replace />;
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    setError(null);
    if (!isPasswordValid(password)) {
      setPasswordError("Choose a password that meets the requirements.");
      return;
    }
    setSubmitting(true);
    try {
      await register.mutateAsync({ email, password });
      navigate("/login", { replace: true });
    } catch (err) {
      const policy = passwordPolicyMessage(err);
      const hidden = hiddenEmailCharactersMessage(err);
      if (policy) {
        setPasswordError(policy);
      } else if (hidden) {
        setError(hidden);
      } else if (err instanceof APIError) {
        setError(err.message);
      } else {
        setError("Registration failed. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout eyebrow="Specht" title="Create account">
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
          id="reg-email"
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <PasswordField
          label="Password"
          id="reg-password"
          rulesId="reg-password-rules"
          userInputs={passwordUserInputs(email)}
          required
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            setPasswordError(null);
          }}
          error={passwordError}
        />
        <Button type="submit" size="lg" disabled={submitting} className="h-10 w-full text-base">
          {submitting ? "Creating account..." : "Create account"}
        </Button>
        <p className="text-muted-foreground text-[0.8125rem]">
          Already have an account?{" "}
          <Link to="/login" className="text-action underline underline-offset-4">Sign in</Link>
        </p>
      </form>
    </AuthLayout>
  );
}
