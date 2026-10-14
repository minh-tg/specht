import { APIError } from "@/api/client";
import { useResetPassword } from "@/api/passwordReset";
import { AuthLayout } from "@/components/AuthLayout";
import { FormField } from "@/components/FormField";
import { PasswordRequirements } from "@/components/PasswordRequirements";
import { Button } from "@/components/ui/button";
import { isPasswordValid } from "@/lib/passwordRules";
import { type SubmitEvent, useState } from "react";
import { Link, useParams } from "react-router-dom";

function SignInLink() {
  return (
    <Link to="/login" className="text-action text-sm underline underline-offset-4">
      Go to sign in
    </Link>
  );
}

/** Chooses a new password from the link an administrator handed over. */
export function ResetPassword() {
  const { token = "" } = useParams<{ token: string; }>();
  const reset = useResetPassword();

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [dead, setDead] = useState(false);

  if (done) {
    return (
      <AuthLayout
        eyebrow="Reset password"
        title="Password changed"
        subtitle="Every session this account had is signed out. Sign in with the new password."
      >
        <SignInLink />
      </AuthLayout>
    );
  }
  if (dead) {
    return (
      <AuthLayout
        eyebrow="Reset password"
        title="This reset link does not work"
        subtitle="It may have been used, replaced by a newer link or have expired. Ask your administrator for a new one."
      >
        <SignInLink />
      </AuthLayout>
    );
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    setPasswordError(null);
    setConfirmError(null);
    setFormError(null);
    if (!isPasswordValid(password)) {
      setPasswordError("Choose a password that meets the requirements.");
      return;
    }
    if (password !== confirm) {
      setConfirmError("The two passwords do not match.");
      return;
    }
    try {
      await reset.mutateAsync({ token, password });
      setDone(true);
    } catch (err) {
      if (err instanceof APIError && err.code === "reset_link_invalid") {
        setDead(true);
      } else if (err instanceof APIError && err.status === 400) {
        setFormError(err.message);
      } else {
        setFormError("Could not set the password. Please try again.");
      }
    }
  }

  return (
    <AuthLayout
      eyebrow="Reset password"
      title="Choose a new password"
      subtitle="Your administrator sent you this link. It works once."
    >
      <form onSubmit={handleSubmit} noValidate className="grid gap-4">
        {formError && (
          <p
            role="alert"
            className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-sm"
          >
            {formError}
          </p>
        )}
        <FormField
          label="New password"
          type="password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            setPasswordError(null);
          }}
          autoComplete="new-password"
          required
          extra={{
            id: "reset-password-rules",
            node: <PasswordRequirements id="reset-password-rules" value={password} />,
          }}
          error={passwordError}
        />
        <FormField
          label="Confirm new password"
          type="password"
          value={confirm}
          onChange={(e) => {
            setConfirm(e.target.value);
            setConfirmError(null);
          }}
          autoComplete="new-password"
          required
          error={confirmError}
        />
        <Button
          type="submit"
          size="lg"
          disabled={reset.isPending}
          className="h-10 w-full text-base"
        >
          {reset.isPending ? "Saving…" : "Set password"}
        </Button>
      </form>
    </AuthLayout>
  );
}
