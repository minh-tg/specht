import { APIError } from "@/api/client";
import { useChangePassword, useMe, useUpdateProfile } from "@/api/hooks";
import { useAuth } from "@/auth/useAuth";
import { ErrorState } from "@/components/ErrorState";
import { FormField } from "@/components/FormField";
import { PasswordField } from "@/components/PasswordField";
import { SkeletonLines } from "@/components/SkeletonLines";
import { Button } from "@/components/ui/button";
import { isPasswordValid, passwordPolicyMessage, passwordUserInputs } from "@/lib/passwordRules";
import { tooManyAttemptsMessage, tooManyAttemptsWait, useRetryWait } from "@/lib/retryWait";
import type { UserProfile } from "@/types/api";
import { type SubmitEvent, useState } from "react";

/** The signed-in person's own account: how they appear to others, and their password. */
export function Profile() {
  const me = useMe();

  return (
    <div className="mx-auto max-w-2xl space-y-8 px-4 py-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Your profile</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          How you appear to other people in Specht, and how you sign in.
        </p>
      </div>
      {me.isError || (!me.isLoading && !me.data)
        ? (
          <ErrorState
            title="Could not load your profile."
            onRetry={() => void me.refetch()}
          />
        )
        : me.data
        ? (
          <>
            <AccountSection profile={me.data} />
            <PasswordSection displayName={me.data.display_name} />
          </>
        )
        : <SkeletonLines label="Loading your profile" lines={4} />}
    </div>
  );
}

function AccountSection({ profile }: { readonly profile: UserProfile; }) {
  const update = useUpdateProfile();
  const saved = profile.display_name ?? "";
  const [name, setName] = useState(saved);
  const dirty = name.trim() !== saved;

  function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (dirty) update.mutate(name.trim());
  }

  return (
    <section
      aria-labelledby="profile-account"
      className="grid gap-4 border-t-2 border-foreground pt-5"
    >
      <h2 id="profile-account" className="text-base font-semibold">Account</h2>
      <dl className="grid gap-3 text-sm sm:grid-cols-[8rem_1fr]">
        <dt className="text-muted-foreground">Email</dt>
        <dd className="break-all font-medium">{profile.email}</dd>
        <dt className="text-muted-foreground">Role</dt>
        <dd className="font-medium">{profile.role === "admin" ? "Administrator" : "Member"}</dd>
      </dl>
      <form onSubmit={handleSubmit} noValidate className="grid gap-3">
        <FormField
          label="Display name"
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            update.reset();
          }}
          autoComplete="name"
          maxLength={120}
          hint="Shown next to your actions and on team rosters. Without one, other people see “Unnamed account”."
          error={update.isError ? update.error.message : null}
        />
        <div>
          <Button type="submit" disabled={!dirty || update.isPending}>
            {update.isPending ? "Saving…" : "Save name"}
          </Button>
        </div>
      </form>
    </section>
  );
}

function PasswordSection({ displayName }: { readonly displayName: string | null | undefined; }) {
  const auth = useAuth();
  const change = useChangePassword();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [currentError, setCurrentError] = useState<string | null>(null);
  const [nextError, setNextError] = useState<string | null>(null);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [noLocalPassword, setNoLocalPassword] = useState(false);
  const retry = useRetryWait(() => setFormError(null));

  function clearMessages() {
    setCurrentError(null);
    setNextError(null);
    setConfirmError(null);
    setFormError(null);
    setNotice("");
  }

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (retry.waiting) return;
    clearMessages();
    if (!isPasswordValid(next)) {
      setNextError("Choose a password that meets the requirements.");
      return;
    }
    if (next !== confirm) {
      setConfirmError("The two passwords do not match.");
      return;
    }
    if (next === current) {
      setNextError("Choose a password you are not using now.");
      return;
    }
    try {
      const session = await change.mutateAsync({ current, next });
      // The server ended every other session; this one continues on the fresh tokens.
      auth.adopt(session);
      setCurrent("");
      setNext("");
      setConfirm("");
      setNotice("Password changed. Your other sessions were signed out.");
    } catch (err) {
      const policy = passwordPolicyMessage(err);
      const waitSeconds = tooManyAttemptsWait(err);
      if (policy) {
        setNextError(policy);
      } else if (err instanceof APIError && err.code === "wrong_password") {
        setCurrentError("The current password is not correct.");
        setCurrent("");
      } else if (err instanceof APIError && err.code === "invalid_password") {
        setNextError(err.message);
      } else if (err instanceof APIError && err.code === "no_local_password") {
        setNoLocalPassword(true);
      } else if (err instanceof APIError && err.code === "account_changed") {
        setFormError(
          "Your account changed while the password was being updated. Sign in again with your new password.",
        );
      } else if (waitSeconds !== null) {
        setFormError(tooManyAttemptsMessage(waitSeconds));
        retry.start(waitSeconds);
      } else if (err instanceof APIError && err.status === 429) {
        setFormError("Too many attempts. Wait a minute and try again.");
      } else {
        setFormError("Could not change the password. Please try again.");
      }
    }
  }

  if (noLocalPassword) {
    return (
      <section
        aria-labelledby="profile-password"
        className="grid gap-3 border-t border-border pt-5"
      >
        <h2 id="profile-password" className="text-base font-semibold">Password</h2>
        <p className="text-sm">
          Your account signs in through your identity provider, so there is no password to change
          here.
        </p>
      </section>
    );
  }

  return (
    <section aria-labelledby="profile-password" className="grid gap-4 border-t border-border pt-5">
      <h2 id="profile-password" className="text-base font-semibold">Password</h2>
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
          label="Current password"
          type="password"
          value={current}
          onChange={(e) => {
            setCurrent(e.target.value);
            setCurrentError(null);
          }}
          autoComplete="current-password"
          required
          error={currentError}
        />
        <PasswordField
          label="New password"
          rulesId="profile-password-rules"
          userInputs={passwordUserInputs(auth.email ?? "", displayName)}
          value={next}
          onChange={(e) => {
            setNext(e.target.value);
            setNextError(null);
          }}
          required
          error={nextError}
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
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={change.isPending || retry.waiting}>
            {change.isPending ? "Changing…" : "Change password"}
          </Button>
          <p role="status" className="text-sev-success-fg text-sm">{notice}</p>
        </div>
        <p className="text-muted-foreground text-[0.8125rem]">
          Changing your password signs you out everywhere else. This browser stays signed in.
        </p>
      </form>
    </section>
  );
}
