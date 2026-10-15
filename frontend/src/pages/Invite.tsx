import { APIError } from "@/api/client";
import { queryKeys } from "@/api/hooks";
import { useAcceptInvite, useInviteLookup, useJoinInvite } from "@/api/pageRequests";
import { useAuth } from "@/auth/useAuth";
import { AuthLayout } from "@/components/AuthLayout";
import { ErrorState } from "@/components/ErrorState";
import { FormField } from "@/components/FormField";
import { INLINE_LINK } from "@/components/inlineLink";
import { PasswordRequirements } from "@/components/PasswordRequirements";
import { SkeletonLines } from "@/components/SkeletonLines";
import { Button } from "@/components/ui/button";
import { isPasswordValid } from "@/lib/passwordRules";
import type { InviteLookup, InviteRole } from "@/types/api";
import { useQueryClient } from "@tanstack/react-query";
import { CheckIcon } from "lucide-react";
import { type SubmitEvent, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

const ROLE_CAN: Record<InviteRole, readonly string[]> = {
  member: ["Read findings and request waivers"],
  manager: [
    "Read findings and request waivers",
    "Triage findings and decide on waiver requests",
    "Set up CI and API keys",
    "Invite people up to the same role",
  ],
};

function RoleSummary({ role }: { readonly role: InviteRole; }) {
  return (
    <>
      <div className="mt-3 flex flex-wrap items-baseline gap-2.5">
        <span className="font-label border-border rounded border px-2 py-0.5 text-[0.6875rem]">
          {role}
        </span>
        <span className="text-muted-foreground text-sm">Your role in this project</span>
      </div>
      <ul
        aria-label={`What a ${role} can do`}
        className="text-muted-foreground mt-3.5 grid gap-1.5 text-[0.8125rem]"
      >
        {ROLE_CAN[role].map((line) => (
          <li key={line} className="grid grid-cols-[1rem_1fr] gap-2">
            <CheckIcon aria-hidden="true" className="text-sev-success-fg mt-0.5 size-3.5" />
            {line}
          </li>
        ))}
      </ul>
    </>
  );
}

function DeadLink() {
  return (
    <AuthLayout
      eyebrow="Invitation"
      title="This invite link does not work"
      subtitle="It may have been used, revoked or have expired. Ask the person who sent it for a new one."
    >
      <Link to="/login" className="text-action text-sm underline underline-offset-4">
        Go to sign in
      </Link>
    </AuthLayout>
  );
}

/** Opens an invitation: create an account and join, or join with the account you are signed in to. */
export function Invite() {
  const { token = "" } = useParams<{ token: string; }>();
  const auth = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const lookup = useInviteLookup(token);
  const accept = useAcceptInvite(token);
  const join = useJoinInvite(token);

  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [dead, setDead] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const invite = lookup.data;
  if (dead || (lookup.error instanceof APIError && lookup.error.status === 404)) {
    return <DeadLink />;
  }
  if (!invite) {
    return (
      <AuthLayout
        eyebrow="Invitation"
        title={lookup.isError ? "Join a project" : "Opening your invitation"}
      >
        {lookup.isError
          ? (
            <ErrorState
              title="Could not check the invite link."
              onRetry={() => void lookup.refetch()}
            />
          )
          : <SkeletonLines label="Checking the invite link" />}
      </AuthLayout>
    );
  }
  // A plain, un-narrowed copy for the handlers below, which TypeScript does not narrow.
  const details: InviteLookup = invite;
  const bound = invite.email !== undefined;
  const signInHref = `/login?redirect=${encodeURIComponent(`/invite/${token}`)}`;

  async function landIn(slug: string) {
    await queryClient.invalidateQueries({ queryKey: queryKeys.projects() });
    navigate(`/${slug}`, { replace: true });
  }

  function explain(err: unknown) {
    if (err instanceof APIError && err.status === 404) {
      setDead(true);
    } else if (err instanceof APIError && err.code === "invite_email_mismatch") {
      setFormError(
        `This invitation is for ${
          details.email ?? "another address"
        }. Use an account with that address.`,
      );
    } else if (err instanceof APIError && err.code === "registration_failed") {
      setFormError(
        "That address already has an account, or the account could not be created. If it is yours, sign in to join.",
      );
    } else if (err instanceof APIError && err.status === 400) {
      setFormError(err.message);
    } else {
      setFormError("Something went wrong. Please try again.");
    }
  }

  async function handleCreate(e: SubmitEvent) {
    e.preventDefault();
    setFormError(null);
    if (!isPasswordValid(password)) {
      setPasswordError("Choose a password that meets the requirements.");
      return;
    }
    setSubmitting(true);
    try {
      const joined = await accept.mutateAsync({
        email: (bound ? (details.email ?? "") : email).trim(),
        password,
        ...(name.trim() ? { display_name: name.trim() } : {}),
      });
      auth.adopt(joined);
      await landIn(joined.project_slug);
    } catch (err) {
      explain(err);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleJoin() {
    setFormError(null);
    setSubmitting(true);
    try {
      const joined = await join.mutateAsync();
      await landIn(joined.project_slug);
    } catch (err) {
      explain(err);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout eyebrow="Invitation" title={`Join ${invite.project_name}`}>
      <RoleSummary role={invite.role} />
      {formError && (
        <p
          role="alert"
          className="bg-destructive/10 text-destructive mt-6 rounded-md px-3 py-2 text-sm"
        >
          {formError}
        </p>
      )}
      {auth.token
        ? (
          <div className="mt-6 grid gap-4">
            <p className="bg-muted text-muted-foreground rounded-md px-3.5 py-3 text-[0.8125rem]">
              {auth.email
                ? (
                  <>
                    You are signed in as <b>{auth.email}</b>.
                  </>
                )
                : "You are signed in."} The project is added to this account.
            </p>
            <Button
              size="lg"
              className="h-10 w-full text-base"
              disabled={submitting}
              onClick={() => void handleJoin()}
            >
              {submitting ? "Joining…" : `Join ${invite.project_name}`}
            </Button>
            <p className="text-muted-foreground text-[0.8125rem]">
              Not you?{" "}
              <button
                type="button"
                className={INLINE_LINK}
                onClick={auth.logout}
              >
                Use another account
              </button>
            </p>
          </div>
        )
        : (
          <form onSubmit={handleCreate} noValidate className="mt-6 grid gap-4">
            {bound && (
              <p className="bg-muted text-muted-foreground rounded-md px-3.5 py-3 text-[0.8125rem]">
                This invitation is for one address. You can only join with <b>{invite.email}</b>.
              </p>
            )}
            <FormField
              label="Email"
              type="email"
              value={bound ? invite.email : email}
              onChange={(e) => setEmail(e.target.value)}
              readOnly={bound}
              inputClassName="read-only:border-dashed read-only:bg-muted read-only:text-muted-foreground"
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
            <FormField
              label="Choose a password"
              type="password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                setPasswordError(null);
              }}
              autoComplete="new-password"
              required
              extra={{
                id: "invite-password-rules",
                node: <PasswordRequirements id="invite-password-rules" value={password} />,
              }}
              error={passwordError}
            />
            <Button type="submit" size="lg" disabled={submitting} className="h-10 w-full text-base">
              {submitting ? "Creating…" : "Create account and join"}
            </Button>
            <p className="text-muted-foreground text-[0.8125rem]">
              Already have an account?{" "}
              <Link to={signInHref} className="text-action underline underline-offset-4">
                Sign in to join
              </Link>
            </p>
          </form>
        )}
    </AuthLayout>
  );
}
