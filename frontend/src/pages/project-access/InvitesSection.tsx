import { useCreateInvite, useInvites, useRevokeInvite } from "@/api/hooks";
import { CopyButton } from "@/components/CopyButton";
import { ErrorState } from "@/components/ErrorState";
import { SelectField } from "@/components/SelectField";
import { SkeletonLines } from "@/components/SkeletonLines";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { Invite, InviteRole } from "@/types/api";
import { TriangleAlertIcon } from "lucide-react";
import { type SubmitEvent, useState } from "react";
import { expiresIn } from "./expiry";

const EXPIRY_OPTIONS = [
  { value: "1", label: "in 1 day" },
  { value: "7", label: "in 7 days" },
  { value: "14", label: "in 14 days" },
  { value: "30", label: "in 30 days" },
];

const ROLE_OPTIONS = [
  { value: "member", label: "Member" },
  { value: "manager", label: "Manager" },
];

const capitalise = (word: string) => word.charAt(0).toUpperCase() + word.slice(1);

/**
 * Invite links for a project: the open ones, a dialog to make one, and the show-once step that
 * hands over the link. Only people who may manage members see it.
 */
export function InvitesSection({ slug }: { readonly slug: string; }) {
  const { data: invites, isLoading, isError, refetch } = useInvites(slug);
  const create = useCreateInvite(slug);
  const revoke = useRevokeInvite(slug);

  const [open, setOpen] = useState(false);
  const [role, setRole] = useState<InviteRole>("member");
  const [email, setEmail] = useState("");
  const [days, setDays] = useState("7");
  const [created, setCreated] = useState<Invite | null>(null);

  function openDialog() {
    create.reset();
    setCreated(null);
    setRole("member");
    setEmail("");
    setDays("7");
    setOpen(true);
  }

  async function handleCreate(e: SubmitEvent) {
    e.preventDefault();
    try {
      const invite = await create.mutateAsync({
        role,
        ...(email.trim() ? { email: email.trim() } : {}),
        expires_in_days: Number(days),
      });
      setCreated(invite);
    } catch {}
  }

  const link = created?.link ? `${window.location.origin}${created.link}` : "";

  return (
    <section aria-labelledby="invites-heading">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h2 id="invites-heading" className="text-section font-semibold">Invite links</h2>
          <p className="text-muted-foreground mt-0.5 max-w-[60ch] text-sm">
            Each link works once and expires. Only a hash is stored, so a link cannot be shown
            again.
          </p>
        </div>
        <Button onClick={openDialog}>Invite people</Button>
      </div>

      {isLoading
        ? <SkeletonLines label="Loading invites" className="mt-4" />
        : isError
        ? (
          <div className="mt-4">
            <ErrorState title="Could not load invites." onRetry={() => void refetch()} />
          </div>
        )
        : (
          <ul aria-label="Pending invites" className="border-foreground mt-3 border-t-2">
            {invites && invites.length > 0
              ? invites.map((invite) => (
                <li
                  key={invite.id}
                  className="border-border grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 border-b px-0.5 py-3 sm:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_auto]"
                >
                  <div>
                    <b className="block font-semibold">{invite.email ?? "Anyone with the link"}</b>
                    <span className="text-muted-foreground text-[0.8125rem]">
                      {invite.created_by ? `Created by ${invite.created_by}` : "Created by someone"}
                    </span>
                  </div>
                  <div className="text-muted-foreground order-3 col-span-full text-[0.8125rem] sm:order-none sm:col-span-1">
                    {capitalise(invite.role)} · expires in{" "}
                    <span className="text-foreground tabular-nums">
                      {expiresIn(invite.expires_at)}
                    </span>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={revoke.isPending}
                    aria-label={`Revoke the invite for ${invite.email ?? "anyone with the link"}`}
                    onClick={() => revoke.mutate(invite.id)}
                  >
                    Revoke
                  </Button>
                </li>
              ))
              : (
                <li className="text-muted-foreground border-border border-b px-0.5 py-5 text-sm">
                  No open invites.
                </li>
              )}
          </ul>
        )}
      {revoke.isError && (
        <p role="alert" className="text-destructive mt-2 text-xs">
          {revoke.error?.message ?? "Failed to revoke the invite"}
        </p>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          {created
            ? (
              <>
                <DialogHeader>
                  <DialogTitle>Send this link</DialogTitle>
                  <DialogDescription>
                    Anyone who opens it can join as a <b>{created.role}</b>.
                  </DialogDescription>
                </DialogHeader>
                <div className="bg-muted flex items-center gap-3 rounded-md py-2.5 pr-2.5 pl-3.5">
                  <code
                    data-testid="invite-link"
                    className="min-w-0 flex-1 text-[0.8125rem] break-all"
                  >
                    {link}
                  </code>
                  <CopyButton text={link} label="invite link" />
                </div>
                <p className="text-muted-foreground flex items-start gap-2 text-[0.8125rem]">
                  <TriangleAlertIcon
                    aria-hidden="true"
                    className="mt-0.5 size-4 shrink-0 text-sev-high-fg"
                  />
                  This is the only time the link is shown. If you lose it, revoke the invite and
                  make another.
                </p>
                <DialogFooter>
                  <Button onClick={() => setOpen(false)}>Done</Button>
                </DialogFooter>
              </>
            )
            : (
              <>
                <DialogHeader>
                  <DialogTitle>Invite someone to this project</DialogTitle>
                  <DialogDescription>
                    You get a link to send them. No email is sent from here.
                  </DialogDescription>
                </DialogHeader>
                <form onSubmit={handleCreate} className="grid gap-4">
                  <div className="grid gap-1.5">
                    <label htmlFor="invite-role" className="text-sm font-medium">Role</label>
                    <SelectField
                      id="invite-role"
                      className="w-full"
                      value={role}
                      onValueChange={(v) => setRole(v === "manager" ? "manager" : "member")}
                      options={ROLE_OPTIONS}
                      aria-describedby="invite-role-hint"
                    />
                    <p id="invite-role-hint" className="text-muted-foreground text-[0.8125rem]">
                      Members read findings and request waivers. Admins are added from the people
                      list.
                    </p>
                  </div>
                  <div className="grid gap-1.5">
                    <label htmlFor="invite-email" className="text-sm font-medium">
                      Email <span className="text-muted-foreground font-normal">(optional)</span>
                    </label>
                    <Input
                      id="invite-email"
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      aria-describedby="invite-email-hint"
                    />
                    <p id="invite-email-hint" className="text-muted-foreground text-[0.8125rem]">
                      Only this address can accept. Leave it empty to let anyone with the link join.
                    </p>
                  </div>
                  <div className="grid gap-1.5">
                    <label htmlFor="invite-days" className="text-sm font-medium">Expires</label>
                    <SelectField
                      id="invite-days"
                      className="w-full"
                      value={days}
                      onValueChange={setDays}
                      options={EXPIRY_OPTIONS}
                    />
                  </div>
                  {create.isError && (
                    <p role="alert" className="text-destructive text-sm">
                      {create.error?.message ?? "Failed to create the invite"}
                    </p>
                  )}
                  <DialogFooter>
                    <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                      Cancel
                    </Button>
                    <Button type="submit" disabled={create.isPending}>
                      {create.isPending ? "Creating…" : "Create link"}
                    </Button>
                  </DialogFooter>
                </form>
              </>
            )}
        </DialogContent>
      </Dialog>
    </section>
  );
}
