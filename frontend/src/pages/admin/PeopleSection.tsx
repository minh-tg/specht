import { useChangeUserRole, useSetUserActive, useUsers } from "@/api/admin";
import { useMe } from "@/api/hooks";
import { type PasswordResetLink, useCreateResetLink } from "@/api/passwordReset";
import { CopyButton } from "@/components/CopyButton";
import { ErrorState } from "@/components/ErrorState";
import { SelectField } from "@/components/SelectField";
import { SkeletonLines } from "@/components/SkeletonLines";
import { StatusPill } from "@/components/StatusPill";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
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
import { isSystemAccount } from "@/lib/accounts";
import { formatDate } from "@/lib/format";
import { latestFailure } from "@/lib/latestFailure";
import { cn } from "@/lib/utils";
import type { UserProfile } from "@/types/api";
import { TriangleAlertIcon } from "lucide-react";
import { useDeferredValue, useState } from "react";

const PAGE_SIZE = 50;

const ROLE_OPTIONS = [
  { value: "admin", label: "Admin" },
  { value: "member", label: "User" },
];

const personName = (user: UserProfile) => user.display_name || user.email;

/**
 * Everyone with an account: change a role, deactivate or bring back an account. The server refuses to
 * demote or deactivate the last admin and to deactivate yourself, and the page says so up front for
 * the second and relays the server's words for the first.
 */
export function PeopleSection() {
  const [search, setSearch] = useState("");
  const [limit, setLimit] = useState(PAGE_SIZE);
  const email = useDeferredValue(search.trim());
  const users = useUsers(email, limit);
  const { data: me } = useMe();
  const changeRole = useChangeUserRole();
  const setActive = useSetUserActive();
  const createLink = useCreateResetLink();
  const [deactivating, setDeactivating] = useState<UserProfile | null>(null);
  const [issued, setIssued] = useState<{ user: UserProfile; link: PasswordResetLink; } | null>(
    null,
  );

  // The server's page may be full even when the system account is one of its rows.
  const received = users.data ?? [];
  const list = received.filter((u) => !isSystemAccount(u));
  const failure = latestFailure(changeRole, setActive, createLink);

  async function deactivate() {
    if (!deactivating) return;
    try {
      await setActive.mutateAsync({ id: deactivating.id, active: false });
    } catch {}
    setDeactivating(null);
  }

  async function issueLink(user: UserProfile) {
    try {
      setIssued({ user, link: await createLink.mutateAsync(user.id) });
    } catch {}
  }

  return (
    <section aria-labelledby="people-heading" className="grid gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h3 id="people-heading" className="text-body font-semibold">People</h3>
          <p className="text-muted-foreground mt-0.5 max-w-[68ch] text-meta">
            Deactivating ends their sessions at once and keeps their history. The last admin cannot
            be demoted or deactivated, and nobody can deactivate themselves.
          </p>
        </div>
        <Input
          type="search"
          aria-label="Find a person by email"
          placeholder="Find by email"
          className="w-56"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setLimit(PAGE_SIZE);
          }}
        />
      </div>

      {users.isLoading
        ? <SkeletonLines label="Loading people" />
        : users.isError && !users.data
        ? <ErrorState title="Could not load people." onRetry={() => void users.refetch()} />
        : (
          <ul
            aria-label="People"
            className="border-foreground m-0 list-none border-t-2 p-0"
          >
            {list.length === 0 && (
              <li className="text-muted-foreground border-border border-b py-5 text-body">
                {email ? "Nobody has an email that contains that." : "No accounts yet."}
              </li>
            )}
            {list.map((user) => {
              const isMe = user.id === me?.id;
              const off = !!user.disabled;
              return (
                <li
                  key={user.id}
                  data-off={off}
                  className="border-border grid items-center gap-x-4 gap-y-2 border-b px-0.5 py-3 sm:grid-cols-[minmax(0,1fr)_7.5rem_8.5rem_14rem]"
                >
                  <div className="min-w-0">
                    <p className={cn("font-semibold", off && "text-muted-foreground line-through")}>
                      {personName(user)}
                      {isMe && (
                        <span className="text-muted-foreground font-normal">{" "}(you)</span>
                      )}
                    </p>
                    {user.display_name && (
                      <p className="text-muted-foreground truncate text-meta">
                        {user.email}
                      </p>
                    )}
                  </div>
                  <SelectField
                    aria-label={`Role of ${personName(user)}`}
                    size="sm"
                    className="w-full"
                    value={user.role}
                    disabled={isMe || changeRole.isPending}
                    options={ROLE_OPTIONS}
                    onValueChange={(role) => {
                      if (role === "admin" || role === "member") {
                        changeRole.mutate({ id: user.id, role });
                      }
                    }}
                  />
                  <div>
                    <StatusPill tone={off ? "off" : "ok"}>
                      {off ? "Deactivated" : "Active"}
                    </StatusPill>
                  </div>
                  <div className="flex flex-wrap gap-2 sm:justify-end">
                    {isMe
                      ? <span className="text-muted-foreground text-meta">That is you</span>
                      : off
                      ? (
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={setActive.isPending}
                          aria-label={`Reactivate ${personName(user)}`}
                          onClick={() => setActive.mutate({ id: user.id, active: true })}
                        >
                          Reactivate
                        </Button>
                      )
                      : (
                        <>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={createLink.isPending}
                            aria-label={`Reset password for ${personName(user)}`}
                            onClick={() => void issueLink(user)}
                          >
                            Reset password
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            aria-label={`Deactivate ${personName(user)}`}
                            onClick={() => setDeactivating(user)}
                          >
                            Deactivate
                          </Button>
                        </>
                      )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}

      {received.length >= limit && (
        <div>
          <Button
            size="sm"
            variant="outline"
            disabled={users.isFetching}
            onClick={() => setLimit(limit + PAGE_SIZE)}
          >
            Show more
          </Button>
        </div>
      )}

      {failure && (
        <p
          role="alert"
          className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-body"
        >
          {failure.message || "Could not change the account."}
        </p>
      )}

      <Dialog open={issued !== null} onOpenChange={(open) => !open && setIssued(null)}>
        <DialogContent className="sm:max-w-md">
          {issued && (
            <>
              <DialogHeader>
                <DialogTitle>Send this link to {personName(issued.user)}</DialogTitle>
                <DialogDescription>
                  Whoever opens it can choose a new password for this account, once, until{" "}
                  {formatDate(issued.link.expires_at)}. A newer link replaces this one.
                </DialogDescription>
              </DialogHeader>
              <div className="bg-muted flex items-center gap-3 rounded-md py-2.5 pr-2.5 pl-3.5">
                <code
                  data-testid="reset-link"
                  className="min-w-0 flex-1 text-code break-all"
                >
                  {`${window.location.origin}${issued.link.link}`}
                </code>
                <CopyButton
                  text={`${window.location.origin}${issued.link.link}`}
                  label="reset link"
                />
              </div>
              <p className="text-muted-foreground flex items-start gap-2 text-meta">
                <TriangleAlertIcon
                  aria-hidden="true"
                  className="mt-0.5 size-4 shrink-0 text-sev-high-fg"
                />
                The link is shown only once. Send it over a channel you trust. Resetting signs the
                account out everywhere.
              </p>
              <DialogFooter>
                <Button onClick={() => setIssued(null)}>Done</Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={deactivating !== null}
        onOpenChange={(open) => !open && setDeactivating(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Deactivate {deactivating ? personName(deactivating) : ""}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              Their sessions end at once and they cannot sign in. Their history and project
              memberships stay, and you can reactivate the account later.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => void deactivate()}>
              Deactivate
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
