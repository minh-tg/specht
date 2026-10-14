import { useCapabilities } from "@/api/hooks";

/**
 * Shown under an email field that adds a person to a project or team. The server does not check
 * that an address belongs to whoever registered it, so while anyone can sign up, an address may
 * belong to a stranger who got there first.
 */
export function OpenRegistrationNote() {
  const capabilities = useCapabilities();
  if (capabilities.data?.registration?.enabled !== true) return null;
  return (
    <p className="text-muted-foreground mt-1 text-xs">
      Sign-up is open on this server, so anyone could have created an account with this address.
      Make sure it belongs to the person you mean.
    </p>
  );
}
