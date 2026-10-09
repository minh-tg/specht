import { MutationCache, QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { shouldRetryQuery } from "./retry";

declare module "@tanstack/react-query" {
  interface Register {
    mutationMeta: {
      /**
       * Toast shown when the mutation succeeds. A function builds the message
       * from the response, for outcomes that report what the server decided.
       */
      success?: string | ((data: never, variables: never) => string);
    };
  }
}

/** Shows the success toast a mutation declared in its meta, if it declared one. */
export function announceMutationSuccess(
  success: string | ((data: never, variables: never) => string) | undefined,
  data: unknown,
  variables: unknown,
): void {
  if (!success) return;
  const message = typeof success === "function"
    ? (success as (data: unknown, variables: unknown) => string)(data, variables)
    : success;
  toast.success(message);
}

/**
 * The app's query client. Mutations announce their own success through
 * `meta.success`, so call sites do not each keep a "saved" message in state.
 */
export function createQueryClient(
  retry: typeof shouldRetryQuery | false = shouldRetryQuery,
): QueryClient {
  return new QueryClient({
    mutationCache: new MutationCache({
      onSuccess: (data, variables, _result, mutation) => {
        announceMutationSuccess(mutation.meta?.success, data, variables);
      },
    }),
    defaultOptions: { queries: { retry } },
  });
}
