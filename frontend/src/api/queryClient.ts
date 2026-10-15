import { playCue } from "@/lib/sound";
import { MutationCache, QueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { APIError } from "./client";
import { shouldRetryQuery } from "./retry";

declare module "@tanstack/react-query" {
  interface Register {
    mutationMeta: {
      /**
       * Toast shown when the mutation succeeds. A function builds the message
       * from the response, for outcomes that report what the server decided.
       */
      success?: string | ((data: never, variables: never) => string);
      /**
       * Set `"none"` for a removal or revocation: the toast stays but the rising cue is skipped. A
       * function decides from the response and the variables, and returns `undefined` to keep the
       * default cue.
       */
      sound?: "none" | ((data: never, variables: never) => "none" | undefined);
    };
  }
}

/** Shows the success toast a mutation declared in its meta, if it declared one. */
export function announceMutationSuccess(
  success: string | ((data: never, variables: never) => string) | undefined,
  data: unknown,
  variables: unknown,
  sound?: "none" | ((data: never, variables: never) => "none" | undefined),
): void {
  if (!success) return;
  const message = typeof success === "function"
    ? (success as (data: unknown, variables: unknown) => string)(data, variables)
    : success;
  toast.success(message);
  const choice = typeof sound === "function"
    ? (sound as (data: unknown, variables: unknown) => "none" | undefined)(data, variables)
    : sound;
  if (choice !== "none") playCue("accepted");
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
        announceMutationSuccess(mutation.meta?.success, data, variables, mutation.meta?.sound);
      },
      // Only mutations that announce their success are user actions worth a failure cue; a 401
      // is the session ending, which redirects instead.
      onError: (error, _variables, _result, mutation) => {
        if (!mutation.meta?.success) return;
        if (error instanceof APIError && error.status === 401) return;
        playCue("error");
      },
    }),
    defaultOptions: { queries: { retry } },
  });
}
