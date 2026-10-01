import { AuthContext, type AuthContextValue } from "@/auth/context";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { expect, it } from "vitest";
import { SessionCacheGuard } from "./SessionCacheGuard";

function auth(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
  return {
    token: "token",
    refreshToken: "refresh",
    userId: "user-a",
    email: "a@example.com",
    login: async () => {},
    logout: () => {},
    loading: false,
    ...overrides,
  };
}

function tree(queryClient: QueryClient, value: AuthContextValue) {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthContext.Provider value={value}>
        <SessionCacheGuard />
      </AuthContext.Provider>
    </QueryClientProvider>
  );
}

function seededClient() {
  const queryClient = new QueryClient();
  queryClient.setQueryData(["me"], { role: "admin" });
  queryClient.setQueryData(["projects"], [{ slug: "payments-api" }]);
  return queryClient;
}

it("clears the cache when the user signs out", () => {
  const queryClient = seededClient();
  const view = render(tree(queryClient, auth()));
  expect(queryClient.getQueryData(["me"])).toBeDefined();

  view.rerender(
    tree(queryClient, auth({ token: null, refreshToken: null, userId: null, email: null })),
  );

  expect(queryClient.getQueryData(["me"])).toBeUndefined();
  expect(queryClient.getQueryData(["projects"])).toBeUndefined();
});

it("clears the cache when a different user signs in", () => {
  const queryClient = seededClient();
  const view = render(tree(queryClient, auth({ userId: "user-a" })));

  view.rerender(tree(queryClient, auth({ userId: "user-b", email: "b@example.com" })));

  expect(queryClient.getQueryData(["me"])).toBeUndefined();
});

it("keeps the cache when the same user's tokens are refreshed", () => {
  const queryClient = seededClient();
  const view = render(tree(queryClient, auth({ token: "token-1" })));

  view.rerender(tree(queryClient, auth({ token: "token-2", refreshToken: "refresh-2" })));

  expect(queryClient.getQueryData(["me"])).toEqual({ role: "admin" });
});

it("does not clear anything on the first render", () => {
  const queryClient = seededClient();

  render(tree(queryClient, auth()));

  expect(queryClient.getQueryData(["projects"])).toBeDefined();
});
