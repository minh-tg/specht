import { Link } from "react-router-dom";

export function NotFound() {
  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <h1 className="text-2xl font-bold">Page not found</h1>
      <p className="text-muted-foreground mt-2 text-sm">
        The page you&apos;re looking for doesn&apos;t exist, or you don&apos;t have access to it.
      </p>
      <Link to="/" className="text-action mt-4 inline-block text-sm underline hover:no-underline">
        Back to projects
      </Link>
    </div>
  );
}
