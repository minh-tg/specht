import { INLINE_LINK } from "@/components/inlineLink";
import { Link } from "react-router-dom";

export function NotFound() {
  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <h1 className="text-2xl font-bold">Page not found</h1>
      <p className="text-muted-foreground mt-2 text-sm">
        The page you&apos;re looking for doesn&apos;t exist, or you don&apos;t have access to it.
      </p>
      <Link to="/" className={`${INLINE_LINK} mt-4 inline-block text-sm`}>
        Back to projects
      </Link>
    </div>
  );
}
