import Link from "next/link";
import { RegisterForm } from "@/app/register/register-form";

export const metadata = { title: "Create account — Fulcrum" };

export default function RegisterPage() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-6xl items-center px-6 py-4">
          <Link href="/" className="flex items-center gap-2.5">
            <span aria-hidden className="block h-4 w-4 rotate-45 border-2 border-signal" />
            <span className="font-mono text-sm font-semibold tracking-widest text-ink uppercase">
              Fulcrum
            </span>
          </Link>
        </div>
      </header>

      <main className="flex flex-1 items-center justify-center px-6 py-16">
        <div className="w-full max-w-md">
          <RegisterForm />
          <p className="mt-6 text-center text-sm text-ink-muted">
            Already registered?{" "}
            <Link href="/login" className="text-signal hover:underline">
              Sign in
            </Link>
          </p>
        </div>
      </main>
    </div>
  );
}
