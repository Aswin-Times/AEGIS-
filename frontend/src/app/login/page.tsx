import { ShieldCheck } from "lucide-react";
import { LoginForm } from "./login-form";

export const metadata = { title: "Sign in to AEGIS" };

export default function LoginPage() {
  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-sm rounded-md border border-line bg-surface p-5">
        <div className="mb-4 flex items-center gap-2">
          <ShieldCheck aria-hidden size={20} className="text-accent" />
          <h1 className="text-base font-semibold">Sign in to AEGIS</h1>
        </div>
        <LoginForm />
      </div>
    </main>
  );
}
