import { AuthPage } from "@/components/ui/auth-page";

export default function LoginPage() {
  return (
    <div style={{ background: '#0a0a0a', minHeight: '100vh' }}>
      <AuthPage mode="login" />
    </div>
  );
}
