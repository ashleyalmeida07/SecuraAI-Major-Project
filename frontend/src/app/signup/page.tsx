import { AuthPage } from "@/components/ui/auth-page";

export default function SignupPage() {
  return (
    <div style={{ background: '#0a0a0a', minHeight: '100vh' }}>
      <AuthPage mode="signup" />
    </div>
  );
}
