'use client';

import { useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Loader2 } from 'lucide-react';

export default function AuthCallbackPage() {
  const router = useRouter();
  const params = useSearchParams();

  useEffect(() => {
    const token = params.get('token');
    const email = params.get('email');
    if (token) {
      localStorage.setItem('authtrack_token', token);
      if (email) localStorage.setItem('authtrack_user_email', email);
      router.replace('/scan');
    } else {
      router.replace('/login');
    }
  }, [params, router]);

  return (
    <div className="dark min-h-screen bg-background flex items-center justify-center">
      <div className="flex flex-col items-center gap-4 text-muted-foreground">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-sm">Signing you in with Google...</p>
      </div>
    </div>
  );
}
