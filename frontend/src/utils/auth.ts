const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://securaai-major-project.onrender.com/api/v1';

export async function login(email: string, password: string) {
  const response = await fetch(`${API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.detail || 'Login failed');
  }

  const data = await response.json();
  localStorage.setItem('token', data.access_token);
  return data;
}

export async function signup(email: string, password: string) {
  const response = await fetch(`${API_URL}/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.detail || 'Signup failed');
  }

  const data = await response.json();
  localStorage.setItem('token', data.access_token);
  return data;
}

export function logout() {
  localStorage.removeItem('token');
  window.location.href = '/login';
}

export function getToken() {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('token');
    if (token === "null" || token === "undefined") return null;
    return token;
  }
  return null;
}

export function isAuthenticated() {
  const token = getToken();
  if (!token) return false;
  // Check if JWT is expired by decoding the payload (base64url)
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      // Token expired — clean up
      localStorage.removeItem('token');
      localStorage.removeItem('SecuraAI_user_email');
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export async function fetchWithAuth(endpoint: string, options: RequestInit = {}) {
  const token = getToken();
  
  const headers = {
    ...options.headers,
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers,
  });
  
  if (response.status === 401) {
    logout();
    throw new Error('Unauthorized');
  }
  
  return response;
}
