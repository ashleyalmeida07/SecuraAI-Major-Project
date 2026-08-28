import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AuthTrack — Multi-Agent Security Scanner",
  description:
    "AuthTrack uses LangGraph-powered AI agents to crawl, map, and audit security headers of web applications. Discover vulnerabilities with intelligent, automated scanning.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        {/* Satoshi font via <link> — avoids PostCSS @import ordering issues with Tailwind v4 */}
        <link
          href="https://api.fontshare.com/v2/css?f[]=satoshi@400,500,700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body style={{ background: '#0a0a0a', color: '#fff', fontFamily: '"Satoshi", sans-serif' }}>
        {children}
      </body>
    </html>
  );
}
