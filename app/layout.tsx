import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = { title: "CRIE | Risk Intelligence", description: "Focused risk intelligence for suspicious links, IOCs, and files." };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
