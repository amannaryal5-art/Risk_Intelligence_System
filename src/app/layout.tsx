import type { Metadata } from "next";
import { JetBrains_Mono, Rajdhani } from "next/font/google";

import "@/app/globals.css";

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
});

const rajdhani = Rajdhani({
  subsets: ["latin"],
  variable: "--font-rajdhani",
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "RiskintelAI War Room",
  description: "Live Feed Status cyber operations page",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${jetbrainsMono.variable} ${rajdhani.variable}`}>
        {children}
      </body>
    </html>
  );
}
