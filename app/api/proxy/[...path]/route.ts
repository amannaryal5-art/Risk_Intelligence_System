import { NextRequest, NextResponse } from "next/server";

const backendUrl = (process.env.RISKINTEL_BACKEND_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const target = backendUrl + "/" + path.map(encodeURIComponent).join("/") + request.nextUrl.search;
  const configuredKey = process.env.RISKINTEL_API_KEY ?? process.env.RISKINTEL_DEFAULT_API_KEY ?? "";
  const suppliedKey = request.headers.get("x-api-key");
  const response = await fetch(target, {
    method: request.method,
    headers: {
      ...(request.headers.get("content-type") ? { "content-type": request.headers.get("content-type")! } : {}),
      ...(suppliedKey || configuredKey ? { "x-api-key": suppliedKey || configuredKey } : {}),
    },
    body: ["GET", "HEAD"].includes(request.method) ? undefined : await request.arrayBuffer(),
    cache: "no-store",
  });
  return new NextResponse(response.body, {
    status: response.status,
    headers: { "content-type": response.headers.get("content-type") ?? "application/json", "cache-control": "no-store" },
  });
}

export const GET = proxy;
export const POST = proxy;
