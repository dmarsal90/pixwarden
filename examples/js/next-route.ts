import { NextResponse, type NextRequest } from "next/server";
import { PixwardenError, scanImageStream } from "pixwarden-js";

export const runtime = "nodejs";
const maxBytes = 10 * 1024 * 1024;

async function* chunks(body: ReadableStream<Uint8Array>): AsyncGenerator<Uint8Array> {
  const reader = body.getReader();
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) return;
      yield item.value;
    }
  } finally {
    reader.releaseLock();
  }
}

export async function POST(request: NextRequest) {
  if (!request.body) return NextResponse.json({ error: "A binary request body is required." }, { status: 400 });
  try {
    const result = await scanImageStream(chunks(request.body), {
      signal: request.signal,
      limits: { maxBytes },
      hints: {
        ...(request.headers.get("x-file-name") ? { filename: request.headers.get("x-file-name")! } : {}),
        ...(request.headers.get("content-type") ? { mediaType: request.headers.get("content-type")! } : {})
      }
    });
    return NextResponse.json(result, { status: result.verdict === "reject" ? 422 : 200 });
  } catch (error) {
    if (error instanceof PixwardenError && error.code === "INPUT_TOO_LARGE") {
      return NextResponse.json({ error: "Request body exceeds the image limit." }, { status: 413 });
    }
    if (error instanceof PixwardenError && error.code === "CANCELLED") {
      return new Response(null, { status: 499 });
    }
    return NextResponse.json({ error: "Image inspection failed." }, { status: 500 });
  }
}
