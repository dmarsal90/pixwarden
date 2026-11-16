import Fastify from "fastify";
import { scanImage } from "pixwarden-js";

const maxBytes = 10 * 1024 * 1024;
const app = Fastify({ bodyLimit: maxBytes });

app.addContentTypeParser("*", { parseAs: "buffer", bodyLimit: maxBytes }, (_request, body, done) => {
  done(null, body);
});

app.post("/images/inspect", async (request, reply) => {
  if (!Buffer.isBuffer(request.body)) {
    return reply.code(400).send({ error: "A binary request body is required." });
  }
  const result = await scanImage(request.body, {
    limits: { maxBytes },
    hints: {
      ...(typeof request.headers["x-file-name"] === "string" ? { filename: request.headers["x-file-name"] } : {}),
      ...(typeof request.headers["content-type"] === "string" ? { mediaType: request.headers["content-type"] } : {})
    }
  });
  return reply.code(result.verdict === "reject" ? 422 : 200).send(result);
});

await app.listen({ port: Number(process.env.PORT ?? 3000), host: "127.0.0.1" });
