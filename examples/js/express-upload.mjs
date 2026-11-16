import express from "express";
import { scanImage } from "pixwarden-js";

const app = express();
const maxBytes = 10 * 1024 * 1024;

app.post(
  "/images/inspect",
  express.raw({ type: "*/*", limit: maxBytes }),
  async (request, response, next) => {
    try {
      if (!Buffer.isBuffer(request.body)) {
        response.status(400).json({ error: "A binary request body is required." });
        return;
      }
      const result = await scanImage(request.body, {
        limits: { maxBytes },
        hints: {
          ...(typeof request.header("x-file-name") === "string" ? { filename: request.header("x-file-name") } : {}),
          ...(typeof request.header("content-type") === "string" ? { mediaType: request.header("content-type") } : {})
        }
      });
      response.status(result.verdict === "reject" ? 422 : 200).json(result);
    } catch (error) {
      next(error);
    }
  }
);

app.listen(Number(process.env.PORT ?? 3000), "127.0.0.1", () => {
  console.log("Pixwarden Express example listening on http://127.0.0.1:3000");
});
