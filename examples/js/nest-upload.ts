import "reflect-metadata";
import { Controller, Module, Post, Req, Res } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import express, { type Request, type Response } from "express";
import { scanImage } from "pixwarden-js";

const maxBytes = 10 * 1024 * 1024;

@Controller("images")
class ImageController {
  @Post("inspect")
  async inspect(@Req() request: Request, @Res() response: Response) {
    if (!Buffer.isBuffer(request.body)) return response.status(400).json({ error: "A binary request body is required." });
    const result = await scanImage(request.body, {
      limits: { maxBytes },
      hints: {
        ...(typeof request.header("x-file-name") === "string" ? { filename: request.header("x-file-name") } : {}),
        ...(typeof request.header("content-type") === "string" ? { mediaType: request.header("content-type") } : {})
      }
    });
    return response.status(result.verdict === "reject" ? 422 : 200).json(result);
  }
}

@Module({ controllers: [ImageController] })
class UploadModule {}

async function bootstrap() {
  const app = await NestFactory.create(UploadModule, { bodyParser: false });
  app.use("/images/inspect", express.raw({ type: "*/*", limit: maxBytes }));
  await app.listen(Number(process.env.PORT ?? 3000), "127.0.0.1");
}

void bootstrap();
