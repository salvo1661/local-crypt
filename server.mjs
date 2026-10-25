import { createReadStream, statSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "dist");
const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 4174);

const types = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".webp": "image/webp",
  ".xml": "application/xml; charset=utf-8",
};

function resolveAsset(url) {
  const pathname = decodeURIComponent(new URL(url, "http://localhost").pathname);
  const normalized = normalize(pathname).replace(/^(\.\.[/\\])+/, "");
  const candidate = join(root, normalized);

  if (!candidate.startsWith(root)) {
    return null;
  }

  try {
    const stat = statSync(candidate);
    if (stat.isFile()) return candidate;
    if (stat.isDirectory()) {
      const indexFile = join(candidate, "index.html");
      try {
        if (statSync(indexFile).isFile()) return indexFile;
      } catch {
        return join(root, "index.html");
      }
    }
  } catch {
    return join(root, "index.html");
  }

  return join(root, "index.html");
}

createServer((request, response) => {
  const file = resolveAsset(request.url || "/");

  if (!file) {
    response.writeHead(400);
    response.end("Bad request");
    return;
  }

  response.setHeader("Content-Type", types[extname(file)] || "application/octet-stream");
  createReadStream(file)
    .on("error", () => {
      response.writeHead(404);
      response.end("Not found");
    })
    .pipe(response);
}).listen(port, host, () => {
  console.log(`Serving ${root} at http://${host}:${port}`);
});
