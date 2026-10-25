import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const distDir = join(process.cwd(), "dist");
const baseUrl = "https://crypt.localtool.tech";
const langs = ["en", "ko", "ja", "zh", "es", "fr", "de", "id", "ar"];

const meta = {
  en: {
    title: "EZCrypt | On-Device Encryption",
    description: "On-device encryption tool with no server upload. Uses PGP-compatible symmetric encryption format.",
  },
  ko: {
    title: "EZCrypt | 온디바이스 암호화",
    description: "서버 업로드 없이 브라우저에서만 작동하는 온디바이스 암호화 도구입니다. PGP 호환 대칭 암호화 형식을 사용합니다.",
  },
  ja: {
    title: "EZCrypt | オンデバイス暗号化",
    description: "サーバーにアップロードせず、ブラウザ内だけで動作するオンデバイス暗号化ツールです。PGP互換の対称暗号化形式を使用します。",
  },
  zh: {
    title: "EZCrypt | 设备端加密",
    description: "无需上传到服务器、仅在浏览器中运行的设备端加密工具。使用兼容 PGP 的对称加密格式。",
  },
  es: {
    title: "EZCrypt | Cifrado en el dispositivo",
    description: "Herramienta de cifrado en el dispositivo sin subida al servidor. Usa un formato de cifrado simétrico compatible con PGP.",
  },
  fr: {
    title: "EZCrypt | Chiffrement sur appareil",
    description: "Outil de chiffrement local sans envoi au serveur. Utilise un format de chiffrement symétrique compatible PGP.",
  },
  de: {
    title: "EZCrypt | On-Device-Verschlüsselung",
    description: "On-Device-Verschlüsselungstool ohne Server-Upload. Verwendet ein PGP-kompatibles symmetrisches Verschlüsselungsformat.",
  },
  id: {
    title: "EZCrypt | Enkripsi di Perangkat",
    description: "Alat enkripsi di perangkat tanpa unggah ke server. Menggunakan format enkripsi simetris yang kompatibel dengan PGP.",
  },
  ar: {
    title: "EZCrypt | تشفير على الجهاز",
    description: "أداة تشفير تعمل داخل المتصفح بدون رفع البيانات إلى الخادم. تستخدم تنسيق تشفير متماثلًا متوافقًا مع PGP.",
  },
};

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function alternateLinks() {
  const links = langs
    .map((lang) => `<link rel="alternate" hreflang="${lang}" href="${baseUrl}/${lang}" />`)
    .join("\n    ");
  return `${links}\n    <link rel="alternate" hreflang="x-default" href="${baseUrl}/en" />`;
}

function renderHtml(template, lang) {
  const { title, description } = meta[lang];
  const escapedTitle = escapeHtml(title);
  const escapedDescription = escapeHtml(description);

  return template
    .replace(/<html lang="[^"]*"/, `<html lang="${lang}"`)
    .replace(/<title>[\s\S]*?<\/title>/, `<title>${escapedTitle}</title>`)
    .replace(/<meta name="description" content="[^"]*" \/>/, `<meta name="description" content="${escapedDescription}" />`)
    .replace(/<meta property="og:title" content="[^"]*" \/>/, `<meta property="og:title" content="${escapedTitle}" />`)
    .replace(/<meta property="og:description" content="[^"]*" \/>/, `<meta property="og:description" content="${escapedDescription}" />`)
    .replace(/<meta name="twitter:title" content="[^"]*" \/>/, `<meta name="twitter:title" content="${escapedTitle}" />`)
    .replace(/<meta name="twitter:description" content="[^"]*" \/>/, `<meta name="twitter:description" content="${escapedDescription}" />`)
    .replace(
      /(<meta property="og:description" content="[^"]*" \/>)/,
      `$1\n    <link rel="canonical" href="${baseUrl}/${lang}" />\n    ${alternateLinks()}`,
    );
}

const template = readFileSync(join(distDir, "index.html"), "utf8");

for (const lang of langs) {
  const langDir = join(distDir, lang);
  mkdirSync(langDir, { recursive: true });
  writeFileSync(join(langDir, "index.html"), renderHtml(template, lang));
}

writeFileSync(join(distDir, "index.html"), renderHtml(template, "en"));

const sitemapUrls = langs
  .map((lang) => {
    const alternates = langs
      .map((alternate) => `    <xhtml:link rel="alternate" hreflang="${alternate}" href="${baseUrl}/${alternate}" />`)
      .join("\n");
    return `  <url>
    <loc>${baseUrl}/${lang}</loc>
${alternates}
    <xhtml:link rel="alternate" hreflang="x-default" href="${baseUrl}/en" />
  </url>`;
  })
  .join("\n");

writeFileSync(
  join(distDir, "sitemap.xml"),
  `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
${sitemapUrls}
</urlset>
`,
);

writeFileSync(
  join(distDir, "robots.txt"),
  `User-agent: *
Allow: /

Sitemap: ${baseUrl}/sitemap.xml
`,
);

copyFileSync(join(distDir, "en", "index.html"), join(distDir, "404.html"));
