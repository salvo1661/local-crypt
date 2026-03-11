import { useState, useRef, useCallback, useMemo, useEffect } from "react";
import CryptoJS from "crypto-js";
import { createMessage, decrypt, encrypt, enums, readMessage, type PartialConfig } from "openpgp";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import {
  Lock, Unlock, Copy, Download, Upload, Shield, FileText, Hash,
  Eye, EyeOff, RefreshCw, Trash2, ArrowRightLeft, Globe, Github, Star, ExternalLink,
} from "lucide-react";
import { detectLang, getTranslations, LANG_LABELS, type Lang } from "@/lib/i18n";

type HashAlgo = "MD5" | "SHA-1" | "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512" | "SHA-3" | "RIPEMD160";
type PgpSymmetricAlgo = "aes128" | "aes192" | "aes256" | "tripledes" | "cast5" | "blowfish" | "twofish" | "idea";
type PgpHashAlgo = "sha256" | "sha384" | "sha512" | "sha224" | "sha3_256" | "sha3_512" | "sha1" | "md5" | "ripemd";
type PgpS2kType = "iterated" | "argon2";

const HASH_ALGOS: HashAlgo[] = ["MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-3", "RIPEMD160"];
const HASH_IMPL: Record<HashAlgo, "MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "SHA3" | "RIPEMD160"> = {
  MD5: "MD5",
  "SHA-1": "SHA1",
  "SHA-224": "SHA224",
  "SHA-256": "SHA256",
  "SHA-384": "SHA384",
  "SHA-512": "SHA512",
  "SHA-3": "SHA3",
  RIPEMD160: "RIPEMD160",
};
const LANGS: Lang[] = ["en", "ko", "ja", "zh", "es", "fr", "de", "id", "ar"];
const PGP_SYMMETRIC_ALGOS: PgpSymmetricAlgo[] = ["aes128", "aes192", "aes256", "tripledes", "cast5", "blowfish", "twofish", "idea"];
const PGP_HASH_ALGOS: PgpHashAlgo[] = ["sha256", "sha384", "sha512", "sha224", "sha3_256", "sha3_512", "sha1", "md5", "ripemd"];
const PGP_S2K_TYPES: PgpS2kType[] = ["iterated", "argon2"];
const SITE_META: Record<Lang, { title: string; description: string }> = {
  en: {
    title: "Secure Handy Safe | On-Device Encryption",
    description: "On-device encryption tool with no server upload. Uses PGP-compatible symmetric encryption format.",
  },
  ko: {
    title: "Secure Handy Safe | 온디바이스 암호화",
    description: "서버 업로드 없이 브라우저에서만 동작하는 온디바이스 암호화 도구. PGP 호환 대칭 암호화 포맷을 사용합니다.",
  },
  ja: {
    title: "Secure Handy Safe | オンデバイス暗号化",
    description: "サーバーへアップロードせず、ブラウザ内だけで動作するオンデバイス暗号化ツール。PGP互換の共通鍵暗号化フォーマットを使用。",
  },
  zh: {
    title: "Secure Handy Safe | 设备端加密",
    description: "无需上传到服务器，仅在浏览器本地运行的设备端加密工具。使用 PGP 兼容的对称加密格式。",
  },
  es: {
    title: "Secure Handy Safe | Cifrado en el dispositivo",
    description: "Herramienta de cifrado en el dispositivo sin subida al servidor. Usa formato de cifrado simétrico compatible con PGP.",
  },
  fr: {
    title: "Secure Handy Safe | Chiffrement sur appareil",
    description: "Outil de chiffrement local sans envoi au serveur. Utilise un format de chiffrement symétrique compatible PGP.",
  },
  de: {
    title: "Secure Handy Safe | On-Device-Verschlüsselung",
    description: "On-Device-Verschlüsselungstool ohne Server-Upload. Verwendet ein PGP-kompatibles symmetrisches Verschlüsselungsformat.",
  },
  id: {
    title: "Secure Handy Safe | Enkripsi di Perangkat",
    description: "Alat enkripsi di perangkat tanpa unggah ke server. Menggunakan format enkripsi simetris yang kompatibel dengan PGP.",
  },
  ar: {
    title: "Secure Handy Safe | تشفير على الجهاز",
    description: "أداة تشفير تعمل على الجهاز بدون رفع إلى الخادم. تستخدم تنسيق تشفير متماثل متوافقًا مع PGP.",
  },
};

function hashText(algo: HashAlgo, text: string): string {
  return CryptoJS[HASH_IMPL[algo]](text).toString();
}

async function encryptTextPgp(text: string, passphrase: string, config: PartialConfig): Promise<string> {
  const message = await createMessage({ text });
  return encrypt({
    message,
    passwords: [passphrase],
    format: "armored",
    config,
  });
}

async function decryptTextPgp(armored: string, passphrase: string, config: PartialConfig): Promise<string> {
  const message = await readMessage({ armoredMessage: armored });
  const result = await decrypt({
    message,
    passwords: [passphrase],
    format: "utf8",
    config,
  });
  return result.data;
}

async function encryptBinaryPgp(data: Uint8Array, passphrase: string, config: PartialConfig): Promise<string> {
  const message = await createMessage({ binary: data });
  return encrypt({
    message,
    passwords: [passphrase],
    format: "armored",
    config,
  });
}

async function decryptBinaryPgp(armored: string, passphrase: string, config: PartialConfig): Promise<Uint8Array> {
  const message = await readMessage({ armoredMessage: armored });
  const result = await decrypt({
    message,
    passwords: [passphrase],
    format: "binary",
    config,
  });
  return result.data;
}

const Index = () => {
  const [lang, setLang] = useState<Lang>(detectLang);
  const i = useMemo(() => getTranslations(lang), [lang]);
  const [pgpSymmetricAlgo, setPgpSymmetricAlgo] = useState<PgpSymmetricAlgo>("aes256");
  const [pgpHashAlgo, setPgpHashAlgo] = useState<PgpHashAlgo>("sha512");
  const [pgpS2kType, setPgpS2kType] = useState<PgpS2kType>("iterated");
  const [pgpS2kIterationCountByte, setPgpS2kIterationCountByte] = useState<number>(224);

  useEffect(() => {
    const meta = SITE_META[lang];
    document.title = meta.title;

    const upsertMeta = (
      attr: "name" | "property",
      key: string,
      content: string,
    ) => {
      let tag = document.querySelector(`meta[${attr}="${key}"]`) as HTMLMetaElement | null;
      if (!tag) {
        tag = document.createElement("meta");
        tag.setAttribute(attr, key);
        document.head.appendChild(tag);
      }
      tag.setAttribute("content", content);
    };

    upsertMeta("name", "description", meta.description);
    upsertMeta("property", "og:title", meta.title);
    upsertMeta("property", "og:description", meta.description);
    upsertMeta("name", "twitter:title", meta.title);
    upsertMeta("name", "twitter:description", meta.description);
  }, [lang]);

  const [textInput, setTextInput] = useState("");
  const [textOutput, setTextOutput] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [hashAlgo, setHashAlgo] = useState<HashAlgo>("SHA-256");
  const [textMode, setTextMode] = useState<"encrypt" | "decrypt">("encrypt");

  const [file, setFile] = useState<File | null>(null);
  const [fileKey, setFileKey] = useState("");
  const [showFileKey, setShowFileKey] = useState(false);
  const [fileMode, setFileMode] = useState<"encrypt" | "decrypt">("encrypt");
  const [processing, setProcessing] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const pgpConfig = useMemo<PartialConfig>(() => {
    const cfg: PartialConfig = {
      preferredSymmetricAlgorithm: enums.symmetric[pgpSymmetricAlgo],
      s2kType: enums.s2k[pgpS2kType],
    };
    if (pgpS2kType === "iterated") {
      cfg.preferredHashAlgorithm = enums.hash[pgpHashAlgo];
      cfg.s2kIterationCountByte = Math.max(0, Math.min(255, Number.isFinite(pgpS2kIterationCountByte) ? Math.trunc(pgpS2kIterationCountByte) : 224));
    }
    return cfg;
  }, [pgpSymmetricAlgo, pgpHashAlgo, pgpS2kType, pgpS2kIterationCountByte]);

  const handleTextProcess = useCallback(async () => {
    if (!textInput.trim()) { toast.error(i.errorNoText); return; }
    if (!secretKey.trim()) { toast.error(i.errorNoKey); return; }
    try {
      const result = textMode === "encrypt"
        ? await encryptTextPgp(textInput, secretKey, pgpConfig)
        : await decryptTextPgp(textInput, secretKey, pgpConfig);
      setTextOutput(result);
      toast.success(textMode === "encrypt" ? i.encryptSuccess : i.decryptSuccess);
    } catch {
      toast.error(i.errorProcess);
    }
  }, [textInput, secretKey, textMode, pgpConfig, i]);

  const handleCopy = useCallback(() => {
    if (!textOutput) return;
    navigator.clipboard.writeText(textOutput);
    toast.success(i.copied);
  }, [textOutput, i]);

  const handleFileProcess = useCallback(async () => {
    if (!file) { toast.error(i.errorFile); return; }
    if (!fileKey.trim()) { toast.error(i.errorNoKey); return; }
    setProcessing(true);
    try {
      if (fileMode === "encrypt") {
        const data = new Uint8Array(await file.arrayBuffer());
        const armored = await encryptBinaryPgp(data, fileKey, pgpConfig);
        const blob = new Blob([armored], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = file.name + ".pgp"; a.click();
        URL.revokeObjectURL(url);
        toast.success(i.encryptFileSuccess);
      } else {
        const armored = (await file.text()).trim();
        const decrypted = await decryptBinaryPgp(armored, fileKey, pgpConfig);
        const blob = new Blob([decrypted]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = file.name.replace(/\.pgp$/, ""); a.click();
        URL.revokeObjectURL(url);
        toast.success(i.decryptFileSuccess);
      }
    } catch {
      toast.error(i.errorFileProcess);
    }
    setProcessing(false);
  }, [file, fileKey, fileMode, pgpConfig, i]);

  const generateRandomKey = (setter: (v: string) => void) => {
    setter(CryptoJS.lib.WordArray.random(32).toString());
    toast.success(i.randomKeySuccess);
  };

  const swapTextIO = () => {
    setTextInput(textOutput);
    setTextOutput("");
    setTextMode(textMode === "encrypt" ? "decrypt" : "encrypt");
  };

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border bg-card/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 py-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight font-mono">CryptoForge</h1>
            <p className="text-xs text-muted-foreground">{i.subtitle}</p>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground bg-muted px-3 py-1.5 rounded-full">
              <Lock className="h-3 w-3" />
              {i.localBadge}
            </div>
            <Select value={lang} onValueChange={(v) => setLang(v as Lang)}>
              <SelectTrigger className="w-[130px] h-8 text-xs">
                <Globe className="h-3.5 w-3.5 mr-1.5" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LANGS.map((l) => (
                  <SelectItem key={l} value={l}>{LANG_LABELS[l]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8">
        <Tabs defaultValue="text" className="space-y-6">
          <TabsList className="grid w-full max-w-md mx-auto grid-cols-3 h-12">
            <TabsTrigger value="text" className="gap-2 text-sm"><FileText className="h-4 w-4" /> {i.textTab}</TabsTrigger>
            <TabsTrigger value="file" className="gap-2 text-sm"><Upload className="h-4 w-4" /> {i.fileTab}</TabsTrigger>
            <TabsTrigger value="hash" className="gap-2 text-sm"><Hash className="h-4 w-4" /> {i.hashTab}</TabsTrigger>
          </TabsList>

          {/* TEXT TAB */}
          <TabsContent value="text" className="space-y-4">
            <Tabs value={textMode} onValueChange={(v) => setTextMode(v as "encrypt" | "decrypt")} className="space-y-4">
              <TabsList className="grid w-full max-w-xs mx-auto grid-cols-2 h-11">
                <TabsTrigger value="encrypt" className="gap-2 text-sm font-semibold"><Lock className="h-4 w-4" /> {i.encrypt}</TabsTrigger>
                <TabsTrigger value="decrypt" className="gap-2 text-sm font-semibold"><Unlock className="h-4 w-4" /> {i.decrypt}</TabsTrigger>
              </TabsList>

              <div className="grid md:grid-cols-[280px_1fr] gap-4">
                <Card>
                  <CardHeader className="pb-3"><CardTitle className="text-base">{i.settings}</CardTitle></CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label>PGP Symmetric Algorithm</Label>
                      <Select value={pgpSymmetricAlgo} onValueChange={(v) => setPgpSymmetricAlgo(v as PgpSymmetricAlgo)}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>{PGP_SYMMETRIC_ALGOS.map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}</SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>S2K Type</Label>
                      <Select value={pgpS2kType} onValueChange={(v) => setPgpS2kType(v as PgpS2kType)}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>{PGP_S2K_TYPES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent>
                      </Select>
                    </div>
                    {pgpS2kType === "iterated" ? (
                      <>
                        <div className="space-y-2">
                          <Label>PGP Hash Algorithm</Label>
                          <Select value={pgpHashAlgo} onValueChange={(v) => setPgpHashAlgo(v as PgpHashAlgo)}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>{PGP_HASH_ALGOS.map((h) => <SelectItem key={h} value={h}>{h}</SelectItem>)}</SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2">
                          <Label>S2K Iteration Count Byte (0-255)</Label>
                          <Input
                            type="number"
                            min={0}
                            max={255}
                            value={pgpS2kIterationCountByte}
                            onChange={(e) => setPgpS2kIterationCountByte(Number(e.target.value))}
                            className="font-mono text-xs"
                          />
                        </div>
                      </>
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        Argon2 uses built-in params from OpenPGP config; iterated-only fields are hidden.
                      </p>
                    )}
                    <div className="space-y-2">
                      <Label>{i.secretKey}</Label>
                      <div className="flex gap-1">
                        <div className="relative flex-1">
                          <Input type={showKey ? "text" : "password"} value={secretKey} onChange={(e) => setSecretKey(e.target.value)} placeholder={i.keyPlaceholder} className="pr-9 font-mono text-xs" />
                          <button type="button" onClick={() => setShowKey(!showKey)} className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                            {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                          </button>
                        </div>
                        <Button variant="outline" size="icon" onClick={() => generateRandomKey(setSecretKey)} title={i.randomKey}><RefreshCw className="h-4 w-4" /></Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <div className="space-y-4">
                  <Card>
                    <CardHeader className="pb-2 flex-row items-center justify-between">
                      <CardTitle className="text-base">{i.input}</CardTitle>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="icon" onClick={swapTextIO} title={i.swapIO}><ArrowRightLeft className="h-4 w-4" /></Button>
                        <Button variant="ghost" size="icon" onClick={() => { setTextInput(""); setTextOutput(""); }} title={i.clear}><Trash2 className="h-4 w-4" /></Button>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <Textarea value={textInput} onChange={(e) => setTextInput(e.target.value)} placeholder={textMode === "decrypt" ? i.pasteEncrypted : i.enterText} className="font-mono text-sm min-h-[140px] resize-y" />
                    </CardContent>
                  </Card>
                  <Button onClick={handleTextProcess} className="w-full h-11 gap-2 font-semibold">
                    {textMode === "encrypt" ? <Lock className="h-4 w-4" /> : <Unlock className="h-4 w-4" />}
                    {textMode === "encrypt" ? i.encryptBtn : i.decryptBtn}
                  </Button>
                  <Card>
                    <CardHeader className="pb-2 flex-row items-center justify-between">
                      <CardTitle className="text-base">{i.output}</CardTitle>
                      <Button variant="ghost" size="icon" onClick={handleCopy} disabled={!textOutput} title={i.copy}><Copy className="h-4 w-4" /></Button>
                    </CardHeader>
                    <CardContent>
                      <Textarea readOnly value={textOutput} placeholder={i.resultPlaceholder} className="font-mono text-sm min-h-[140px] resize-y bg-muted/50" />
                    </CardContent>
                  </Card>
                </div>
              </div>
            </Tabs>
          </TabsContent>

          {/* FILE TAB */}
          <TabsContent value="file" className="space-y-4">
            <Tabs value={fileMode} onValueChange={(v) => setFileMode(v as "encrypt" | "decrypt")} className="space-y-4">
              <TabsList className="grid w-full max-w-xs mx-auto grid-cols-2 h-11">
                <TabsTrigger value="encrypt" className="gap-2 text-sm font-semibold"><Lock className="h-4 w-4" /> {i.encrypt}</TabsTrigger>
                <TabsTrigger value="decrypt" className="gap-2 text-sm font-semibold"><Unlock className="h-4 w-4" /> {i.decrypt}</TabsTrigger>
              </TabsList>
            <Card className="max-w-2xl mx-auto">
              <CardHeader>
                <CardTitle className="text-lg">{i.fileTitle}</CardTitle>
                <CardDescription>Select a file to encrypt/decrypt with PGP-compatible format (.pgp).</CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="space-y-2">
                  <Label>PGP Symmetric Algorithm</Label>
                  <Select value={pgpSymmetricAlgo} onValueChange={(v) => setPgpSymmetricAlgo(v as PgpSymmetricAlgo)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>{PGP_SYMMETRIC_ALGOS.map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>S2K Type</Label>
                  <Select value={pgpS2kType} onValueChange={(v) => setPgpS2kType(v as PgpS2kType)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>{PGP_S2K_TYPES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
                {pgpS2kType === "iterated" ? (
                  <>
                    <div className="space-y-2">
                      <Label>PGP Hash Algorithm</Label>
                      <Select value={pgpHashAlgo} onValueChange={(v) => setPgpHashAlgo(v as PgpHashAlgo)}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>{PGP_HASH_ALGOS.map((h) => <SelectItem key={h} value={h}>{h}</SelectItem>)}</SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>S2K Iteration Count Byte (0-255)</Label>
                      <Input
                        type="number"
                        min={0}
                        max={255}
                        value={pgpS2kIterationCountByte}
                        onChange={(e) => setPgpS2kIterationCountByte(Number(e.target.value))}
                        className="font-mono text-xs"
                      />
                    </div>
                  </>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    Argon2 uses built-in params from OpenPGP config; iterated-only fields are hidden.
                  </p>
                )}
                <div className="space-y-2">
                  <Label>{i.secretKey}</Label>
                  <div className="flex gap-1">
                    <div className="relative flex-1">
                      <Input type={showFileKey ? "text" : "password"} value={fileKey} onChange={(e) => setFileKey(e.target.value)} placeholder={i.keyPlaceholder} className="pr-9 font-mono text-xs" />
                      <button type="button" onClick={() => setShowFileKey(!showFileKey)} className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                        {showFileKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                    <Button variant="outline" size="icon" onClick={() => generateRandomKey(setFileKey)}><RefreshCw className="h-4 w-4" /></Button>
                  </div>
                </div>
                <div
                  className="border-2 border-dashed border-border rounded-xl p-8 text-center cursor-pointer hover:border-primary/50 hover:bg-primary/5 transition-colors"
                  onClick={() => fileInputRef.current?.click()}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) setFile(f); }}
                >
                  <input ref={fileInputRef} type="file" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) setFile(f); }} />
                  <Upload className="h-10 w-10 mx-auto mb-3 text-muted-foreground" />
                  {file ? (
                    <div>
                      <p className="font-medium text-sm">{file.name}</p>
                      <p className="text-xs text-muted-foreground mt-1">{(file.size / 1024).toFixed(1)} KB</p>
                    </div>
                  ) : (
                    <div>
                      <p className="text-sm font-medium">{i.dropFile}</p>
                      <p className="text-xs text-muted-foreground mt-1">{i.allFormats}</p>
                    </div>
                  )}
                </div>
                <Button onClick={handleFileProcess} disabled={processing || !file} className="w-full h-11 gap-2 font-semibold">
                  {processing ? <RefreshCw className="h-4 w-4 animate-spin" /> : fileMode === "encrypt" ? <Lock className="h-4 w-4" /> : <Download className="h-4 w-4" />}
                  {processing ? i.processing : fileMode === "encrypt" ? i.encryptDownload : i.decryptDownload}
                </Button>
              </CardContent>
            </Card>
            </Tabs>
          </TabsContent>

          {/* HASH TAB */}
          <TabsContent value="hash" className="space-y-4">
            <Card className="max-w-2xl mx-auto">
              <CardHeader>
                <CardTitle className="text-lg">{i.hashTitle}</CardTitle>
                <CardDescription>{i.hashDesc}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>{i.hashAlgo}</Label>
                  <Select value={hashAlgo} onValueChange={(v) => setHashAlgo(v as HashAlgo)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>{HASH_ALGOS.map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>{i.hashInput}</Label>
                  <Textarea value={textInput} onChange={(e) => setTextInput(e.target.value)} placeholder={i.hashPlaceholder} className="font-mono text-sm min-h-[120px]" />
                </div>
                <Button onClick={() => { if (!textInput.trim()) { toast.error(i.errorNoText); return; } setTextOutput(hashText(hashAlgo, textInput)); toast.success(i.hashSuccess); }} className="w-full h-11 gap-2 font-semibold">
                  <Hash className="h-4 w-4" /> {i.hashBtn}
                </Button>
                {textOutput && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label>{i.output}</Label>
                      <Button variant="ghost" size="sm" onClick={handleCopy} className="gap-1 h-7 text-xs"><Copy className="h-3 w-3" /> {i.copy}</Button>
                    </div>
                    <div className="p-3 rounded-lg bg-muted font-mono text-xs break-all select-all">{textOutput}</div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        <div className="mt-12 text-center text-xs text-muted-foreground space-y-1">
          <p>{i.footer1}</p>
          <p className="font-mono">{i.footer2}</p>
          <div className="pt-3 flex flex-wrap justify-center gap-2">
            <a
              href="https://github.com/salvo1661/local-crypt"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-full border border-border px-3 py-1.5 text-xs hover:bg-muted transition-colors"
            >
              <Github className="h-3.5 w-3.5" />
              <span>Open Source on GitHub</span>
              <ExternalLink className="h-3 w-3" />
            </a>
            <a
              href="https://leanvibe.io/vibe/secure-handy-safe-mmk5u1kz"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-full border border-border px-3 py-1.5 text-xs hover:bg-muted transition-colors"
            >
              <Star className="h-3.5 w-3.5" />
              <span>Recommended on LeanVibe</span>
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Index;
