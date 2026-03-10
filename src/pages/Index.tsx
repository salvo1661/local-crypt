import { useState, useRef, useCallback, useMemo, useEffect } from "react";
import CryptoJS from "crypto-js";
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
  Eye, EyeOff, RefreshCw, Trash2, ArrowRightLeft, Globe,
} from "lucide-react";
import { detectLang, getTranslations, LANG_LABELS, type Lang } from "@/lib/i18n";

type AesAlgo = "AES-128" | "AES-192" | "AES-256";
type CipherAlgo = AesAlgo | "TripleDES" | "Rabbit" | "RC4" | "RC4Drop";
type HashAlgo = "MD5" | "SHA-1" | "SHA-224" | "SHA-256" | "SHA-384" | "SHA-512" | "SHA-3" | "RIPEMD160";
type AesMode = "CBC" | "ECB" | "CFB" | "OFB" | "CTR";
type AesPadding = "Pkcs7" | "ZeroPadding" | "NoPadding";

const CIPHER_ALGOS: CipherAlgo[] = ["AES-128", "AES-192", "AES-256", "TripleDES", "Rabbit", "RC4", "RC4Drop"];
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
const AES_MODES: AesMode[] = ["CBC", "ECB", "CFB", "OFB", "CTR"];
const AES_PADDINGS: AesPadding[] = ["Pkcs7", "ZeroPadding", "NoPadding"];
const LANGS: Lang[] = ["en", "ko", "ja", "zh", "es", "fr", "de", "id", "ar"];
const SITE_META: Record<Lang, { title: string; description: string }> = {
  en: {
    title: "Secure Handy Safe | On-Device Encryption",
    description: "On-device encryption tool with no server upload. Supports AES-128, AES-192, AES-256, 3DES, Rabbit, RC4, and RC4Drop.",
  },
  ko: {
    title: "Secure Handy Safe | 온디바이스 암호화",
    description: "서버 업로드 없이 브라우저에서만 동작하는 온디바이스 암호화 도구. AES-128, AES-192, AES-256, 3DES, Rabbit, RC4, RC4Drop 지원.",
  },
  ja: {
    title: "Secure Handy Safe | オンデバイス暗号化",
    description: "サーバーへアップロードせず、ブラウザ内だけで動作するオンデバイス暗号化ツール。AES-128、AES-192、AES-256、3DES、Rabbit、RC4、RC4Dropに対応。",
  },
  zh: {
    title: "Secure Handy Safe | 设备端加密",
    description: "无需上传到服务器，仅在浏览器本地运行的设备端加密工具。支持 AES-128、AES-192、AES-256、3DES、Rabbit、RC4、RC4Drop。",
  },
  es: {
    title: "Secure Handy Safe | Cifrado en el dispositivo",
    description: "Herramienta de cifrado en el dispositivo sin subida al servidor. Compatible con AES-128, AES-192, AES-256, 3DES, Rabbit, RC4 y RC4Drop.",
  },
  fr: {
    title: "Secure Handy Safe | Chiffrement sur appareil",
    description: "Outil de chiffrement local sans envoi au serveur. Prend en charge AES-128, AES-192, AES-256, 3DES, Rabbit, RC4 et RC4Drop.",
  },
  de: {
    title: "Secure Handy Safe | On-Device-Verschlüsselung",
    description: "On-Device-Verschlüsselungstool ohne Server-Upload. Unterstützt AES-128, AES-192, AES-256, 3DES, Rabbit, RC4 und RC4Drop.",
  },
  id: {
    title: "Secure Handy Safe | Enkripsi di Perangkat",
    description: "Alat enkripsi di perangkat tanpa unggah ke server. Mendukung AES-128, AES-192, AES-256, 3DES, Rabbit, RC4, dan RC4Drop.",
  },
  ar: {
    title: "Secure Handy Safe | تشفير على الجهاز",
    description: "أداة تشفير تعمل على الجهاز بدون رفع إلى الخادم. تدعم AES-128 وAES-192 وAES-256 و3DES وRabbit وRC4 وRC4Drop.",
  },
};

const PBKDF2_ITERATIONS = 100_000;

/** 암호화 파라미터를 파일에 포함하는 메타데이터 구조 (표준 복호화 도구 호환용) */
interface CryptoMeta {
  v: 1;
  algo: CipherAlgo;
  mode: AesMode;
  padding: AesPadding;
  kdf: "PBKDF2";
  kdfHash: "SHA256";
  kdfIter: number;
  /** PBKDF2 salt — Base64 */
  salt: string;
  /** Block cipher IV — Base64, empty for ECB / stream ciphers */
  iv: string;
}

function isAesAlgo(algo: CipherAlgo): boolean {
  return algo.startsWith("AES-");
}

function isBlockCipher(algo: CipherAlgo): boolean {
  return isAesAlgo(algo) || algo === "TripleDES";
}

function getCipherImpl(algo: CipherAlgo): "AES" | "TripleDES" | "Rabbit" | "RC4" | "RC4Drop" {
  if (isAesAlgo(algo)) return "AES";
  return algo;
}

function getKeyWords(algo: CipherAlgo) {
  if (algo === "AES-128") return 128 / 32;
  if (algo === "AES-192") return 192 / 32;
  if (algo === "AES-256") return 256 / 32;
  if (algo === "TripleDES") return 192 / 32;
  return 128 / 32; // Rabbit, RC4, RC4Drop
}

function getIVBytes(algo: CipherAlgo, mode: AesMode): number {
  if (algo === "Rabbit" || algo === "RC4" || algo === "RC4Drop") return 0;
  if (mode === "ECB") return 0;
  return algo === "TripleDES" ? 8 : 16;
}

function deriveKey(passphrase: string, salt: CryptoJS.lib.WordArray, algo: CipherAlgo) {
  return CryptoJS.PBKDF2(passphrase, salt, {
    keySize: getKeyWords(algo),
    iterations: PBKDF2_ITERATIONS,
    hasher: CryptoJS.algo.SHA256,
  });
}

/**
 * 출력 형식: CFGE1:<base64(JSON meta)>:<base64(ciphertext)>
 * meta에 algo/mode/padding/kdf/salt/iv가 모두 포함되어 있어
 * OpenSSL·Python cryptography 등 표준 도구로 복호화 가능
 */
function encryptText(algo: CipherAlgo, text: string, passphrase: string, mode: AesMode, padding: AesPadding): string {
  const salt = CryptoJS.lib.WordArray.random(16);
  const ivBytes = getIVBytes(algo, mode);
  const iv = ivBytes > 0 ? CryptoJS.lib.WordArray.random(ivBytes) : null;
  const key = deriveKey(passphrase, salt, algo);

  const cfg: Record<string, unknown> = {};
  if (isBlockCipher(algo)) {
    cfg.mode = CryptoJS.mode[mode];
    cfg.padding = CryptoJS.pad[padding];
  }
  if (iv) cfg.iv = iv;

  const encrypted = CryptoJS[getCipherImpl(algo)].encrypt(text, key, cfg);
  const meta: CryptoMeta = {
    v: 1, algo, mode, padding,
    kdf: "PBKDF2", kdfHash: "SHA256", kdfIter: PBKDF2_ITERATIONS,
    salt: CryptoJS.enc.Base64.stringify(salt),
    iv: iv ? CryptoJS.enc.Base64.stringify(iv) : "",
  };
  return `CFGE1:${btoa(JSON.stringify(meta))}:${encrypted.ciphertext.toString(CryptoJS.enc.Base64)}`;
}

function decryptText(algo: CipherAlgo, ciphertext: string, passphrase: string, mode: AesMode, padding: AesPadding): string {
  if (!ciphertext.startsWith("CFGE1:")) throw new Error("Unsupported format");
  const parts = ciphertext.trim().split(":");
  if (parts.length !== 3) throw new Error("Invalid format");
  const meta: CryptoMeta = JSON.parse(atob(parts[1]));
  const salt = CryptoJS.enc.Base64.parse(meta.salt);
  const key = deriveKey(passphrase, salt, meta.algo);
  const cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Base64.parse(parts[2]),
  });
  const cfg: Record<string, unknown> = {};
  if (isBlockCipher(meta.algo)) {
    cfg.mode = CryptoJS.mode[meta.mode];
    cfg.padding = CryptoJS.pad[meta.padding];
  }
  if (meta.iv) cfg.iv = CryptoJS.enc.Base64.parse(meta.iv);
  const decrypted = CryptoJS[getCipherImpl(meta.algo)].decrypt(cipherParams, key, cfg);
  return decrypted.toString(CryptoJS.enc.Utf8);
}

function hashText(algo: HashAlgo, text: string): string {
  return CryptoJS[HASH_IMPL[algo]](text).toString();
}

function wordArrayToArrayBuffer(wordArray: CryptoJS.lib.WordArray): ArrayBuffer {
  const { words, sigBytes } = wordArray;
  const u8 = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i++) {
    u8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return u8.buffer;
}

const Index = () => {
  const [lang, setLang] = useState<Lang>(detectLang);
  const i = useMemo(() => getTranslations(lang), [lang]);

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
  const [cipherAlgo, setCipherAlgo] = useState<CipherAlgo>("AES-256");
  const [hashAlgo, setHashAlgo] = useState<HashAlgo>("SHA-256");
  const [aesMode, setAesMode] = useState<AesMode>("CBC");
  const [aesPadding, setAesPadding] = useState<AesPadding>("Pkcs7");
  const [textMode, setTextMode] = useState<"encrypt" | "decrypt">("encrypt");

  const [file, setFile] = useState<File | null>(null);
  const [fileAlgo, setFileAlgo] = useState<CipherAlgo>("AES-256");
  const [fileKey, setFileKey] = useState("");
  const [showFileKey, setShowFileKey] = useState(false);
  const [fileMode, setFileMode] = useState<"encrypt" | "decrypt">("encrypt");
  const [fileAesMode, setFileAesMode] = useState<AesMode>("CBC");
  const [fileAesPadding, setFileAesPadding] = useState<AesPadding>("Pkcs7");
  const [processing, setProcessing] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleTextProcess = useCallback(() => {
    if (!textInput.trim()) { toast.error(i.errorNoText); return; }
    if (!secretKey.trim()) { toast.error(i.errorNoKey); return; }
    try {
      let result: string;
      if (textMode === "encrypt") {
        result = encryptText(cipherAlgo, textInput, secretKey, aesMode, aesPadding);
      } else {
        result = decryptText(cipherAlgo, textInput, secretKey, aesMode, aesPadding);
        if (!result) throw new Error();
      }
      setTextOutput(result);
      toast.success(textMode === "encrypt" ? i.encryptSuccess : i.decryptSuccess);
    } catch {
      toast.error(i.errorProcess);
    }
  }, [textInput, secretKey, textMode, cipherAlgo, aesMode, aesPadding, i]);

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
      const reader = new FileReader();
      reader.onload = () => {
        try {
          if (fileMode === "encrypt") {
            // 파일 바이너리 → Base64 → PBKDF2 key 유도 → 암호화 → CFGE1 포맷으로 저장
            const wordArray = CryptoJS.lib.WordArray.create(reader.result as ArrayBuffer);
            const base64 = CryptoJS.enc.Base64.stringify(wordArray);
            const resultStr = encryptText(fileAlgo, base64, fileKey, fileAesMode, fileAesPadding);
            const blob = new Blob([resultStr], { type: "application/octet-stream" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url; a.download = file.name + ".enc"; a.click();
            URL.revokeObjectURL(url);
            toast.success(i.encryptFileSuccess);
          } else {
            // CFGE1 포맷 파싱 → PBKDF2 key 재유도 → 복호화 → 원본 바이너리 복원
            const ciphertext = (reader.result as string).trim();
            const decryptedBase64 = decryptText(fileAlgo, ciphertext, fileKey, fileAesMode, fileAesPadding);
            if (!decryptedBase64) throw new Error();
            const ab = wordArrayToArrayBuffer(CryptoJS.enc.Base64.parse(decryptedBase64));
            const blob = new Blob([ab]);
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url; a.download = file.name.replace(/\.enc$/, ""); a.click();
            URL.revokeObjectURL(url);
            toast.success(i.decryptFileSuccess);
          }
        } catch {
          toast.error(i.errorFileProcess);
        }
        setProcessing(false);
      };
      if (fileMode === "encrypt") reader.readAsArrayBuffer(file);
      else reader.readAsText(file);
    } catch {
      toast.error(i.errorFileRead);
      setProcessing(false);
    }
  }, [file, fileKey, fileAlgo, fileMode, fileAesMode, fileAesPadding, i]);

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
                      <Label>{i.algorithm}</Label>
                      <Select value={cipherAlgo} onValueChange={(v) => setCipherAlgo(v as CipherAlgo)}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>{CIPHER_ALGOS.map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}</SelectContent>
                      </Select>
                    </div>
                    {(isAesAlgo(cipherAlgo) || cipherAlgo === "TripleDES") && (
                      <>
                        <div className="space-y-2">
                          <Label>{i.blockMode}</Label>
                          <Select value={aesMode} onValueChange={(v) => setAesMode(v as AesMode)}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>{AES_MODES.map((m) => <SelectItem key={m} value={m}>{m}</SelectItem>)}</SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2">
                          <Label>{i.padding}</Label>
                          <Select value={aesPadding} onValueChange={(v) => setAesPadding(v as AesPadding)}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>{AES_PADDINGS.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}</SelectContent>
                          </Select>
                        </div>
                      </>
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
                <CardDescription>{i.fileDesc}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="space-y-2">
                  <Label>{i.algorithm}</Label>
                  <Select value={fileAlgo} onValueChange={(v) => setFileAlgo(v as CipherAlgo)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>{CIPHER_ALGOS.map((a) => <SelectItem key={a} value={a}>{a}</SelectItem>)}</SelectContent>
                  </Select>
                </div>
                {(isAesAlgo(fileAlgo) || fileAlgo === "TripleDES") && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <Label>{i.blockMode}</Label>
                      <Select value={fileAesMode} onValueChange={(v) => setFileAesMode(v as AesMode)}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>{AES_MODES.map((m) => <SelectItem key={m} value={m}>{m}</SelectItem>)}</SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>{i.padding}</Label>
                      <Select value={fileAesPadding} onValueChange={(v) => setFileAesPadding(v as AesPadding)}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>{AES_PADDINGS.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}</SelectContent>
                      </Select>
                    </div>
                  </div>
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
        </div>
      </main>
    </div>
  );
};

export default Index;
