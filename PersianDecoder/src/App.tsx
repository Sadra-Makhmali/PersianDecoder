import { useState } from 'react';
import { Lock, Unlock, Check, Shield, Wifi, WifiOff, Zap, ClipboardPaste, Copy, Key, ToggleLeft, ToggleRight } from 'lucide-react';
import * as pako from 'pako';

interface CopyState {
  [key: string]: boolean;
}

function App() {
  const [encodeInput, setEncodeInput] = useState('');
  const [encodeOutput, setEncodeOutput] = useState('');
  const [decodeInput, setDecodeInput] = useState('');
  const [decodeOutput, setDecodeOutput] = useState('');
  const [copied, setCopied] = useState<CopyState>({});
  const [customProtocol, setCustomProtocol] = useState(false);
  const [encodeKey, setEncodeKey] = useState('');
  const [decodeKey, setDecodeKey] = useState('');

  const base64Chars = 'ابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی۰۱۲۳۴۵۶۷۸۹آabcdefghijklmnopqrstuv';

  const charToIndex: Record<string, number> = {};
  for (let i = 0; i < base64Chars.length; i++) {
    charToIndex[base64Chars[i]] = i;
  }

  const normalizeInput = (text: string): string => {
    let normalized = text.normalize('NFC');

    const replacements: Record<string, string> = {
      'ي': 'ی',
      'ى': 'ی',
      'ك': 'ک',
      'أ': 'ا',
      'إ': 'ا',
      'ٱ': 'ا',
      'ٲ': 'آ',
      'ؤ': 'و',
      'ئ': 'ی',
      'ة': 'ه',
      'ء': 'ا',
      'ـ': '',
      'ً': '',
      'ٌ': '',
      'ٍ': '',
      'َ': '',
      'ُ': '',
      'ِ': '',
      'ّ': '',
      'ْ': '',
      'ٓ': '',
      'ٔ': ''
    };

    for (const [from, to] of Object.entries(replacements)) {
      normalized = normalized.replace(new RegExp(from, 'g'), to);
    }

    normalized = normalized.replace(/\s+/g, '');

    return normalized;
  };

  const validateEncodedText = (text: string): { isValid: boolean; invalidChars: string[] } => {
    const normalized = normalizeInput(text);
    const invalidChars = new Set<string>();

    for (const char of normalized) {
      if (!base64Chars.includes(char)) {
        invalidChars.add(char);
      }
    }

    return {
      isValid: invalidChars.size === 0,
      invalidChars: Array.from(invalidChars)
    };
  };

  const xorEncrypt = (text: string, key: string): string => {
    let result = '';
    for (let i = 0; i < text.length; i++) {
      const charCode = text.charCodeAt(i);
      const keyCode = key.charCodeAt(i % key.length);
      result += String.fromCharCode(charCode ^ keyCode);
    }
    return result;
  };

  const rot13 = (text: string): string => {
    return text.replace(/[a-zA-Z]/g, (char) => {
      const base = char <= 'Z' ? 65 : 97;
      return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
    });
  };

  const reverseString = (text: string): string => {
    return text.split('').reverse().join('');
  };

  const caesarShift = (text: string, shift: number): string => {
    return text.split('').map(char => {
      const code = char.charCodeAt(0);
      return String.fromCharCode(code + shift);
    }).join('');
  };

  const bytesToBase64Persian = (bytes: Uint8Array): string => {
    let result = '';
    for (let i = 0; i < bytes.length; i += 3) {
      const b1 = bytes[i];
      const b2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
      const b3 = i + 2 < bytes.length ? bytes[i + 2] : 0;

      result += base64Chars[b1 >> 2];
      result += base64Chars[((b1 & 3) << 4) | (b2 >> 4)];
      result += i + 1 < bytes.length ? base64Chars[((b2 & 15) << 2) | (b3 >> 6)] : '';
      result += i + 2 < bytes.length ? base64Chars[b3 & 63] : '';
    }
    return result;
  };

  const base64PersianToBytes = (str: string): Uint8Array => {
    const len = str.length;
    const bytes: number[] = [];

    for (let i = 0; i < len; i += 4) {
      const c1 = charToIndex[str[i]] ?? 0;
      const c2 = charToIndex[str[i + 1]] ?? 0;
      const c3 = i + 2 < len ? (charToIndex[str[i + 2]] ?? 0) : 0;
      const c4 = i + 3 < len ? (charToIndex[str[i + 3]] ?? 0) : 0;

      bytes.push((c1 << 2) | (c2 >> 4));

      if (i + 2 < len) {
        bytes.push(((c2 & 15) << 4) | (c3 >> 2));
      }

      if (i + 3 < len) {
        bytes.push(((c3 & 3) << 6) | c4);
      }
    }

    return new Uint8Array(bytes);
  };

  const deriveKeyHash = (key: string): number => {
    let hash = 0;
    for (let i = 0; i < key.length; i++) {
      const char = key.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash);
  };

  const encode = (text: string, userKey?: string): string => {
    let method: number;
    let processed = text;

    if (userKey) {
      const keyHash = deriveKeyHash(userKey);
      method = (keyHash % 15) + 1;
      processed = xorEncrypt(text, userKey);
      processed = caesarShift(processed, method);
      processed = xorEncrypt(processed, `${userKey}${method}سفارشی`);
    } else {
      method = Math.floor(Math.random() * 15) + 1;

      switch (method) {
        case 1:
        case 2:
        case 3:
          processed = xorEncrypt(text, `کلید${method}امن`);
          break;
        case 4:
        case 5:
          processed = rot13(text);
          processed = xorEncrypt(processed, `رمز${method}`);
          break;
        case 6:
        case 7:
          processed = reverseString(text);
          processed = xorEncrypt(processed, `پنهان${method}`);
          break;
        case 8:
        case 9:
          processed = caesarShift(text, method);
          processed = xorEncrypt(processed, `امنیت${method}`);
          break;
        case 10:
        case 11:
          processed = rot13(reverseString(text));
          processed = xorEncrypt(processed, `محرمانه${method}`);
          break;
        case 12:
        case 13:
          processed = caesarShift(reverseString(text), method);
          processed = xorEncrypt(processed, `حفاظت${method}`);
          break;
        case 14:
        case 15:
          processed = reverseString(rot13(caesarShift(text, method)));
          processed = xorEncrypt(processed, `قفل${method}`);
          break;
      }
    }

    const encoder = new TextEncoder();
    const bytes = encoder.encode(processed);
    const compressed = pako.deflate(bytes);

    const isCustom = userKey ? 128 : 0;
    const methodByte = new Uint8Array([method | isCustom]);
    const combined = new Uint8Array(methodByte.length + compressed.length);
    combined.set(methodByte, 0);
    combined.set(compressed, methodByte.length);

    return bytesToBase64Persian(combined);
  };

  const decode = (persian: string, userKey?: string): string => {
    try {
      const normalized = normalizeInput(persian);
      const combined = base64PersianToBytes(normalized);

      if (combined.length < 2) return '';

      const methodByte = combined[0];
      const isCustom = (methodByte & 128) !== 0;
      const method = methodByte & 127;
      if (method < 1 || method > 15) return '';

      if (isCustom && !userKey) {
        return 'NEEDS_KEY';
      }

      if (!isCustom && userKey) {
        return 'PUBLIC_CONTENT';
      }

      const compressed = combined.slice(1);
      const decompressed = pako.inflate(compressed);
      const decoder = new TextDecoder();
      let decrypted = decoder.decode(decompressed);

      if (isCustom && userKey) {
        decrypted = xorEncrypt(decrypted, `${userKey}${method}سفارشی`);
        decrypted = caesarShift(decrypted, -method);
        decrypted = xorEncrypt(decrypted, userKey);
      } else {
        switch (method) {
          case 1:
          case 2:
          case 3:
            decrypted = xorEncrypt(decrypted, `کلید${method}امن`);
            break;
          case 4:
          case 5:
            decrypted = xorEncrypt(decrypted, `رمز${method}`);
            decrypted = rot13(decrypted);
            break;
          case 6:
          case 7:
            decrypted = xorEncrypt(decrypted, `پنهان${method}`);
            decrypted = reverseString(decrypted);
            break;
          case 8:
          case 9:
            decrypted = xorEncrypt(decrypted, `امنیت${method}`);
            decrypted = caesarShift(decrypted, -method);
            break;
          case 10:
          case 11:
            decrypted = xorEncrypt(decrypted, `محرمانه${method}`);
            decrypted = reverseString(rot13(decrypted));
            break;
          case 12:
          case 13:
            decrypted = xorEncrypt(decrypted, `حفاظت${method}`);
            decrypted = reverseString(caesarShift(decrypted, -method));
            break;
          case 14:
          case 15:
            decrypted = xorEncrypt(decrypted, `قفل${method}`);
            decrypted = caesarShift(rot13(reverseString(decrypted)), -method);
            break;
        }
      }

      return decrypted;
    } catch {
      return '';
    }
  };

  const handleEncode = () => {
    if (!encodeInput.trim()) {
      setEncodeOutput('');
      return;
    }

    if (encodeInput.length > 500) {
      alert('محتوا نباید بیشتر از ۵۰۰ کاراکتر باشد');
      return;
    }

    if (customProtocol && !encodeKey.trim()) {
      alert('لطفا کلید شخصی خود را وارد کنید');
      return;
    }

    const encoded = encode(encodeInput, customProtocol ? encodeKey : undefined);
    setEncodeOutput(encoded);
  };

  const handleDecode = () => {
    if (!decodeInput.trim()) {
      setDecodeOutput('');
      return;
    }

    const cleanedInput = decodeInput.trim();

    const validation = validateEncodedText(cleanedInput);
    if (!validation.isValid) {
      const invalidCharsDisplay = validation.invalidChars.slice(0, 5).map(c => `"${c}"`).join(', ');
      const moreChars = validation.invalidChars.length > 5 ? ` و ${validation.invalidChars.length - 5} کاراکتر دیگر` : '';
      setDecodeOutput(`خطا: محتوا شامل کاراکترهای نامعتبر است: ${invalidCharsDisplay}${moreChars}\n\nلطفا مطمئن شوید که محتوا را به طور کامل کپی کرده‌اید و هنگام paste هیچ کاراکتر اضافی وارد نشده است.`);
      return;
    }

    const decoded = decode(cleanedInput, customProtocol ? decodeKey : undefined);

    if (decoded === 'NEEDS_KEY') {
      if (!customProtocol) {
        setDecodeOutput('خطا: این محتوا با کلید شخصی رمزنگاری شده است.\n\nبرای رمزگشایی این محتوا، ابتدا پروتکل اختصاصی کاربر را فعال کنید و کلید شخصی را وارد نمایید.');
      } else if (!decodeKey) {
        setDecodeOutput('خطا: این محتوا با کلید شخصی رمزنگاری شده است.\n\nلطفا کلید شخصی را در فیلد مربوطه وارد کنید و دوباره تلاش کنید.');
      }
      return;
    }

    if (decoded === 'PUBLIC_CONTENT') {
      setDecodeOutput('خطا: این محتوا با رمزنگاری عمومی ایجاد شده است.\n\nبرای رمزگشایی این محتوا، پروتکل اختصاصی کاربر را غیرفعال کنید و در حالت عمومی رمزگشایی نمایید.');
      return;
    }

    if (!decoded) {
      if (customProtocol && decodeKey) {
        setDecodeOutput('خطا: کلید شخصی نادرست است یا محتوا آسیب دیده.\n\nلطفا کلید را بررسی کنید و مجددا تلاش کنید.');
      } else {
        setDecodeOutput('خطا: رمزگشایی ناموفق بود. احتمالاً محتوا آسیب دیده یا ناقص است.\n\nراهنمایی:\n• مطمئن شوید که تمام محتوا کپی شده است\n• از copy/paste مستقیم استفاده کنید (نه تایپ دستی)\n• محتوا را در یک خط بدون فاصله قرار دهید');
      }
      return;
    }

    setDecodeOutput(decoded);
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied({ ...copied, [key]: true });
    setTimeout(() => {
      setCopied({ ...copied, [key]: false });
    }, 2000);
  };

  const pasteFromClipboard = async (setter: (value: string) => void) => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setter(text);
      }
    } catch {
    }
  };

  const handleToggleProtocol = () => {
    setCustomProtocol(!customProtocol);
    setEncodeInput('');
    setEncodeOutput('');
    setDecodeInput('');
    setDecodeOutput('');
    setEncodeKey('');
    setDecodeKey('');
  };

  const theme = {
    bg: customProtocol ? 'from-slate-950 via-neutral-900 to-red-950' : 'from-slate-900 via-slate-800 to-teal-900',
    accent: customProtocol ? 'red' : 'teal',
    encodeAccent: customProtocol ? 'red' : 'emerald',
    decodeAccent: customProtocol ? 'orange' : 'sky',
    iconBg: customProtocol ? 'from-red-500 to-red-700' : 'from-teal-500 to-teal-600',
    encodeBg: customProtocol ? 'from-red-500 to-red-700' : 'from-emerald-400 to-emerald-600',
    decodeBg: customProtocol ? 'from-orange-500 to-orange-700' : 'from-sky-400 to-sky-600',
    encodeBtn: customProtocol ? 'from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 shadow-red-500/30 hover:shadow-red-500/50' : 'from-emerald-500 to-teal-500 hover:from-emerald-600 hover:to-teal-600 shadow-emerald-500/30 hover:shadow-emerald-500/50',
    decodeBtn: customProtocol ? 'from-orange-500 to-orange-600 hover:from-orange-600 hover:to-orange-700 shadow-orange-500/30 hover:shadow-orange-500/50' : 'from-sky-500 to-blue-500 hover:from-sky-600 hover:to-blue-600 shadow-sky-500/30 hover:shadow-sky-500/50'
  };

  return (
    <div className={`min-h-screen bg-gradient-to-br ${theme.bg} transition-colors duration-500`}>
      <div className="absolute inset-0 opacity-20" style={{backgroundImage: 'radial-gradient(circle at 25px 25px, rgba(255,255,255,0.1) 2px, transparent 0)', backgroundSize: '50px 50px'}}></div>

      <div className="relative max-w-6xl mx-auto px-4 py-8 sm:py-12">
        <div className="flex justify-center mb-6">
          <button
            onClick={handleToggleProtocol}
            className={`flex items-center gap-3 px-5 py-3 rounded-xl border transition-all duration-300 ${
              customProtocol
                ? 'bg-red-500/20 border-red-500/50 text-red-400 hover:bg-red-500/30'
                : 'bg-white/5 border-white/20 text-slate-300 hover:bg-white/10'
            }`}
          >
            {customProtocol ? (
              <ToggleRight className="w-6 h-6" />
            ) : (
              <ToggleLeft className="w-6 h-6" />
            )}
            <span className="font-medium text-sm sm:text-base">پروتکل اختصاصی کاربر</span>
            {customProtocol && <Key className="w-4 h-4" />}
          </button>
        </div>

        <div className="text-center mb-8 sm:mb-10 lg:mb-12">
          <div className={`inline-flex items-center justify-center w-16 h-16 sm:w-20 sm:h-20 bg-gradient-to-br ${theme.iconBg} rounded-xl sm:rounded-2xl shadow-lg ${customProtocol ? 'shadow-red-500/30' : 'shadow-teal-500/30'} mb-4 sm:mb-6 transition-all duration-500`}>
            <Shield className="w-8 h-8 sm:w-10 sm:h-10 text-white" />
          </div>
          <h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-black text-white mb-3 sm:mb-4 tracking-tight">
            {customProtocol ? 'رمزنگاری پیشرفته' : 'رمزنگاری محتوا'}
          </h1>
          <p className="text-sm sm:text-base lg:text-lg text-slate-300 max-w-xl mx-auto px-4">
            {customProtocol ? 'محافظت با کلید شخصی شما - امنیت در دستان خودتان' : 'محافظت از لینک‌ها و متن‌های حساس با حروف فارسی'}
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-4 sm:gap-6 lg:gap-8">
          <div className={`bg-white/10 backdrop-blur-xl rounded-2xl sm:rounded-3xl p-5 sm:p-6 lg:p-8 border ${customProtocol ? 'border-red-500/20' : 'border-white/10'} shadow-2xl transition-all duration-500`}>
            <div className="flex items-center gap-3 sm:gap-4 mb-5 sm:mb-6">
              <div className={`p-2.5 sm:p-3 bg-gradient-to-br ${theme.encodeBg} rounded-lg sm:rounded-xl shadow-lg ${customProtocol ? 'shadow-red-500/30' : 'shadow-emerald-500/30'} transition-all duration-500`}>
                <Lock className="w-6 h-6 sm:w-7 sm:h-7 text-white" />
              </div>
              <div>
                <h2 className="text-xl sm:text-2xl font-bold text-white">قفل کردن</h2>
                <p className="text-xs sm:text-sm text-slate-400">{customProtocol ? 'رمزنگاری با کلید شخصی' : 'رمزنگاری محتوا'}</p>
              </div>
            </div>

            <div className="space-y-4 sm:space-y-5">
              {customProtocol && (
                <div>
                  <label className={`block text-xs sm:text-sm font-medium mb-2 ${customProtocol ? 'text-red-300' : 'text-slate-300'}`}>
                    کلید شخصی
                  </label>
                  <div className="relative">
                    <input
                      type="password"
                      value={encodeKey}
                      onChange={(e) => setEncodeKey(e.target.value)}
                      placeholder="کلید شخصی خود را وارد کنید..."
                      className={`w-full px-4 sm:px-5 py-3 sm:py-4 bg-white/5 border rounded-lg sm:rounded-xl focus:ring-2 resize-none text-sm sm:text-base text-white placeholder-slate-500 transition-all ${
                        customProtocol
                          ? 'border-red-500/30 focus:ring-red-500 focus:border-transparent'
                          : 'border-white/10 focus:ring-emerald-500 focus:border-transparent'
                      }`}
                    />
                    <Key className={`absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 ${customProtocol ? 'text-red-400' : 'text-slate-500'}`} />
                  </div>
                  <p className="text-xs text-slate-500 mt-1.5">این کلید هیچ‌جا ذخیره نمی‌شود</p>
                </div>
              )}

              <div>
                <label className="block text-xs sm:text-sm font-medium text-slate-300 mb-2">
                  محتوای اصلی
                </label>
                <div className="relative">
                  <textarea
                    value={encodeInput}
                    onChange={(e) => setEncodeInput(e.target.value)}
                    placeholder="لینک یا متن خود را وارد کنید..."
                    className={`w-full h-28 sm:h-36 px-4 sm:px-5 py-3 sm:py-4 bg-white/5 border rounded-lg sm:rounded-xl focus:ring-2 resize-none text-sm sm:text-base text-white placeholder-slate-500 transition-all ${
                      customProtocol
                        ? 'border-red-500/30 focus:ring-red-500 focus:border-transparent'
                        : 'border-white/10 focus:ring-emerald-500 focus:border-transparent'
                    }`}
                    maxLength={500}
                  />
                  {!encodeInput && (
                    <button
                      onClick={() => pasteFromClipboard(setEncodeInput)}
                      className={`absolute bottom-2 left-2 flex items-center gap-1.5 px-3 py-1.5 border rounded-md text-xs font-medium transition-all active:scale-95 ${
                        customProtocol
                          ? 'bg-red-500/20 hover:bg-red-500/30 border-red-500/30 text-red-400'
                          : 'bg-emerald-500/20 hover:bg-emerald-500/30 border-emerald-500/30 text-emerald-400'
                      }`}
                    >
                      <ClipboardPaste className="w-3.5 h-3.5" />
                      پیست
                    </button>
                  )}
                </div>
                <div className="text-left text-xs text-slate-500 mt-1.5 sm:mt-2">
                  {encodeInput.length} / 500
                </div>
              </div>

              <button
                onClick={handleEncode}
                className={`w-full bg-gradient-to-r ${theme.encodeBtn} text-white font-bold py-3 sm:py-4 rounded-lg sm:rounded-xl transition-all duration-300 shadow-lg active:scale-[0.98] flex items-center justify-center gap-2 text-sm sm:text-base`}
              >
                <Zap className="w-4 h-4 sm:w-5 sm:h-5" />
                {customProtocol ? 'رمزنگاری با کلید شخصی' : 'رمزنگاری کن'}
              </button>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-xs sm:text-sm font-medium text-slate-300">
                    محتوای رمز شده
                  </label>
                  {encodeOutput && (
                    <button
                      onClick={() => copyToClipboard(encodeOutput, 'encode')}
                      className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-md text-xs font-medium transition-all active:scale-95 ${
                        customProtocol
                          ? 'bg-red-500/20 hover:bg-red-500/30 border-red-500/30 text-red-400'
                          : 'bg-emerald-500/20 hover:bg-emerald-500/30 border-emerald-500/30 text-emerald-400'
                      }`}
                    >
                      {copied['encode'] ? (
                        <>
                          <Check className="w-3.5 h-3.5" />
                          کپی شد
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          کپی
                        </>
                      )}
                    </button>
                  )}
                </div>
                <div
                  className={`relative w-full h-28 sm:h-36 px-4 sm:px-5 py-3 sm:py-4 border rounded-lg sm:rounded-xl text-sm sm:text-base font-medium overflow-auto ${
                    customProtocol
                      ? 'bg-red-950/50 border-red-500/20'
                      : 'bg-emerald-950/50 border-emerald-500/20'
                  }`}
                >
                  {encodeOutput ? (
                    <p className={`break-all whitespace-normal select-all ${customProtocol ? 'text-red-300' : 'text-emerald-300'}`}>{encodeOutput}</p>
                  ) : (
                    <p className="text-slate-600">نتیجه رمزنگاری اینجا نمایش داده می‌شود...</p>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className={`bg-white/10 backdrop-blur-xl rounded-2xl sm:rounded-3xl p-5 sm:p-6 lg:p-8 border ${customProtocol ? 'border-orange-500/20' : 'border-white/10'} shadow-2xl transition-all duration-500`}>
            <div className="flex items-center gap-3 sm:gap-4 mb-5 sm:mb-6">
              <div className={`p-2.5 sm:p-3 bg-gradient-to-br ${theme.decodeBg} rounded-lg sm:rounded-xl shadow-lg ${customProtocol ? 'shadow-orange-500/30' : 'shadow-sky-500/30'} transition-all duration-500`}>
                <Unlock className="w-6 h-6 sm:w-7 sm:h-7 text-white" />
              </div>
              <div>
                <h2 className="text-xl sm:text-2xl font-bold text-white">باز کردن</h2>
                <p className="text-xs sm:text-sm text-slate-400">{customProtocol ? 'رمزگشایی با کلید شخصی' : 'رمزگشایی محتوا'}</p>
              </div>
            </div>

            <div className="space-y-4 sm:space-y-5">
              {customProtocol && (
                <div>
                  <label className={`block text-xs sm:text-sm font-medium mb-2 ${customProtocol ? 'text-orange-300' : 'text-slate-300'}`}>
                    کلید شخصی
                  </label>
                  <div className="relative">
                    <input
                      type="password"
                      value={decodeKey}
                      onChange={(e) => setDecodeKey(e.target.value)}
                      placeholder="کلید شخصی را وارد کنید..."
                      className={`w-full px-4 sm:px-5 py-3 sm:py-4 bg-white/5 border rounded-lg sm:rounded-xl focus:ring-2 resize-none text-sm sm:text-base text-white placeholder-slate-500 transition-all ${
                        customProtocol
                          ? 'border-orange-500/30 focus:ring-orange-500 focus:border-transparent'
                          : 'border-white/10 focus:ring-sky-500 focus:border-transparent'
                      }`}
                    />
                    <Key className={`absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 ${customProtocol ? 'text-orange-400' : 'text-slate-500'}`} />
                  </div>
                  <p className="text-xs text-slate-500 mt-1.5">بدون کلید صحیح، رمزگشایی ممکن نیست</p>
                </div>
              )}

              <div>
                <label className="block text-xs sm:text-sm font-medium text-slate-300 mb-2">
                  محتوای رمز شده
                </label>
                <div className="relative">
                  <textarea
                    value={decodeInput}
                    onChange={(e) => setDecodeInput(e.target.value)}
                    placeholder="محتوای رمز شده را وارد کنید..."
                    className={`w-full h-28 sm:h-36 px-4 sm:px-5 py-3 sm:py-4 bg-white/5 border rounded-lg sm:rounded-xl focus:ring-2 resize-none text-sm sm:text-base text-white placeholder-slate-500 font-medium transition-all ${
                      customProtocol
                        ? 'border-orange-500/30 focus:ring-orange-500 focus:border-transparent'
                        : 'border-white/10 focus:ring-sky-500 focus:border-transparent'
                    }`}
                  />
                  {!decodeInput && (
                    <button
                      onClick={() => pasteFromClipboard(setDecodeInput)}
                      className={`absolute bottom-2 left-2 flex items-center gap-1.5 px-3 py-1.5 border rounded-md text-xs font-medium transition-all active:scale-95 ${
                        customProtocol
                          ? 'bg-orange-500/20 hover:bg-orange-500/30 border-orange-500/30 text-orange-400'
                          : 'bg-sky-500/20 hover:bg-sky-500/30 border-sky-500/30 text-sky-400'
                      }`}
                    >
                      <ClipboardPaste className="w-3.5 h-3.5" />
                      پیست
                    </button>
                  )}
                </div>
              </div>

              <button
                onClick={handleDecode}
                className={`w-full bg-gradient-to-r ${theme.decodeBtn} text-white font-bold py-3 sm:py-4 rounded-lg sm:rounded-xl transition-all duration-300 shadow-lg active:scale-[0.98] flex items-center justify-center gap-2 text-sm sm:text-base`}
              >
                <Zap className="w-4 h-4 sm:w-5 sm:h-5" />
                {customProtocol ? 'رمزگشایی با کلید شخصی' : 'رمزگشایی کن'}
              </button>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-xs sm:text-sm font-medium text-slate-300">
                    محتوای اصلی
                  </label>
                  {decodeOutput && !decodeOutput.startsWith('خطا:') && (
                    <button
                      onClick={() => copyToClipboard(decodeOutput, 'decode')}
                      className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-md text-xs font-medium transition-all active:scale-95 ${
                        customProtocol
                          ? 'bg-orange-500/20 hover:bg-orange-500/30 border-orange-500/30 text-orange-400'
                          : 'bg-sky-500/20 hover:bg-sky-500/30 border-sky-500/30 text-sky-400'
                      }`}
                    >
                      {copied['decode'] ? (
                        <>
                          <Check className="w-3.5 h-3.5" />
                          کپی شد
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          کپی
                        </>
                      )}
                    </button>
                  )}
                </div>
                <div
                  className={`relative w-full h-28 sm:h-36 px-4 sm:px-5 py-3 sm:py-4 border rounded-lg sm:rounded-xl text-sm sm:text-base font-medium overflow-auto ${
                    customProtocol
                      ? 'bg-orange-950/50 border-orange-500/20'
                      : 'bg-sky-950/50 border-sky-500/20'
                  }`}
                >
                  {decodeOutput ? (
                    <p className={`break-all whitespace-normal select-all ${decodeOutput.startsWith('خطا:') ? 'text-red-400' : customProtocol ? 'text-orange-300' : 'text-sky-300'}`}>
                      {decodeOutput}
                    </p>
                  ) : (
                    <p className="text-slate-600">نتیجه رمزگشایی اینجا نمایش داده می‌شود...</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className={`mt-8 sm:mt-10 lg:mt-12 bg-white/5 backdrop-blur-xl rounded-xl sm:rounded-2xl p-4 sm:p-6 border ${customProtocol ? 'border-red-500/10' : 'border-white/10'} transition-all duration-500`}>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 sm:gap-6 text-center sm:text-right">
            <div className="flex items-center gap-2.5 sm:gap-3">
              <div className={`p-1.5 sm:p-2 rounded-lg ${customProtocol ? 'bg-red-500/20' : 'bg-teal-500/20'}`}>
                <WifiOff className={`w-4 h-4 sm:w-5 sm:h-5 ${customProtocol ? 'text-red-400' : 'text-teal-400'}`} />
              </div>
              <div>
                <p className="text-sm sm:text-base text-white font-medium">بدون نیاز به اینترنت</p>
                <p className="text-[10px] sm:text-xs text-slate-400">حتی با قطع اینترنت کار می‌کند</p>
              </div>
            </div>
            <div className="hidden sm:block w-px h-10 bg-white/10"></div>
            <div className="flex items-center gap-2.5 sm:gap-3">
              <div className={`p-1.5 sm:p-2 rounded-lg ${customProtocol ? 'bg-red-500/20' : 'bg-emerald-500/20'}`}>
                {customProtocol ? <Key className="w-4 h-4 sm:w-5 sm:h-5 text-red-400" /> : <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-emerald-400" />}
              </div>
              <div>
                <p className="text-sm sm:text-base text-white font-medium">{customProtocol ? 'کلید شخصی ذخیره نمی‌شود' : 'کاملا امن و محلی'}</p>
                <p className="text-[10px] sm:text-xs text-slate-400">{customProtocol ? 'فقط شما به کلید دسترسی دارید' : 'هیچ اطلاعاتی به سرور ارسال نمی‌شود'}</p>
              </div>
            </div>
            <div className="hidden sm:block w-px h-10 bg-white/10"></div>
            <div className="flex items-center gap-2.5 sm:gap-3">
              <div className={`p-1.5 sm:p-2 rounded-lg ${customProtocol ? 'bg-orange-500/20' : 'bg-sky-500/20'}`}>
                <Wifi className={`w-4 h-4 sm:w-5 sm:h-5 ${customProtocol ? 'text-orange-400' : 'text-sky-400'}`} />
              </div>
              <div>
                <p className="text-sm sm:text-base text-white font-medium">یکبار باز کنید</p>
                <p className="text-[10px] sm:text-xs text-slate-400">سپس آفلاین استفاده کنید</p>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-6 sm:mt-8 text-center px-4">
          <p className="text-xs sm:text-sm text-slate-500">
            تمام عملیات رمزنگاری در مرورگر شما انجام می‌شود
          </p>
          <p className={`text-xs mt-2 ${customProtocol ? 'text-red-400' : 'text-slate-400'}`}>
            {customProtocol ? 'نسخه 3.0 - پروتکل اختصاصی با کلید شخصی' : 'نسخه 3.0 - پشتیبانی از کلید شخصی'}
          </p>
        </div>
      </div>
    </div>
  );
}

export default App;
