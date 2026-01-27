import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;

// Trust proxy
app.set('trust proxy', 1);

// Body parsers (genel)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors());

// Rate limiter
const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
});
app.use(limiter);

// Static files
app.use(express.static(path.join(process.cwd(), 'public')));

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    (req.headers['x-real-ip'] as string) ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);
  next();
});

// Root
app.get('/', (_req: Request, res: Response) => {
  res.send('Hello, world!');
});

/**
 * IMPORTANT:
 * Growtopia client çoğu zaman dashboard'a JSON değil düz text yollar.
 * Bu yüzden sadece bu route altında raw text body yakalıyoruz.
 */
app.use('/player/login/dashboard', express.text({ type: '*/*' }));

/**
 * Dashboard endpoint - serves login HTML page with client data
 */
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  try {
    // Mobil bazen body yollamaz (GET olur), o yüzden hem body hem query deniyoruz
    const rawBody = typeof req.body === 'string' ? req.body : '';
    const rawQuery = typeof req.query?.data === 'string' ? req.query.data : '';

    const clientData = rawBody.length ? rawBody : rawQuery;

    // Debug: mobil/pc farkını gör
    console.log('[DASHBOARD] method:', req.method, 'content-type:', req.headers['content-type']);
    console.log('[DASHBOARD] raw length:', clientData.length);

    // _token: clientData'nın base64'ü olmalı
    const tokenBase64 = Buffer.from(clientData, 'utf-8').toString('base64');

    const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
    const templateContent = fs.readFileSync(templatePath, 'utf-8');

    const htmlContent = templateContent.replace('{{ data }}', tokenBase64);

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(htmlContent);
  } catch (why) {
    console.log(`[ERROR][DASHBOARD]: ${why}`);
    res.status(500).send('Internal Server Error');
  }
});

/**
 * Validate login endpoint - validates GrowID credentials (senin sisteminde "success" dönüyor)
 */
app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;

    const _token = formData._token ?? '';
    const growId = formData.growId ?? '';
    const password = formData.password ?? '';

    // Debug
    console.log('[VALIDATE] growId:', growId, 'tokenLen:', _token.length);

    const tokenPlain = `_token=${_token}&growId=${growId}&password=${password}&reg=0`;
    const token = Buffer.from(tokenPlain, 'utf-8').toString('base64');

    res.json({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: '',
      accountType: 'growtopia',
    });
  } catch (error) {
    console.log(`[ERROR][VALIDATE]: ${error}`);
    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
});

/**
 * Checktoken handler - redirect YOK (mobilde 307 body düşebiliyor)
 */
const handleCheckToken = (req: Request, res: Response) => {
  try {
    // Hem {data:{refreshToken, clientData}} hem düz format destek
    const body = req.body as any;

    const refreshToken = body?.data?.refreshToken ?? body?.refreshToken;
    const clientData = body?.data?.clientData ?? body?.clientData;

    console.log('[CHECKTOKEN] method:', req.method, 'hasRefresh:', !!refreshToken, 'hasClientData:', !!clientData);

    if (!refreshToken || !clientData) {
      return res.status(400).json({
        status: 'error',
        message: 'Missing refreshToken or clientData',
      });
    }

    const decoded = Buffer.from(refreshToken, 'base64').toString('utf-8');

    // clientData'yı base64 yapıp _token alanına basıyoruz
    const replacedPlain = decoded.replace(
      /(_token=)[^&]*/,
      `$1${Buffer.from(clientData, 'utf-8').toString('base64')}`,
    );

    const token = Buffer.from(replacedPlain, 'utf-8').toString('base64');

    return res.json({
      status: 'success',
      message: 'Token is valid.',
      token,
      url: '',
      accountType: 'growtopia',
    });
  } catch (error) {
    console.log(`[ERROR][CHECKTOKEN]: ${error}`);
    return res.status(500).json({
      status: 'error',
      message: 'Internal Server Error',
    });
  }
};

// İki endpoint de aynı handler (redirect yok)
app.all('/player/growid/checktoken', handleCheckToken);
app.all('/player/growid/validate/checktoken', handleCheckToken);

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
