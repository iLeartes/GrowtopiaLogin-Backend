import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;

app.set('trust proxy', 1);

// parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
});
app.use(limiter);

app.use(express.static(path.join(process.cwd(), 'public')));

app.use((req: Request, _res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    (req.headers['x-real-ip'] as string) ||
    req.socket.remoteAddress ||
    'unknown';
  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);
  next();
});

app.get('/', (_req, res) => res.send('Hello, world!'));

/**
 * Dashboard: Growtopia client çoğu zaman JSON değil düz text yollar.
 * Sadece bu route altında raw text body yakalıyoruz.
 */
app.use('/player/login/dashboard', express.text({ type: '*/*' }));

app.all('/player/login/dashboard', (req: Request, res: Response) => {
  try {
    const rawBody = typeof req.body === 'string' ? req.body : '';
    const rawQuery = typeof req.query?.data === 'string' ? req.query.data : '';
    const clientData = rawBody.length ? rawBody : rawQuery;

    // Eğer clientData boşsa, yine de boş bırakıyoruz ({} yapmıyoruz)
    // Çünkü {} mobilde "e30=" üretiyor ve token bozuyor.
    const tokenBase64 = Buffer.from(clientData, 'utf-8').toString('base64');

    const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
    const templateContent = fs.readFileSync(templatePath, 'utf-8');

    const htmlContent = templateContent.replace('{{ data }}', tokenBase64);

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(htmlContent);
  } catch (e) {
    console.log('[ERROR][DASHBOARD]', e);
    return res.status(500).send('Internal Server Error');
  }
});

/**
 * Validate: MUTLAKA text/html + JSON STRING dön.
 * Growtopia client bazı sürümlerde application/json görünce ekrana basıyor.
 */
app.all('/player/growid/login/validate', (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;

    const _token = formData._token ?? '';
    const growId = formData.growId ?? '';
    const password = formData.password ?? '';

    const tokenPlain = `_token=${_token}&growId=${growId}&password=${password}&reg=0`;
    const token = Buffer.from(tokenPlain, 'utf-8').toString('base64');

    const payload = JSON.stringify({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: '',
      accountType: 'growtopia',
    });

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(payload);
  } catch (e) {
    console.log('[ERROR][VALIDATE]', e);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(500).send(
      JSON.stringify({ status: 'error', message: 'Internal Server Error' }),
    );
  }
});

/**
 * Checktoken: redirect KALDIRILDI.
 * İki endpoint de aynı handler’a düşer.
 * Yine text/html + JSON STRING.
 */
const handleCheckToken = (req: Request, res: Response) => {
  try {
    const body = req.body as any;

    const refreshToken = body?.data?.refreshToken ?? body?.refreshToken;
    const clientData = body?.data?.clientData ?? body?.clientData;

    if (!refreshToken || !clientData) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(400).send(
        JSON.stringify({
          status: 'error',
          message: 'Missing refreshToken or clientData',
        }),
      );
    }

    const decoded = Buffer.from(refreshToken, 'base64').toString('utf-8');

    const replacedPlain = decoded.replace(
      /(_token=)[^&]*/,
      `$1${Buffer.from(clientData, 'utf-8').toString('base64')}`,
    );

    const token = Buffer.from(replacedPlain, 'utf-8').toString('base64');

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(
      JSON.stringify({
        status: 'success',
        message: 'Token is valid.',
        token,
        url: '',
        accountType: 'growtopia',
      }),
    );
  } catch (e) {
    console.log('[ERROR][CHECKTOKEN]', e);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(500).send(
      JSON.stringify({ status: 'error', message: 'Internal Server Error' }),
    );
  }
};

app.all('/player/growid/checktoken', handleCheckToken);
app.all('/player/growid/validate/checktoken', handleCheckToken);

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
