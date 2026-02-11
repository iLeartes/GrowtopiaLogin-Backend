import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 8080;

// @note trust proxy - set to number of proxies in front of app
app.set('trust proxy', 1);

// @note middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// @note rate limiter - 50 requests per minute
const limiter = rateLimit({
    windowMs: 60_000,
    max: 50,
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

// @note static files from public folder
app.use(express.static(path.join(process.cwd(), 'public')));

// @note request logging middleware
app.use((req: Request, _res: Response, next: NextFunction) => {
    const clientIp =
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        // @ts-ignore
        req.headers['x-real-ip'] ||
        req.socket.remoteAddress ||
        'unknown';

    console.log(
        `[REQ] ${req.method} ${req.path} → ${clientIp} | ${_res.statusCode}`,
    );
    next();
});

// @note root endpoint
app.get('/', (_req: Request, res: Response) => {
    res.send('Hello, world!');
});

/**
 * @note dashboard endpoint - serves login HTML page with client data
 * @param req - express request with optional body data
 * @param res - express response
 */
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
    const tData: Record<string, string> = {};

    // @note handle empty body or missing data
    const body = req.body;
    if (body && typeof body === 'object' && Object.keys(body).length > 0) {
        try {
            const bodyStr = JSON.stringify(body);
            // Simple parsing logic tailored to specific client data format if any
            // Assuming 'body' is already parsed JSON by express.json() / urlencoded
            // If client sends raw string in specific format, might need manual parsing
            // The original code had specific string splitting logic, let's keep it generally safe
            const parts = bodyStr.split('"');

            if (parts.length > 1) {
                const uData = parts[1].split('\n'); // This looks like it expects a specific raw format inside JSON?
                // Actually, if express parsed it, body is an object.
                // Let's assume standard behavior first. If client sends data like `key|val\nkey2|val2` in a field, we parse it.
                // But the original code `const parts = bodyStr.split('"');` suggests it might be receiving raw data or a single key with raw string value?
                // Let's trust express parsing for now, or if it fails we might need raw body parser.

                // Re-implementing original logic roughly:
                // It seems to expect the body to be a string representation where the interesting part is inside quotes?
                // Let's just iterate over body keys if it's an object.
                for (const key in body) {
                    tData[key] = body[key];
                }
            }
        } catch (why) {
            console.log(`[ERROR]: ${why}`);
        }
    }

    // @note convert tData object to base64 string
    const tDataBase64 = Buffer.from(JSON.stringify(tData)).toString('base64');

    // @note read dashboard template and replace placeholder
    const templatePath = path.join(
        process.cwd(),
        'template',
        'dashboard.html',
    );

    try {
        const templateContent = fs.readFileSync(templatePath, 'utf-8');
        const htmlContent = templateContent.replace('{{ data }}', tDataBase64);

        res.setHeader('Content-Type', 'text/html');
        res.send(htmlContent);
    } catch (err) {
        console.error('Error reading dashboard template:', err);
        res.status(500).send('Error loading dashboard template');
    }
});

/**
 * @note validate login endpoint - validates GrowID credentials
 * @param req - express request with growId, password, _token
 * @param res - express response with token
 */
app.all(
    '/player/growid/login/validate',
    async (req: Request, res: Response) => {
        try {
            const formData = req.body as Record<string, string>;
            const _token = formData._token;
            const growId = formData.growId;
            const password = formData.password;
            const serverName = formData.serverName || ''; // Extract serverName

            // Check if serverName is missing?
            if (!serverName) {
                // You might want to return an error or handle it, but for now we follow old logic
                // Or we can assume default if empty.
            }

            // Include serverName in the token string
            const token = Buffer.from(
                `_token=${_token}&growId=${growId}&password=${password}&serverName=${serverName}&reg=0`,
            ).toString('base64');

            res.setHeader('Content-Type', 'text/html');
            res.json({
                status: 'success',
                message: 'Account Validated.',
                token,
                url: '', // This triggers the client to use the token for actual login?
                accountType: 'growtopia',
            });
        } catch (error) {
            console.log(`[ERROR]: ${error}`);
            res.status(500).json({
                status: 'error',
                message: 'Internal Server Error',
            });
        }
    },
);

/**
 * @note first checktoken endpoint - redirects using 307 to preserve data
 * @param req - express request with refreshToken and clientData
 * @param res - express response with updated token
 */
app.all('/player/growid/checktoken', async (req: Request, res: Response) => {
    return res.redirect(307, '/player/growid/validate/checktoken');
});

/**
 * @note second checktoken endpoint - validates token and returns updated token
 * @param req - express request with refreshToken and clientData
 * @param res - express response with updated token
 */
app.all(
    '/player/growid/validate/checktoken',
    async (req: Request, res: Response) => {
        try {
            // @note handle both { data: { ... } } and { refreshToken, clientData } formats
            const body = req.body as
                | { data: { refreshToken: string; clientData: string } }
                | { refreshToken: string; clientData: string };

            const refreshToken =
                'data' in body ? body.data?.refreshToken : body.refreshToken;
            const clientData =
                'data' in body ? body.data?.clientData : body.clientData;

            if (!refreshToken || !clientData) {
                res.status(400).json({
                    status: 'error',
                    message: 'Missing refreshToken or clientData',
                });
                return;
            }

            let decodeRefreshToken = Buffer.from(refreshToken, 'base64').toString(
                'utf-8',
            );

            // We might need to preserve serverName here too if it's in the original token
            // But usually checktoken just updates clientData part. 
            // The regex replacement below preserves other fields like growId/password/serverName if they are before clientData injection point?
            // Actually it replaces `_token=...&` with `_token=...NewData...&` logic.
            // Wait, regex: `/_token=[^&]*/` replaces just the _token value.
            // So other fields (growId, password, serverName) should remain untouched if they are outside _token value.

            const token = Buffer.from(
                decodeRefreshToken.replace(
                    /(_token=)[^&]*/,
                    `$1${Buffer.from(clientData).toString('base64')}`,
                ),
            ).toString('base64');

            res.send(
                `{"status":"success","message":"Token is valid.","token":"${token}","url":"","accountType":"growtopia"}`,
            );
        } catch (error) {
            console.log(`[ERROR]: ${error}`);
            res.status(500).json({
                status: 'error',
                message: 'Internal Server Error',
            });
        }
    },
);

app.listen(PORT, () => {
    console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
