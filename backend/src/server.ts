import 'dotenv/config';
import app from './app';
import { config } from './config/env';
import { runGeminiHealthCheck } from './services/gemini.service';

const PORT = config.PORT;

app.listen(PORT, () => {
  console.log(`[server] SecureAI API running on http://localhost:${PORT}`);
  console.log(`[server] Environment: ${config.NODE_ENV}`);

  // Gemini health check — runs after the server is up, never blocks startup.
  if (config.GEMINI_API_KEY) {
    runGeminiHealthCheck(config.GEMINI_API_KEY, config.GEMINI_MODEL).catch(() => {
      // Already logged inside runGeminiHealthCheck — swallow here to be safe.
    });
  }
});
