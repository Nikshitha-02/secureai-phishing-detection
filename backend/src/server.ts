import 'dotenv/config';
import app from './app';
import { config } from './config/env';

const PORT = config.PORT;

app.listen(PORT, () => {
  console.log(`[server] SecureAI API running on http://localhost:${PORT}`);
  console.log(`[server] Environment: ${config.NODE_ENV}`);
});
