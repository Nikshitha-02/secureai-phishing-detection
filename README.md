# SecureAI – AI-Powered Phishing Detection & Security Assistant

A cybersecurity platform that uses AI to analyze URLs and emails for phishing attacks, provides a risk score, explains why the content is suspicious, and stores scan history for authenticated users.

---

## Tech Stack

| Layer      | Technology                                        |
|------------|---------------------------------------------------|
| Frontend   | React 19, TypeScript 6, Vite 8, Tailwind CSS v4   |
| Backend    | Node.js, Express 5, TypeScript 5                  |
| Database   | PostgreSQL via Supabase                           |
| Auth       | Supabase Authentication                           |
| AI         | Google Gemini API                                 |
| HTTP       | Axios, REST                                       |
| State      | Zustand                                           |
| Routing    | React Router v7                                   |

---

## Project Structure

```
SecureAI/
├── frontend/          # React + Vite application
│   └── src/
│       ├── assets/
│       ├── components/
│       ├── features/
│       │   ├── auth/
│       │   ├── url-scanner/
│       │   ├── email-scanner/
│       │   ├── dashboard/
│       │   └── history/
│       ├── hooks/
│       ├── layouts/
│       ├── lib/
│       ├── pages/
│       ├── routes/
│       ├── services/
│       ├── store/
│       ├── types/
│       └── utils/
│
├── backend/           # Express REST API
│   └── src/
│       ├── config/        # Env vars, DB config
│       ├── controllers/   # Route handlers
│       ├── middlewares/   # Auth, errors, rate-limit
│       ├── models/        # TypeScript DB types
│       ├── routes/        # Express routers
│       ├── services/      # Gemini, Supabase logic
│       └── utils/         # Logger, helpers
│
└── README.md
```

---

## Getting Started

### Prerequisites

- Node.js >= 20
- npm >= 9
- A [Supabase](https://supabase.com) project
- A [Google AI Studio](https://aistudio.google.com) API key

### 1. Clone the repository

```bash
git clone https://github.com/your-username/SecureAI.git
cd SecureAI
```

### 2. Set up the frontend

```bash
cd frontend
cp .env.example .env       # then fill in your values
npm install --legacy-peer-deps
npm run dev                # starts on http://localhost:5173
```

### 3. Set up the backend

```bash
cd backend
cp .env.example .env       # then fill in your values
npm install
npm run dev                # starts on http://localhost:5000
```

---

## Environment Variables

### Frontend (`frontend/.env`)

| Variable              | Description                              |
|-----------------------|------------------------------------------|
| `VITE_SUPABASE_URL`   | Your Supabase project URL                |
| `VITE_SUPABASE_ANON_KEY` | Supabase public/anon key             |
| `VITE_API_BASE_URL`   | Backend API base URL                     |

### Backend (`backend/.env`)

| Variable                    | Description                              |
|-----------------------------|------------------------------------------|
| `NODE_ENV`                  | `development` or `production`            |
| `PORT`                      | Port for the Express server (default: 5000) |
| `CORS_ORIGIN`               | Allowed frontend origin                  |
| `SUPABASE_URL`              | Your Supabase project URL                |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key (server-only)  |
| `GEMINI_API_KEY`            | Google Gemini API key                    |

---

## Available Scripts

### Frontend

| Script              | Description                          |
|---------------------|--------------------------------------|
| `npm run dev`       | Start Vite dev server                |
| `npm run build`     | TypeScript check + production build  |
| `npm run preview`   | Preview production build             |
| `npm run lint`      | Run ESLint                           |
| `npm run lint:fix`  | Run ESLint with auto-fix             |
| `npm run format`    | Format with Prettier                 |

### Backend

| Script              | Description                          |
|---------------------|--------------------------------------|
| `npm run dev`       | Start with ts-node-dev (hot reload)  |
| `npm run build`     | Compile TypeScript to `dist/`        |
| `npm start`         | Run compiled `dist/server.js`        |
| `npm run lint`      | Run ESLint                           |
| `npm run lint:fix`  | Run ESLint with auto-fix             |
| `npm run format`    | Format with Prettier                 |

---

## Architecture & Data Flow

```
Browser (React)
     │  HTTPS REST
     ▼
Express API (backend)
     ├──► Supabase Auth  — verify JWT from request header
     ├──► Gemini API     — AI phishing analysis
     └──► Supabase DB    — store / retrieve scan history
```

---

## Planned Features

- [ ] URL phishing scan with AI risk score
- [ ] Email content phishing analysis
- [ ] Risk score explanation (why is this suspicious?)
- [ ] User authentication (login / register)
- [ ] Scan history dashboard
- [ ] Protected routes for authenticated users
- [ ] Rate limiting per user

---

## License

ISC
