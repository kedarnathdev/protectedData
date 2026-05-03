# 🔐 ProtectedData

**A production-ready, password-protected short URL service for securely sharing text and files.**

ProtectedData (branded as **Fly Nexus LLP**) lets you create short URLs that gate access behind a password. Each link can carry text content and an optional file attachment. Users enter a password to unlock the content and download files — no account needed. An admin dashboard provides full CRUD control over all entries.

---

## ✨ Key Features

- **Password-Protected Links** — Every short URL requires a password to reveal its content. Passwords are hashed with bcrypt (12 rounds) and never stored in plain text.
- **File Attachments** — Attach files (up to 50 MB) to any link. Supports PDF, images, ZIP, TXT, DOCX, XLSX, and CSV.
- **Serial Number Lookup** — Each link gets a unique, auto-incrementing serial number (starting from 1001) for easy reference and search.
- **Admin Dashboard** — JWT-authenticated panel to view, edit, and delete all URLs. Manage labels, text, and file attachments in one place.
- **Rate Limiting** — Built-in protection against brute-force attacks: 100 req/15 min general, 10 req/15 min on sensitive routes.
- **Input Validation & Sanitization** — All inputs are validated server-side with clear error messages.
- **Docker-Ready** — Multi-stage Dockerfile, docker-compose config, and GitHub Actions CI/CD for multi-arch builds (amd64 + arm64).
- **Non-Root Container** — Runs as an unprivileged user inside Docker for better security.
- **Health Checks** — Built-in Docker health check endpoint for container orchestration.

---

## 🛠 Tech Stack

| Layer        | Technology                                                          |
| ------------ | ------------------------------------------------------------------- |
| **Runtime**  | [Node.js 20](https://nodejs.org/) (Alpine)                         |
| **Framework**| [Express.js 4](https://expressjs.com/)                              |
| **Database** | [MongoDB Atlas](https://www.mongodb.com/atlas) via [Mongoose 8](https://mongoosejs.com/) |
| **Auth**     | [JSON Web Tokens](https://github.com/auth0/node-jsonwebtoken) + [bcrypt](https://github.com/kelektiv/node.bcrypt.js) |
| **Uploads**  | [Multer](https://github.com/expressjs/multer)                      |
| **IDs**      | [nanoid](https://github.com/ai/nanoid) (8-char short IDs)          |
| **Security** | [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit), [CORS](https://github.com/expressjs/cors) |
| **Frontend** | Vanilla HTML/CSS/JS with [Inter](https://fonts.google.com/specimen/Inter) font |
| **CI/CD**    | GitHub Actions → GHCR + Docker Hub (multi-arch)                     |

---

## 📋 Prerequisites

Before you begin, make sure you have the following installed and configured:

- **Node.js** ≥ 18 — [Download](https://nodejs.org/)
- **npm** ≥ 9 (comes with Node.js)
- **MongoDB** — A running MongoDB instance or a [MongoDB Atlas](https://www.mongodb.com/atlas) cluster
- **Docker** *(optional)* — Required only if running via containers — [Install](https://docs.docker.com/get-docker/)
- **Git** — [Install](https://git-scm.com/)

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/kedarnathdev/protectedData.git
cd protectedData
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env` with your settings:

```env
# MongoDB Atlas connection string
MONGO_URI=mongodb+srv://<user>:<password>@cluster0.xxxxx.mongodb.net/<dbname>

# Server port
PORT=3000

# JWT secret for admin authentication (use a strong random string)
JWT_SECRET=your_jwt_secret_here_change_me

# Default admin credentials (used by seed script)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme123
```

### 4. Seed the admin user

```bash
npm run seed
```

### 5. Start the server

```bash
npm start
```

The server will be available at `http://localhost:3000`.

---

## 🐳 Running with Docker

### Using Docker Compose (recommended)

```bash
# Create your .env file first (see step 3 above), then:
docker compose up -d
```

### Using the pre-built image

```bash
docker pull kedarnathdev/protecteddata:master

docker run -d \
  --name protecteddata \
  -p 3000:3000 \
  --env-file .env \
  -v uploads_data:/app/uploads \
  kedarnathdev/protecteddata:master
```

---

## 📖 Usage

### Public Interface

1. **Access the home page** at `http://localhost:3000` — search for links by serial number.
2. **Open a short URL** (e.g., `http://localhost:3000/aBcDeFgH`) — enter the password to unlock text and download attached files.

### Admin Panel

1. Navigate to `http://localhost:3000/admin.html`.
2. Log in with the credentials set during seeding.
3. Create, edit, and delete protected URLs from the dashboard.

### API Endpoints

| Method   | Endpoint                  | Description                              | Auth     |
| -------- | ------------------------- | ---------------------------------------- | -------- |
| `POST`   | `/api/shorten`            | Create a new password-protected short URL | None     |
| `GET`    | `/api/search?serial=1001` | Look up a URL by serial number           | None     |
| `POST`   | `/api/:shortId/verify`    | Verify password and retrieve content     | None     |
| `GET`    | `/api/:shortId/download`  | Download attached file (password in query)| Password |
| `POST`   | `/api/admin/login`        | Admin login, returns JWT                 | None     |
| `GET`    | `/api/admin/urls`         | List all URLs (no password hashes)       | JWT      |
| `PUT`    | `/api/admin/urls/:id`     | Edit a URL entry                         | JWT      |
| `DELETE` | `/api/admin/urls/:id`     | Delete a URL and its file                | JWT      |

#### Example: Create a short URL

```bash
curl -X POST http://localhost:3000/api/shorten \
  -F "password=mySecretPass" \
  -F "textContent=This is protected content" \
  -F "label=demo" \
  -F "file=@./document.pdf"
```

**Response:**

```json
{
  "success": true,
  "shortUrl": "http://localhost:3000/aBcDeFgH",
  "shortId": "aBcDeFgH",
  "serialNumber": 1001
}
```

#### Example: Verify and access content

```bash
curl -X POST http://localhost:3000/api/aBcDeFgH/verify \
  -H "Content-Type: application/json" \
  -d '{"password": "mySecretPass"}'
```

**Response:**

```json
{
  "success": true,
  "textContent": "This is protected content",
  "hasFile": true,
  "fileName": "document.pdf",
  "downloadUrl": "/api/aBcDeFgH/download?token=mySecretPass"
}
```

---

## 📁 Project Structure

```
protectedData/
├── config/
│   └── db.js                # MongoDB connection setup
├── middleware/
│   ├── rateLimiter.js       # General & sensitive rate limiters
│   └── validate.js          # Input validation & file filter rules
├── models/
│   ├── Admin.js             # Admin user schema (username + hashed password)
│   └── Url.js               # URL schema (shortId, password, text, file, etc.)
├── routes/
│   ├── admin.js             # Admin auth, CRUD, and file management routes
│   └── url.js               # Public shorten, search, verify, and download routes
├── scripts/
│   └── seedAdmin.js         # CLI script to create/update the admin user
├── public/
│   ├── css/
│   │   └── styles.css       # Global stylesheet (dark theme, Inter font)
│   ├── index.html           # Home page — serial number search
│   ├── admin.html           # Admin dashboard (JWT-protected SPA)
│   └── view.html            # Password verification & content viewer
├── uploads/                 # Uploaded files (gitignored, Docker volume)
├── .env.example             # Environment variable template
├── .github/
│   └── workflows/
│       └── docker.yml       # CI/CD: multi-arch Docker build → GHCR + Docker Hub
├── Dockerfile               # Multi-stage production build (Node 20 Alpine)
├── docker-compose.yml       # One-command deployment with volumes
├── server.js                # Application entry point
├── package.json             # Dependencies and scripts
└── .gitignore               # Ignored files (node_modules, uploads, .env)
```

---

## 🤝 Contributing

Contributions are welcome. To get started:

1. **Fork** the repository.
2. **Create a feature branch** from `master`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Commit** your changes with clear, descriptive messages.
4. **Push** to your fork and open a **Pull Request** against `master`.

Please make sure your code:
- Follows the existing project structure and naming conventions.
- Includes input validation for any new endpoints.
- Does not commit `.env` or uploaded files.

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 👤 Authors

- **Kedarnath** — [GitHub](https://github.com/kedarnathdev)

---

<p align="center">
  Built with ❤️ using Node.js, Express, and MongoDB
</p>
