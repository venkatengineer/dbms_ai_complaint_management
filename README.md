# Personal Portfolio Website 🌐

A modern, responsive, and impressive personal portfolio website built to showcase skills, projects, and achievements. This website includes a Contact Form integrated with a backend to send emails.

## 🚀 Features

- Responsive and modern UI
- Sections for About, Skills, Projects, and Contact
- Contact Form that sends emails using backend API
- Clean and reusable code structure

## 🛠️ Tech Stack

| Frontend | Backend | Tools |
|----------|----------|--------|
| HTML5 | Node.js + Express.js | Git & GitHub |
| CSS3 | Nodemailer / Email API | VS Code |
| JavaScript | MongoDB (optional) |  |

## 📂 Folder Structure

```
portfolio/
│── backend/
│   ├── server.js
│   ├── package.json
│   └── .env (for email credentials)
│
│── public/
│   ├── index.html
│   ├── styles.css
│   └── script.js
│
└── README.md
```

## ⚙️ How to Run the Project Locally

### 1️⃣ Clone the Repository
```bash
git clone <your-repo-link>
cd portfolio
```

### 2️⃣ Setup Backend
```bash
cd backend
npm install
```
Create a `.env` file and add:
```
EMAIL=your_email@example.com
PASSWORD=your_generated_app_password
```

### 3️⃣ Start Server
```bash
node server.js
```

### 4️⃣ Open Portfolio
Open `public/index.html` in browser.

---

## 📬 Contact Form Setup

The backend sends email using Nodemailer.  
Users submitting the contact form will send a direct email to your inbox.

---

## 📍 Deployment

You can deploy using any of the following:

| Frontend Hosting | Backend Hosting |
|------------------|-----------------------|
| GitHub Pages | Render |
| Netlify | Railway |
| Vercel | AWS / Azure / GCP |

---

## ❤️ Contribution

Pull requests are welcome!  
If you'd like to improve UI or add new features, feel free to contribute.

---

## 📄 License

This project is licensed under the **MIT License**.

---

### ⭐ If you like this, give the repo a star on GitHub!

