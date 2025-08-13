const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// Make sure uploads directory exists
const UPLOAD_DIR = "uploads";
if (!fs.existsSync(UPLOAD_DIR)){
    fs.mkdirSync(UPLOAD_DIR);
}

// Multer storage config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, req.body.username + ext);
  }
});
const upload = multer({ storage });

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/uploads", express.static(UPLOAD_DIR));
app.use(session({
  secret: "supersecretkey",
  resave: false,
  saveUninitialized: false
}));

let users = [];

function checkAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect("/login");
}

app.get("/", (req, res) => {
  if (req.session.user) {
    res.send(\`
      <h1>Welcome, \${req.session.user.username}!</h1>
      <img src="\${req.session.user.profilePic || '/default-avatar.png'}" alt="Profile Picture" width="100" height="100" />
      <p>Status: \${req.session.user.status}</p>
      <a href="/logout">Logout</a>
    \`);
  } else {
    res.send(\`
      <h1>Home</h1>
      <a href="/signup">Sign Up</a> | <a href="/login">Login</a>
    \`);
  }
});

app.get("/signup", (req, res) => {
  res.send(\`
    <h1>Sign Up</h1>
    <form method="post" action="/signup" enctype="multipart/form-data">
      <input name="username" placeholder="Username" required />
      <input name="password" type="password" placeholder="Password" required />
      <label>Profile Picture: <input type="file" name="profilePic" accept="image/*" /></label><br/>
      <button type="submit">Sign Up</button>
    </form>
    <a href="/login">Login</a>
  \`);
});

app.post("/signup", upload.single("profilePic"), async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const profilePicPath = req.file ? "/uploads/" + req.file.filename : null;

  users.push({
    username: req.body.username,
    password: hashedPassword,
    status: "Unverified",
    profilePic: profilePicPath
  });

  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.send(\`
    <h1>Login</h1>
    <form method="post" action="/login">
      <input name="username" placeholder="Username" required>
      <input name="password" type="password" placeholder="Password" required>
      <button type="submit">Login</button>
    </form>
    <a href="/signup">Sign Up</a>
  \`);
});

app.post("/login", async (req, res) => {
  const user = users.find(u => u.username === req.body.username);
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    req.session.user = user;
    res.redirect("/");
  } else {
    res.send("Invalid credentials <a href='/login'>Try again</a>");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/promote", checkAuth, (req, res) => {
  if (req.session.user.status !== "Manager") return res.send("Access denied");
  const list = users.map(u => \`
    <li>\${u.username} — \${u.status}
      \${u.status !== 'Member' ? \`<a href="/promote/\${u.username}">Promote</a>\` : ''}
    </li>
  \`).join("");
  res.send(\`
    <h1>Promote Users</h1>
    <ul>\${list}</ul>
    <a href="/">Back</a>
  \`);
});

app.get("/promote/:username", checkAuth, (req, res) => {
  if (req.session.user.status !== "Manager") return res.send("Access denied");
  const user = users.find(u => u.username === req.params.username);
  if (user) user.status = "Member";
  res.redirect("/promote");
});

// Default Manager Account
(async () => {
  const hashed = await bcrypt.hash("managerpass", 10);
  users.push({ username: "manager", password: hashed, status: "Manager" });
})();

app.listen(PORT, () => console.log(\`Server running on port \${PORT}\`));