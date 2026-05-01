const express = require("express");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const server = jsonServer.create();
const router = jsonServer.router("products.json");
const middlewares = jsonServer.defaults();

const SECRET_KEY = "my_secret_key_2026";

server.use(express.json());
server.use(express.urlencoded({ extended: true }));
server.use(middlewares);

//
// ===============================
// 🚫 RATE LIMIT LOGIN
// ===============================
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 phút
  max: 5, // tối đa 5 lần login / phút
  message: { message: "Bạn login quá nhiều, thử lại sau" },
});

//
// ===============================
// 🔐 LOGIN
// ===============================
server.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Thiếu dữ liệu" });
  }

  const users = router.db.get("users").value() || [];

  const user = users.find(
    (u) => u.username === username && u.password === password,
  );

  if (!user) {
    return res.status(401).json({ message: "Sai tài khoản" });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, {
    expiresIn: "1h",
  });

  res.json({ token });
});

//
// ===============================
// 🔐 VERIFY TOKEN
// ===============================
function verifyToken(req, res, next) {
  const auth = req.headers["authorization"];

  if (!auth) {
    return res.status(401).json({ message: "Thiếu token" });
  }

  const token = auth.split(" ")[1];

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(401).json({ message: "Token sai" });
    }

    req.user = user;
    next();
  });
}

//
// ===============================
// 🔥 CHECK ADMIN
// ===============================
function checkAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Chỉ admin mới được phép" });
  }
  next();
}

//
// ===============================
// 🔥 HOTELS ROUTES
// ===============================

// GET: public
server.get("/hotels", (req, res, next) => next());

// POST: admin only
server.post("/hotels", verifyToken, checkAdmin, (req, res, next) => next());

// PUT: admin only
server.put("/hotels/:id", verifyToken, checkAdmin, (req, res, next) => next());

// DELETE: admin only
server.delete("/hotels/:id", verifyToken, checkAdmin, (req, res, next) =>
  next(),
);

//
// 🚫 CHẶN USERS
//
server.use("/users", (req, res) => {
  res.status(403).json({ message: "Không cho truy cập" });
});

//
// 🚫 CHẶN DB
//
server.use("/db", (req, res) => {
  res.status(403).json({ message: "Không cho truy cập" });
});

//
// 📦 JSON SERVER ROUTES
//
server.use(router);

//
// 🏠 ROOT
//
server.get("/", (req, res) => {
  res.json({
    message: "API đang chạy",
    endpoints: ["/login", "/hotels"],
  });
});

//
// 🚀 START SERVER
//
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server chạy tại port ${PORT}`);
});
