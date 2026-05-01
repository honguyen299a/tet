const express = require("express");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");

const server = jsonServer.create();
const router = jsonServer.router("products.json");
const middlewares = jsonServer.defaults();

const SECRET_KEY = "123";

server.use(express.json());
server.use(express.urlencoded({ extended: true }));
server.use(middlewares);

//
// ===============================
// 🔐 LOGIN
// ===============================
server.post("/login", (req, res) => {
  const { username, password } = req.body;

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
    return res.status(403).json({ message: "Thiếu token" });
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
//

/**
 * GET: ai cũng xem được (KHÔNG cần token)
 */
server.get("/hotels", (req, res, next) => {
  next();
});

/**
 * POST: chỉ admin
 */
server.post("/hotels", verifyToken, checkAdmin, (req, res, next) => {
  next();
});

/**
 * PUT: chỉ admin
 */
server.put("/hotels/:id", verifyToken, checkAdmin, (req, res, next) => {
  next();
});

/**
 * DELETE: chỉ admin
 */
server.delete("/hotels/:id", verifyToken, checkAdmin, (req, res, next) => {
  next();
});

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
// 🏠 ROOT TEST
//
server.get("/", (req, res) => {
  res.json({
    message: "API đang chạy",
    endpoints: ["/login", "/hotels"],
  });
});

//
// 🚀 PORT
//
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server chạy tại port ${PORT}`);
});
const rateLimit = require("express-rate-limit");

const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 phút
  max: 100, // tối đa 100 request
  message: "Bạn gọi API quá nhiều, thử lại sau",
});

server.use(limiter);
