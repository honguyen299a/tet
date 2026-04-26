const express = require("express");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");

const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();

const SECRET_KEY = "123"; // ✅ FIX: thêm thiếu cái này

server.use(express.json());
server.use(express.urlencoded({ extended: true }));
server.use(middlewares);

//
// 🔐 LOGIN (Authentication)
//
server.post("/login", (req, res) => {
  const { username, password } = req.body;

  // ✅ FIX: đọc db an toàn hơn
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
// 🔐 Middleware check token
//
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
// 🔥 Bảo vệ hotels
//
server.use("/hotels", verifyToken);

//
// 🚫 Chặn users
//
server.use("/users", (req, res) => {
  res.status(403).json({ message: "Không cho truy cập" });
});

//
// 🚫 Chặn db
//
server.use("/db", (req, res) => {
  res.status(403).json({ message: "Không cho truy cập" });
});

//
// 📦 API json-server
//
server.use(router);

//
// 🚀 PORT (Render bắt buộc dùng process.env.PORT)
//
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server chạy tại port ${PORT}`);
});
