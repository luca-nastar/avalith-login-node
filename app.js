const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const user = require("./user");
const secretKey = require("./config");

const app = express();

//Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

//Login
app.post("/login", (req, res) => {
	const { userName, password } = req.body;

	if (userName !== user.userName)
		return res.status(401).json({ msg: "Usuario incorrecto" });

	bcrypt.compare(password, user.password, (err, check) => {
		const accessToken = jwt.sign({ name: user.name }, secretKey, {
			expiresIn: "1h",
		});

		if (err) return res.status(500).json({ err });

		if (!check) return res.status(401).json({ msg: "Contraseña incorrecta" });

		return res.status(201).json({ accessToken });
	});
});

//Greetings
app.get("/greetings", (req, res) => {
	const token = req.headers.authorization;

	jwt.verify(token, secretKey, (err, decoded) => {
		if (err) return res.status(403).send(err);

		res.send(`Buenos dias ${decoded.name}!`);
	});
});

module.exports = app;
