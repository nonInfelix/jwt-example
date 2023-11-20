// npm run start
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const port = 8000;

// erlaubt App, JSON zu aktzeptieren
app.use(express.json());

const users = [];

const posts = [
  { author: "Felix", title: "I write code" },
  { author: "Max", title: "I drink soda" },
  { author: "Alex", title: "I read books" },
];

app.get("/users", (req, res) => {
  res.json(users);
});

// bcrypt ist async lib
app.post("/users", async (req, res) => {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    console.log("Salt: ", salt);
    console.log("password: ", hashedPassword);
    /** Beispiel 
     * salt und hashedPassword wird jedes mal neu
    Salt:      $2b$10$xpkLwnIvWibM.oED5jaQme
	password:  $2b$10$xpkLwnIvWibM.oED5jaQme49mB0Dj2rrz259cwfd2K/arwOgbfeu6 
     */

    const user = { name: req.body.name, password: hashedPassword };
    users.push(user);
    res.status(201).send();
  } catch {
    res.status(500).send();
  }
});

app.get("/posts", (req, res) => {
  res.json(posts);
});
app.post("/login", async (req, res) => {
  const user = users.find((user) => (user.name = req.body.name));
  if (user == null) {
    return res.status(400).send();
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      res.send("erfolgreich eingeloggt");
    } else {
      res.status(400).send("Falsches Passwort");
    }
  } catch {
    res.status(500).send("Da ist etwas schiefgelaufen");
  }
});

app.listen(port, () => {
  console.log(`Server läuft auf http://localhost:${port}`);
});
