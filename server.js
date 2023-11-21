// npm run start
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

const port = 8000;

// erlaubt App, JSON zu aktzeptieren
app.use(express.json());

const users = [];

const posts = [
  { username: "Felix", title: "I write code" },
  { username: "Max", title: "I drink soda" },
  { username: "Alex", title: "I read books" },
];

// normalerweise in redis cache/db... --NUR DEMO-ZWECKE--
let refreshTokens = [];

//get users
app.get("/users", (req, res) => {
  res.json(users);
});

//create users
// bcrypt ist async lib
app.post("/users", async (req, res) => {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    // es würde auch gehen:
    //const hashedPassword = await bcrypt.hash(req.body.password, 10); -> 10 = bcrypt.genSalt(10)
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

function generateAccessToken(user) {
  // token secret wurde im terminal mit folgendem erstellt: node
  //require("crypto").randomBytes(64).toString("hex")
  return jwt.sign({ name: user.name }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15s",
  });
}
// login user
app.post("/login", async (req, res) => {
  const user = users.find((user) => user.name == req.body.name);
  if (user == null) {
    return res.status(400).send();
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      //jwt Prozess ------------------------
      const accessToken = generateAccessToken(user);
      const refreshToken = jwt.sign(
        { name: user.name },
        process.env.REFRESH_TOKEN
      );
      // --NUR DEMO ZWECKE--
      refreshTokens.push(refreshToken);
      //--------------------------------
      res.json({
        message: "erfolgreich",
        accessToken: accessToken,
        refreshToken: refreshToken,
      });
    } else {
      res.status(400).send("Falsches Passwort");
    }
  } catch {
    res.status(500).send("Da ist etwas schiefgelaufen");
  }
});

//verifiziert user
function authenticateToken(req, res, next) {
  // auth Header erhalten
  const authHeader = req.headers["authorization"];
  // token ohne Bearer
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.status(401).send();

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    // user: Enthält die Daten, die im Payload des Tokens gespeichert sind,
    //wenn das Token erfolgreich verifiziert wurde.
    if (err) return res.status(403).send();
    //Wenn das Token erfolgreich verifiziert wird (kein Fehler),
    // werden die Daten aus dem Payload des Tokens (user) req.user zugewiesen.
    //Diese Aktion fügt die Benutzerinformationen zur Anfrage hinzu,
    //sodass nachfolgende Middleware oder Routen diese Informationen verwenden können.
    req.user = user;
    next();
  });
}

// posts vom angemeldeten user
app.get("/posts", authenticateToken, (req, res) => {
  // eingeloggter user erhält nur seine eigenen posts
  console.log(req.user);
  res.json(posts.filter((post) => post.username === req.user.name));
});

app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.status(401).send();
  if (!refreshTokens.includes(refreshToken)) return res.status(403).send();
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
    if (err) return res.status(403).send();
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  });
});

app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

app.listen(port, () => {
  console.log(`Server läuft auf http://localhost:${port}`);
});
