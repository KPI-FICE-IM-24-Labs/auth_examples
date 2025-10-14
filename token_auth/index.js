const express = require("express");
const onFinished = require("on-finished");
const bodyParser = require("body-parser");
const path = require("path");
const crypto = require("node:crypto");
const jose = require('jose');
const fs = require('node:fs');

const port = 3000;
const app = express();
require("dotenv").config();

const privateKey = crypto.createPrivateKey(fs.readFileSync(`${process.cwd()}/../jwe.pem`));

const JWKS = jose.createRemoteJWKSet(
    new URL(`https://${process.env.DOMAIN}/.well-known/jwks.json`)
);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = "Authorization";

const uuid = require("uuid");

class Session {
  #sessions = {};
  constructor() {
    try {
      this.#sessions = fs.readFileSync("./sessions.json", "utf8");
      this.#sessions = JSON.parse(this.#sessions.trim());

      console.log(this.#sessions);
    } catch (e) {
      this.#sessions = {};
    }
  }

  #storeSessions() {
    fs.writeFileSync(
      "./sessions.json",
      JSON.stringify(this.#sessions),
      "utf-8",
    );
  }

  set(key, value) {
    if (!value) {
      value = {};
    }
    this.#sessions[key] = value;
    this.#storeSessions();
  }

  get(key) {
    return this.#sessions[key];
  }

  init(res) {
    const sessionId = uuid.v4();
    this.set(sessionId);

    return sessionId;
  }

  destroy(req, res) {
    const sessionId = req.sessionId;
    delete this.#sessions[sessionId];
    this.#storeSessions();
  }
}

const sessions = new Session();

const request = require("request");
const axios = require("axios");

const DOMAIN = process.env.DOMAIN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const API_IDENTIFIER = process.env.API_IDENTIFIER;

const auth0Login = (login, password) => {
  return new Promise((resolve, reject) => {
    const options = {
      method: "POST",
      url: `https://${DOMAIN}/oauth/token`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      form: {
        grant_type: "password",
        username: login,
        password: password,
        audience: API_IDENTIFIER,
        scope: "offline_access",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      },
    };
    request(options, (error, response, body) => {
      if (error) reject(error);
      resolve(body);
    });
  });
};

const getAccessToken = async () => {
  const options = {
    method: "POST",
    url: `https://${DOMAIN}/oauth/token`,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    data: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      audience: API_IDENTIFIER,
    }),
  };

  const response = await axios.request(options);
  return response.data.access_token;
};

const auth0Signup = async (login, password) => {
  const accessToken = await getAccessToken();
  let data = JSON.stringify({
    email: login,
    nickname: login,
    connection: "Username-Password-Authentication",
    password: password,
  });

  let config = {
    method: "POST",
    maxBodyLength: Infinity,
    url: `https://${DOMAIN}/api/v2/users`,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      Authorization: `Bearer ${accessToken}`,
    },
    data: data,
  };

  axios
    .request(config)
    .then((response) => {
      console.log(JSON.stringify(response.data));
    })
    .catch((error) => {
      console.log(error);
    });
};

const auth0LoginRefreshToken = (refreshToken) => {
  return new Promise((resolve, reject) => {
    const options = {
      method: "POST",
      url: `https://${DOMAIN}/oauth/token`,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      form: {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      },
    };

    request(options, (error, response, body) => {
      if (error) reject(error);
      resolve(body);
    });
  });
};

app.use((req, res, next) => {
  let currentSession = {};
  let sessionId = req.get(SESSION_KEY);

  if (sessionId) {
    currentSession = sessions.get(sessionId);
    if (!currentSession) {
      currentSession = {};
      sessionId = sessions.init(res);
    }
  } else {
    sessionId = sessions.init(res);
  }

  req.session = currentSession;
  req.sessionId = sessionId;

  onFinished(req, () => {
    const currentSession = req.session;
    const sessionId = req.sessionId;
    sessions.set(sessionId, currentSession);
  });

  next();
});

app.get("/", async (req, res) => {
  console.log("GET /");
  if (req.session.access_token) {
    try {
      const { plaintext } = await jose.compactDecrypt(req.session.access_token, privateKey);
      const jwt = new TextDecoder().decode(plaintext);
      const { payload } = await jose.jwtVerify(jwt, JWKS, {
        issuer: `https://${DOMAIN}/`,
        audience: API_IDENTIFIER,
      });

      const now = Math.floor(Date.now() / 1000);
      const tokenLifetime = req.session.expires_at - now;

      if (tokenLifetime <= 30) {
        const response = await auth0LoginRefreshToken(req.session.refresh_token);
        const responseObj = JSON.parse(response);

        req.session.access_token = responseObj.access_token;
        req.session.expires_at = now + responseObj.expires_in;

        console.log("Token refreshed");
      }

      res.json({
        username: req.session.username,
        payload,
        logout: "http://localhost:3000/logout",
      });
    } catch (error) {
      console.log(error)
      sessions.destroy(req, res);
      return res.sendFile(path.join(__dirname + "/index.html"));
    }
  }
  res.sendFile(path.join(__dirname + "/index.html"));
});

app.get("/logout", (req, res) => {
  sessions.destroy(req, res);
  res.redirect("/");
});

app.post("/api/login", async (req, res) => {
  const { login, password } = req.body;
  await auth0Login(login, password)
    .then((response) => {
      const result = JSON.parse(response);
      console.log(result);
      req.session.username = login;
      req.session.login = login;
      req.session.access_token = result.access_token;
      req.session.expires_at =
        Math.floor(Date.now() / 1000) + result.expires_in;
      req.session.refresh_token = result.refresh_token;
      res.json({ token: req.sessionId });
    })
    .catch((error) => {
      console.error(error);
      res.status(401).send();
    });
});
app.post("/api/signup", (req, res) => {
  const { login, password } = req.body;
  auth0Signup(login, password);
});
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
