require('dotenv').config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");
const bodyParser = require("body-parser");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const axios = require("axios");
var qr = require("qr-image");
const dns = require('dns');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);
let db;

async function connectDB() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");
    db = client.db(process.env.MONGODB_DB_NAME);
    app.locals.db = db;
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
  }
}
connectDB();

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

transporter.verify(function(error, success) {
  if (error) {
    console.log('Error with email server:', error);
  } else {
    console.log('Email server is ready to take our messages');
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.resolve(__dirname, "public")));

app.get("/", (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      jwt.verify(token, JWT_SECRET);
      return res.redirect('/API.html');
    } catch (err) {
      res.clearCookie('token');
    }
  }
  res.redirect('/login');
});
app.get("/login", (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      jwt.verify(token, JWT_SECRET);
      return res.redirect('/API.html');
    } catch (err) {
      res.clearCookie('token');
    }
  }
  res.sendFile(path.join(__dirname, "public", "login.html"));
});
app.get("/register", (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      jwt.verify(token, JWT_SECRET);
      return res.redirect('/API.html');
    } catch (err) {
      res.clearCookie('token');
    }
  }
  res.sendFile(path.join(__dirname, "public", "register.html"));
});
app.get("/main", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "main2.html"));
});

app.post("/register", async (req, res) => {
  const { username, email, password, password2 } = req.body;

  if (!username || !email || !password || !password2) {
    return res.send(
      `<script>alert("Error! All fields are required."); window.location="/register";</script>`
    );
  }

  if (password !== password2) {
    return res.send(
      `<script>alert("Error! Passwords do not match."); window.location="/register";</script>`
    );
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.send(
      `<script>alert("Error! Please enter a valid email address."); window.location="/register";</script>`
    );
  }

  try {
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.send(
        `<script>alert("Error! Username or email already exists."); window.location="/register";</script>`
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
      [username, email, hashedPassword]
    );

    res.send(
      `<script>alert("Registration successful!"); window.location="/login";</script>`
    );
  } catch (error) {
    console.error(error);
    res.send(
      `<script>alert("Server error! Please try again."); window.location="/register";</script>`
    );
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .send(
        `<script>alert("Ошибка! Заполните все поля."); window.location="/login";</script>`
      );
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (result.rows.length === 0) {
      return res
        .status(400)
        .send(
          `<script>alert("Ошибка! Пользователь не найден."); window.location="/login";</script>`
        );
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res
        .status(400)
        .send(
          `<script>alert("Ошибка! Неверный пароль."); window.location="/login";</script>`
        );
    }


    const token = jwt.sign({ username: user.username }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.cookie("token", token, { httpOnly: true, maxAge: 3600000 });
    res.redirect("/API.html");
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .send(
        `<script>alert("Ошибка сервера! Попробуйте снова."); window.location="/login";</script>`
      );
  }
});

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  
  if (!token) {
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    return res.redirect('/login');
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    res.clearCookie('token');
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    return res.redirect('/login');
  }
}

app.get("/main", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "main.html"));
});

app.use('/api/*', requireAuth);
app.use('/weather', requireAuth);
app.use('/blogs*', requireAuth);
app.use('/generate-qr', requireAuth);
app.use('/calculate-bmi', requireAuth);

app.use((req, res, next) => {
  const publicPaths = ['/login', '/register', '/'];
  if (!publicPaths.includes(req.path) && req.path.endsWith('.html')) {
    requireAuth(req, res, next);
  } else {
    next();
  }
});


app.get("/logout", (req, res) => {
  res.clearCookie('token', { 
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  });
  res.redirect('/login');
});

app.get("/API.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "API.html"));
});

app.get("/CRUD.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "CRUD.html"));
});

app.get("/qr-image.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "qr-image.html"));
});

app.get("/BMI.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "BMI.html"));
});

app.post("/generate-qr", requireAuth, (req, res) => {
  const url = req.body.url;
  const qrCode = qr.imageSync(url, { type: "png" });
  res.type("png");
  res.send(qrCode);
});

app.post("/calculate-bmi", requireAuth, (req, res) => {
  const { weight, height } = req.body;
  const weightNum = parseFloat(weight);
  const heightNum = parseFloat(height);

  if (!weightNum || !heightNum || weightNum <= 0 || heightNum <= 0) {
    return res.json({ error: "Weight and height must be positive numbers" });
  }

  const bmi = weightNum / (heightNum * heightNum);
  let category = "";

  if (bmi < 18.5) category = "Underweight";
  else if (bmi >= 18.5 && bmi < 24.9) category = "Normal weight";
  else if (bmi >= 25 && bmi < 29.9) category = "Overweight";
  else category = "Obese";

  res.json({ bmi: bmi.toFixed(2), category });
});

const getWeather = async (city) => {
  const apiKey = process.env.WEATHER_API_KEY;
  const url = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(
    city
  )}&appid=${apiKey}&units=metric`;

  const axiosConfig = {
    timeout: 5000,
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  };

  try {
    const response = await axios.get(url, axiosConfig);
    return response.data;
  } catch (error) {
    console.error("Error getting weather data:", {
      message: error.message,
      status: error.response?.status,
      data: error.response?.data,
      url: url
    });
    return null;
  }
};

const getNews = async (city) => {
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  const apiKey = process.env.NEWS_API_KEY;
  const url = `https://newsapi.org/v2/everything?q=${encodeURIComponent(
    city
  )}&apiKey=${apiKey}`;

  const axiosConfig = {
    timeout: 5000,
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'X-Api-Key': apiKey
    }
  };

  try {
    const response = await axios.get(url, axiosConfig);
    return (response.data.articles || []).slice(0, 3);
  } catch (error) {
    console.error("Error getting news data:", {
      message: error.message,
      status: error.response?.status,
      data: error.response?.data,
      url: url
    });
    return [];
  }
};

const getTimeZone = async (lat, lon) => {
  const apiKey = process.env.TIMEZONE_API_KEY;
  const url = `https://api.timezonedb.com/v2.1/get-time-zone?key=${apiKey}&format=json&by=position&lat=${lat}&lng=${lon}`;

  const axiosConfig = {
    timeout: 5000,
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  };

  try {
    const response = await axios.get(url, axiosConfig);
    return response.data;
  } catch (error) {
    console.error("Error getting timezone data:", {
      message: error.message,
      status: error.response?.status,
      data: error.response?.data,
      url: url
    });
    return {
      formatted: new Date().toLocaleString()
    };
  }
};

const getAirQuality = async (lat, lon) => {
  const apiKey = process.env.WEATHER_API_KEY;
  const url = `https://api.openweathermap.org/data/2.5/air_pollution?lat=${lat}&lon=${lon}&appid=${apiKey}`;

  const axiosConfig = {
    timeout: 5000,
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  };

  try {
    const response = await axios.get(url, axiosConfig);
    return response.data;
  } catch (error) {
    console.error("Error getting air quality data:", {
      message: error.message,
      status: error.response?.status,
      data: error.response?.data,
      url: url
    });
    return null;
  }
};

app.get("/weather", requireAuth, async (req, res) => {
  const city = req.query.city;
  const weatherData = await getWeather(city);

  if (weatherData) {
    const { name, main, weather, wind, coord, sys, rain } = weatherData;
    const { lat, lon } = coord;
    const temperature = main.temp;
    const feelsLike = main.feels_like;
    const humidity = main.humidity;
    const pressure = main.pressure;
    const windSpeed = wind.speed;
    const description = weather[0].description;
    const iconUrl = `http://openweathermap.org/img/wn/${weather[0].icon}.png`;
    const country = sys.country;

    const newsData = await getNews(city);
    const newsHtml = newsData.length ? newsData
      .slice(0, 3)
      .map(
        (article) => `
          <div class="news-item">
            <a href="${article.url}" target="_blank"><strong>${article.title || 'No title'}</strong></a>
            <p>${article.description || 'No description available'}</p>
          </div>
        `
      )
      .join("") : '<p>No news available at the moment</p>';

    const timeZoneData = await getTimeZone(lat, lon);
    const timeString = timeZoneData?.formatted || new Date().toLocaleString();

    const rainVolume = weatherData.rain ? weatherData.rain["1h"] : 0;
    const snowVolume = weatherData.snow ? weatherData.snow["1h"] : 0;

    const totalPrecipitation = rainVolume + snowVolume;

    // Get air quality data
    const airQualityData = await getAirQuality(lat, lon);
    const aqi = airQualityData?.list?.[0]?.main?.aqi || 'N/A';
    
    // Get AQI description
    const aqiDescriptions = {
      1: 'Good',
      2: 'Fair',
      3: 'Moderate',
      4: 'Poor',
      5: 'Very Poor'
    };
    
    const aqiDescription = aqiDescriptions[aqi] || 'Unknown';
    
    // Get country flag URL
    const flagUrl = `https://flagcdn.com/${sys.country.toLowerCase()}.svg`;

    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Weather in ${city}</title>
    <script src="https://maps.googleapis.com/maps/api/js?key=${process.env.GOOGLE_MAPS_API_KEY}&callback=initMap" async defer></script>
    <style>
        /* Global Styles */
        body {
            padding: 50px 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            margin: 0;
            color: #fff;
        }
        h1, h3 {
            color: #333;
            margin-bottom: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 40px;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        .form-container {
            margin-bottom: 30px;
        }
        input[type="text"] {
            padding: 12px;
            font-size: 18px;
            width: 60%;
            margin-right: 12px;
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }
        input[type="text"]:focus {
            border-color: #1e90ff;
            outline: none;
        }
        button {
            padding: 12px 24px;
            font-size: 18px;
            background-color: #1e90ff;
            color: #fff;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        button:hover {
            background-color: #4682b4;
        }
        button:focus {
            outline: none;
        }
        /* Weather Card Styles */
        .weather-card {
            display: flex;
            justify-content: center;
            padding: 20px;
            margin-top: 30px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            background: rgba(0, 0, 0, 0.9);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
            text-align: left;
            width: 95%;
        }

        .weather-card table {
            padding: 20px 0px;
            width: 100%;
            border-collapse: collapse;
        }

        .weather-card td {
            padding: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            color: #fff;
        }

        .weather-card td strong {
            color: #1e90ff;
        }

        .weather-card .weather-icon {
            width: 80px;
            height: 80px;
            margin-right: 20px;
        }

        .weather-card h3 {
            font-size: 28px;
            color: #fff;
            margin: 0;
        }

        /* Map Styling */
        #map {
            height: 400px;
            width: 100%;
            margin-top: 20px;
            border-radius: 12px;
        }
        /* Error Message */
        .error-message {
            color: #ff4757;
            font-size: 20px;
            margin-top: 20px;
            text-align: center;
        }
        #map {
            height: 100vh;
            width: 100%;
        }
        /* Responsive Adjustments */
        @media (max-width: 768px) {
            .container {
                padding: 20px;
            }
            input[type="text"] {
                width: 80%;
            }
            button {
                padding: 10px 20px;
            }
            .weather-card h3 {
                font-size: 24px;
            }
        }

        #back{
        position: relative;
        right: 40%;
        color: #fff;
        text-decoration: none;
        font-size: 20px;
        font-weight: bold;
        }
        
        .country-flag {
          height: 30px;
          vertical-align: middle;
          margin-left: 10px;
          border-radius: 4px;
        }
        
        .weather-card {
          background: rgba(0, 0, 0, 0.9);
          padding: 20px;
          border-radius: 12px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          margin: 20px 0;
        }

        .news {
            background: rgba(0, 0, 0, 0.9);
            border-radius: 12px;
            padding: 25px;
            margin-top: 30px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .news h2 {
            color: #fff;
            margin-bottom: 20px;
        }

        .news-item {
            padding: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }

        .news-item a {
            color: #1e90ff;
            text-decoration: none;
        }

        .news-item p {
            color: #ccc;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <a id="back" href="/API.html">⬅ Go back</a>
        <h1>Weather in ${name}, ${country} <img src="${flagUrl}" alt="${country} flag" class="country-flag"></h1>
        <div class="weather-card">
        <table>
        <tr>
            <td><img src="${iconUrl}" alt="${description}" class="weather-icon"></td>
            <td colspan="2"><h3>${temperature}°C</h3></td>
        </tr>
        <tr>
            <td><strong>Description:</strong></td>
            <td colspan="2">${description}</td>
        </tr>
        <tr>
            <td><strong>Feels like:</strong></td>
            <td>${feelsLike}°C</td>
        </tr>
        <tr>
            <td><strong>Humidity:</strong></td>
            <td>${humidity}%</td>
        </tr>
        <tr>
            <td><strong>Pressure:</strong></td>
            <td>${pressure} hPa</td>
        </tr>
        <tr>
            <td><strong>Wind speed:</strong></td>
            <td>${windSpeed} m/s</td>
        </tr>
        <tr>
            <td><strong>Air Quality Index:</strong></td>
            <td>${aqiDescription} (${aqi})</td>
        </tr>
        <tr>
            <td><strong>Total precipitation (last 3h):</strong></td>
            <td>${totalPrecipitation} mm</td>
        </tr>
        </table>
    </div>


        <h3>Current Time</h3>
        <div class="weather-card">
            <p>Time: ${timeString}</p>
        </div>

        <div class="news">
            <h2>News</h2>
            ${newsHtml}
        </div>

        <h1>Google Maps API</h1>
        <div id="map"></div>
    </div>

    <script>
        function initMap() {
            const cityCoordinates = { lat: ${lat}, lng: ${lon} };
            const map = new google.maps.Map(document.getElementById("map"), {
                zoom: 10,
                center: cityCoordinates,
            });
            const marker = new google.maps.Marker({
                position: cityCoordinates,
                map: map,
                title: "${name}",
            });
        }
    </script>
</body>
</html>
`);
  } else {
    res.send(`
      <h1>Error fetching weather data for ${city}</h1>
      <a href="/">Go back</a>
    `);
  }
});

app.post("/blogs", requireAuth, async (req, res) => {
  const db = req.app.locals.db;
  const { title, body, author } = req.body;
  if (!title || !body)
    return res.status(400).json({ error: "Title and body are required" });

  const newBlog = {
    title,
    body,
    author: author || "Anonymous",
    createdAt: new Date(),
  };
  const result = await db.collection("blogs").insertOne(newBlog);
  res.status(201).json({ message: "Blog created", postId: result.insertedId });
});
app.get("/blogs", requireAuth, async (req, res) => {
  const db = req.app.locals.db;
  const blogs = await db.collection("blogs").find().toArray();
  res.status(200).json(blogs);
});
app.get("/blogs/:id", requireAuth, async (req, res) => {
  const db = req.app.locals.db;
  const blog = await db
    .collection("blogs")
    .findOne({ _id: new ObjectId(req.params.id) });
  if (!blog) return res.status(404).json({ error: "Blog not found" });
  res.status(200).json(blog);
});
app.put("/blogs/:id", requireAuth, async (req, res) => {
  const db = req.app.locals.db;
  const { title, body, author } = req.body;
  const updateData = {};
  if (title) updateData.title = title;
  if (body) updateData.body = body;
  if (author) updateData.author = author;

  const result = await db
    .collection("blogs")
    .updateOne({ _id: new ObjectId(req.params.id) }, { $set: updateData });

  if (result.matchedCount === 0)
    return res.status(404).json({ error: "Blog not found" });
  res.status(200).json({ message: "Blog updated" });
});
app.delete("/blogs/:id", requireAuth, async (req, res) => {
  const db = req.app.locals.db;
  const result = await db
    .collection("blogs")
    .deleteOne({ _id: new ObjectId(req.params.id) });
  if (result.deletedCount === 0)
    return res.status(404).json({ error: "Blog not found" });
  res.status(200).json({ message: "Blog deleted" });
});

app.post("/send-email", requireAuth, async (req, res) => {
  const { to, subject, message } = req.body;

  if (!to || !subject || !message) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(to)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: to,
      subject: subject,
      text: message,
    };

    await transporter.sendMail(mailOptions);
    
    res.status(200).json({ message: 'Email sent successfully' });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

app.get("/Nodemailer.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "Nodemailer.html"));
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  if (req.xhr || req.headers.accept.indexOf('json') > -1) {
    return res.status(500).json({ error: 'Something went wrong!' });
  }
  res.status(500).send('Something went wrong!');
});

dns.setServers(['1.1.1.1', '1.0.0.1']);
