 const express = require('express');
  const mysql = require('mysql2');
 
  const bcrypt = require('bcrypt');
  const nodemailer = require('nodemailer');
  const dotenv = require('dotenv');
  dotenv.config();
  const Razorpay = require('razorpay');
  const app = express();
;
  app.use(express.json());
  app.use('/uploads', express.static('uploads'));
  const crypto = require('crypto');
  const axios = require('axios');

const cors = require("cors");
app.use(cors({ origin: "*" }));



  // ✅ MySQL Connection Pool
  const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  // ✅ Test DB Connection
  db.getConnection((err, connection) => {
    if (err) {
      console.error('❌ DB pool connection error:', err);
    } else {
      console.log('✅ Connected to Railway DB via pool!');
      connection.release();
    }
  });
// Payment Gateway Setup
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Nodemailer Setup
 const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  // User Registration:
  app.post('/api/signup', async (req, res) => {
    const { fullName, phone, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
      if (err) return res.status(500).json({ success: false });
      if (results.length > 0) return res.json({ success: false, message: 'User already exists' });

      db.query(
        'INSERT INTO users (full_name, phone, email, password) VALUES (?, ?, ?, ?)',
        [fullName, phone, email, hashedPassword],
        err => {
          if (err) return res.json({ success: false, message: 'Signup failed' });
          res.json({ success: true });
        }
      );
    });
  });

// User Login with Otp:
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err || results.length === 0) return res.json({ success: false, message: 'User not found' });

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.json({ success: false, message: 'Incorrect password' });

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 5 * 60000);

      db.query(
        'INSERT INTO otp_verification (email, otp, expires_at) VALUES (?, ?, ?)',
        [email, otp, expiresAt],
        err => {
          if (err) return res.json({ success: false });

          transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your OTP - KUMBAM',
            text: `Welcome to book the mahal in a easy way ${otp}`,
          }, (err) => {
            if (err) return res.json({ success: false });
            res.json({ success: true, token: otp, phone: user.phone, username: user.full_name });
          });
        }
      );
    });
  });


  // OTP Verification:
  app.post('/api/verify-email-otp', (req, res) => {
    const { email, otp } = req.body;
    db.query('SELECT * FROM otp_verification WHERE email = ? ORDER BY id DESC LIMIT 1', [email], (err, results) => {
      if (err || results.length === 0) return res.json({ success: false });
      const record = results[0];
      const now = new Date();
      if (record.otp !== otp || now > record.expires_at) return res.json({ success: false });
      res.json({ success: true });
    });
  });

// Forgot Password:
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60000);

    db.query('INSERT INTO otp_verification (email, otp, expires_at) VALUES (?, ?, ?)', [email, otp, expiresAt], (err) => {
      if (err) return res.json({ success: false });

      transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your KUMBAM Password Reset OTP',
        text: `Your OTP to reset paassword is ${otp}`,
      }, (err) => {
        if (err) return res.json({ success: false });
        res.json({ success: true });
      });
    });
  });

  // Reset Password:
   app.post('/api/reset-password', async (req, res) => {
    const { email, otp, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('SELECT * FROM otp_verification WHERE email = ? ORDER BY id DESC LIMIT 1', [email], (err, results) => {
      if (err || results.length === 0) return res.json({ success: false });
      const record = results[0];
      const now = new Date();
      if (record.otp !== otp || now > record.expires_at) return res.json({ success: false });

      db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], (err) => {
        if (err) return res.json({ success: false });
        res.json({ success: true });
      });
    });
  });


  // Resend OTP:
   app.post('/api/resend-email-otp', (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ success: false, message: 'Email required' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 2 * 60000);  //2minutes expiry

  db.query(
    'INSERT INTO otp_verification (email, otp, expires_at) VALUES (?, ?, ?)',
    [email, otp, expiresAt],
    (err) => {
      if (err) return res.status(500).json({ success: false, message: 'DB Error' });

      transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Resend OTP - KUMBAM',
        text: `Your Resend OTP valid for few mintues is ${otp}`,
      }, (err) => {
        if (err) return res.status(500).json({ success: false, message: 'Failed to send OTP' });
        res.json({ success: true, message: 'OTP sent successfully' });
      });
    }
  );
});

// Mahals List Insertion:
app.post('/api/banquets', (req, res) => {
  const { name, category, address, capacity, price, description, images } = req.body;

  // Insert banquet hall
  const hallSql = `INSERT INTO banquet_halls (name, category, address, capacity, price, description) VALUES (?, ?, ?, ?, ?, ?)`;
  db.query(hallSql, [name, category, address, capacity, price, description], (err, hallResult) => {
    if (err) return res.status(500).send(err);

    const banquetId = hallResult.insertId;

    // Insert images if provided
    if (images && images.length > 0) {
      const imageValues = images.map(url => [banquetId, url]);
      db.query(`INSERT INTO banquet_images (banquet_id, image_url) VALUES ?`, [imageValues], (imgErr) => {
        if (imgErr) return res.status(500).send(imgErr);
        res.json({ message: 'Banquet added successfully', banquetId });
      });
    } else {
      res.json({ message: 'Banquet added without images', banquetId });
    }
  });
});


// Mahals List To View For Multiple Images:
app.get('/api/banquet/:id', (req, res) => {
  const banquetId = req.params.id;

  const sql = `
    SELECT b.*, GROUP_CONCAT(i.image_url) AS images
    FROM banquet_halls b
    LEFT JOIN banquet_images i ON b.id = i.banquet_id
    WHERE b.id = ?
    GROUP BY b.id
  `;

  db.query(sql, [banquetId], (err, results) => {
    if (err) return res.status(500).send(err);

    if (results.length === 0) {
      return res.status(404).json({ message: 'Banquet not found' });
    }

    const banquet = {
      ...results[0],
      images: results[0].images ? results[0].images.split(',') : []
    };

    res.json(banquet);
  });
});

// Fetch all banquet halls
// ✅ Get all banquets (mysql2 callback pool + promise wrapper)
// app.get('/api/banquets', async (req, res) => {
//   try {
//     const [rows] = await db.promise().query(`
//       SELECT 
//         id,
//         name,
//         location AS address,       
//         guest_capacity AS capacity, 
//         price,
//         image_url,
//         dining_capacity,
//         rooms,
//         parking,
//         ac,
//         category,
//         description
//       FROM banquet_halls
//     `);
//     res.json(rows);
//   } catch (err) {
//     console.error('❌ Database query failed:', err);
//     res.status(500).json({ error: 'Database query failed' });
//   }
// });

// ✅ Get all banquets with multiple images
app.get('/api/banquets', async (req, res) => {
  try {
    const [rows] = await db.promise().query(`
      SELECT 
        b.id,
        b.name,
        b.location AS address,       
        b.guest_capacity AS capacity, 
        b.price,
        GROUP_CONCAT(i.image_url) AS images,
        b.dining_capacity,
        b.rooms,
        b.parking,
        b.ac,
        b.category,
        b.description
        
      FROM banquet_halls b
      LEFT JOIN  banquet_hall_images i ON b.id = i.banquet_id
      GROUP BY b.id
    `);

    // 🔹 Convert comma-separated images into an array
    const data = rows.map(row => ({
      ...row,
      images: row.images ? row.images.split(',') : []
    }));

    res.json(data);
  } catch (err) {
    console.error('❌ Database query failed:', err);
    res.status(500).json({ error: 'Database query failed' });
  }
});



// Category-wise Mahals List:
app.get('/api/categories', (req, res) => {
    db.query('SELECT DISTINCT category FROM banquet_halls', (err, results) => {
      if (err) return res.status(500).send(err);
      res.json(results.map(r => r.category));
    });
  });


// ✅ Book Now API
app.post("/api/book-now", async (req, res) => {
  try {
    const {
      name,
      phone,
      event_type,
      address,
      mahal_name,
      location,
      price,
      dates,
      booking_date,
      status,
      banquet_id,
    } = req.body;

    // Validation
    if (!name || !phone || !event_type || !dates || !banquet_id) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const created_at = new Date();

    const query = `
      INSERT INTO bookings 
      (name, phone, event_type, address, mahal_name, location, price, dates, created_at, booking_date, status, banquet_id) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const values = [
      name,
      phone,
      event_type,
      address,
      mahal_name,
      location,
      price,
      dates,
      created_at,
      booking_date,
      status || "pending", // default value
      banquet_id,
    ];

    db.query(query, values, (err, result) => {
      if (err) {
        console.error("❌ Database Error:", err);
        return res.status(500).json({ message: "Database error" });
      }
      res.status(201).json({ message: "✅ Booking successful", bookingId: result.insertId });
    });
  } catch (error) {
    console.error("❌ Server Error:", error);
    res.status(500).json({ message: "Server error" });
  }
});



app.get("/api/booked-dates", async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      "SELECT dates FROM bookings WHERE status != 'cancelled'"
    );

    const bookedDates = rows.map(r => r.dates);
    res.json({ bookedDates });
  } catch (err) {
    console.error("❌ Failed to fetch booked dates:", err);
    res.status(500).json({ error: "Database error" });
  }
});



app.get('/api/booked-dates/:hallId', (req, res) => {
  const { hallId } = req.params;

  const query = 'SELECT booking_date FROM bookings WHERE banquet_id = ?';

  db.query(query, [hallId], (err, results) => {
    if (err) {
      console.error('Error fetching booked dates:', err);
      return res.status(500).json({
        success: false,
        message: 'Database error while fetching booked dates',
      });
    }

    if (!results.length) {
      return res.status(200).json({
        success: true,
        bookedDates: [],
      });
    }

    // Merge all booked dates into a single flat array
    const bookedDates = results.flatMap(row => {
      try {
        return JSON.parse(row.dates); // if stored as JSON
      } catch {
        return String(row.dates || '')
          .split(',')
          .map(d => d.trim())
          .filter(Boolean);
      }
    });

    res.status(200).json({
      success: true,
      bookedDates,
    });
  });
});





// Filter available halls for a given date

app.get('/api/available-halls', (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ success: false, message: 'date is required (DD-MM-YYYY)' });

  const sql = `
    SELECT h.*
    FROM banquet_halls h
    WHERE NOT EXISTS (
      SELECT 1
      FROM bookings b
      WHERE b.hall_id = h.id
        AND JSON_SEARCH(b.dates, 'one', ?) IS NOT NULL
    )
  `;
  db.query(sql, [date], (err, result) => {
    if (err) {
      console.error('available-halls error:', err);
      return res.status(500).json({ success: false, message: 'Error fetching halls' });
    }
    res.json({ success: true, availableHalls: result });
  });
});





app.post('/api/initiate-payment', async (req, res) => {
  try {
    const { amount, bookingId } = req.body;

    const order = await razorpay.orders.create({
      amount: amount * 100, // amount in paise
      currency: "INR",
      receipt: bookingId,
    });

    res.json({
      success: true,
      orderId: order.id,
      amount: order.amount,
      key: process.env.RAZORPAY_KEY_ID,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to create Razorpay order" });
  }
});

// ✅ CHECK PAYMENT STATUS
app.get('/api/check-payment-status/:transactionId', async (req, res) => {
  const { transactionId } = req.params;

  const xVerify = crypto
    .createHash('sha256')
    .update(`/pg/v1/status/${MERCHANT_ID}/${transactionId}` + SALT_KEY)
    .digest('hex') + '###1';

  try {
    const response = await axios.get(
      `${BASE_URL}/pg/v1/status/${MERCHANT_ID}/${transactionId}`,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-VERIFY': xVerify,
          'X-MERCHANT-ID': MERCHANT_ID,
        },
      }
    );

    const status = response.data.data.transactionStatus;

    await db.promise().query(
      `UPDATE payments SET status = ? WHERE transaction_id = ?`,
      [status, transactionId]
    );

    res.json({ success: true, status });
  } catch (err) {
    console.error('❌ Status Check Error:', err?.response?.data || err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch payment status' });
  }
});


  app.get("/api/muhurtham_dates_2025/:hallId", async (req, res) => {
    try {
      const { hallId } = req.params;

      const [rows] = await db.promise().query(
        "SELECT date, description FROM muhurtham_dates_2025 WHERE hall_id = ?",
        [hallId]
      );

      if (rows.length === 0) {
        return res.json({ valarpirai: [], theipirai: [] });
      }

      // Group dates by description
      const valarpirai = rows
        .filter(r => r.description && r.description.toLowerCase() === "valarpirai")
        .map(r => r.date.toISOString().split("T")[0]); // format YYYY-MM-DD

      const theipirai = rows
        .filter(r => r.description && r.description.toLowerCase() === "theipirai")
        .map(r => r.date.toISOString().split("T")[0]);

      res.json({ valarpirai, theipirai });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Error fetching muhurtham dates" });
    }
  });



// ✅ MARK PAYMENT SUCCESSFUL (after callback)
app.post('/api/payment-success', async (req, res) => {
  const { transactionId, bookingId } = req.body;

  if (!transactionId || !bookingId) {
    return res.status(400).json({ success: false, message: 'Missing transaction or booking ID' });
  }

  try {
    const [result] = await db.promise().query(
      `UPDATE payments SET status = 'COMPLETED' WHERE transaction_id = ? AND booking_id = ?`,
      [transactionId, bookingId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Payment not found or already updated' });
    }

    res.json({ success: true, message: 'Payment marked as completed' });
  } catch (error) {
    console.error('❌ Payment Success Handler Error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});






  // ✅ Booking Insert
  app.get('/banquets/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM banquet_halls WHERE id = ?', [id], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    if (!result.length) return res.status(404).json({ error: 'Not found' });
    res.json(result[0]);
  });
});



// Get Muhurtham Dates for a specific hall
// app.get('/api/muhurtham_dates_2025/:hallId', async (req, res) => {
//   try {
//     const { hallId } = req.params;

//     // ✅ Query is correct: fetches by hall_id and orders by date
//     const [rows] = await db.query(
//       `SELECT id, hall_id, date, description 
//        FROM muhurtham_dates_2025 
//        WHERE hall_id = ? 
//        ORDER BY date ASC`,
//       [hallId]
//     );

//     // ✅ Returns JSON response with results
//     res.json(rows);
//   } catch (error) {
//     console.error('Error fetching muhurtham dates:', error);
//     res.status(500).json({ message: 'Server error while fetching muhurtham dates' });
//   }
// });


// app.get('/api/muhurtham_dates_2025/:hallId', async (req, res) => {
//   try {
//     const { hallId } = req.params;

//     // 1️⃣ Fetch Muhurtham Dates
//     const [muhurthamRows] = await db.query(
//       `SELECT date, description 
//        FROM muhurtham_dates_2025 
//        WHERE hall_id = ? 
//        ORDER BY date ASC`,
//       [hallId]
//     );

//     // 2️⃣ Fetch Booked Dates
//     const [bookedRows] = await db.query(
//       `SELECT dates AS date, status 
//        FROM bookings 
//        WHERE banquet_id = ? 
//        AND status = 'booked'
//        ORDER BY dates ASC`,
//       [hallId]
//     );

//     // 3️⃣ Format response
//     const response = {
//       muhurthamDates: muhurthamRows.map(row => ({
//         date: row.date,
//         type: "muhurtham",
//         description: row.description
//       })),
//       bookedDates: bookedRows.map(row => ({
//         date: row.date,
//         type: "booked",
//         status: row.status
//       }))
//     };

//     res.json(response);

//   } catch (error) {
//     console.error('Error fetching dates:', error);
//     res.status(500).json({ message: 'Server error while fetching dates' });
//   }
// });



 app.listen(5000, '0.0.0.0', () => {
    console.log('✅ Server running on port 5000');
  });
