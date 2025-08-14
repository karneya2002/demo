 const express = require('express');
  const mysql = require('mysql2');
  const cors = require('cors');
  const bcrypt = require('bcrypt');
  const nodemailer = require('nodemailer');
  const dotenv = require('dotenv');
  dotenv.config();
  const Razorpay = require('razorpay');
  const app = express();
  app.use(cors());
  app.use(express.json());
  app.use('/uploads', express.static('uploads'));
  const crypto = require('crypto');
  const axios = require('axios');


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
  key_secret: process.env.RAZORPAY_SECRET,
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
app.get('/api/banquets', (req, res) => {
  const sql = `
    SELECT b.*, GROUP_CONCAT(i.image_url) AS images
    FROM banquet_halls b
    LEFT JOIN banquet_images i ON b.id = i.banquet_id
    GROUP BY b.id
  `;

  db.query(sql, (err, results) => {
    if (err) return res.status(500).send(err);

    // Convert comma-separated images into an array
    const formatted = results.map(row => ({
      ...row,
      images: row.images ? row.images.split(',') : []
    }));

    res.json(formatted);
  });
});


// Category-wise Mahals List:
app.get('/api/categories', (req, res) => {
    db.query('SELECT DISTINCT category FROM banquet_halls', (err, results) => {
      if (err) return res.status(500).send(err);
      res.json(results.map(r => r.category));
    });
  });


  // Booking Endpoint:
app.post('/api/book-now', async (req, res) => {
  try {
    const { 
      banquetId,       // foreign key to banquet_halls
      name, 
      phone, 
      email, 
      eventType, 
      address, 
      mahalName, 
      location, 
      price, 
      dates, 
      bookingDate      // optional single "main" booking date
    } = req.body;

    // --- Required fields check ---
    if (!banquetId || !name || !phone || !email || !eventType || !address || !mahalName || !location || !price || !dates) {
      return res.status(400).json({ success: false, message: 'Please fill all required fields.' });
    }

    // --- Phone validation ---
    const phoneRegex = /^[6-9]\d{9}$/;
    if (!phoneRegex.test(String(phone))) {
      return res.status(400).json({ success: false, message: 'Invalid phone number.' });
    }

    // --- Email validation ---
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(String(email))) {
      return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    // --- Normalize dates to array ---
    const dateList = Array.isArray(dates)
      ? dates.map(d => String(d).trim()).filter(Boolean)
      : String(dates).split(',').map(d => d.trim()).filter(Boolean);

    if (dateList.length === 0) {
      return res.status(400).json({ success: false, message: 'At least one date is required.' });
    }

    // --- Check if any date is already booked ---
    db.query('SELECT dates FROM bookings WHERE banquet_id = ?', [banquetId], (checkErr, rows) => {
      if (checkErr) {
        console.error('Check bookings error:', checkErr);
        return res.status(500).json({ success: false, message: 'Error checking existing bookings.' });
      }

      const existingDates = rows.flatMap(r => {
        try { return JSON.parse(r.dates); }
        catch { return String(r.dates || '').split(',').map(s => s.trim()).filter(Boolean); }
      });

      const conflict = dateList.some(d => existingDates.includes(d));
      if (conflict) {
        return res.status(409).json({ success: false, message: 'Selected date(s) already booked.' });
      }

      // --- Insert booking ---
      const insertSql = `
        INSERT INTO bookings 
        (name, phone, event_type, address, mahal_name, location, price, dates, booking_date, status, banquet_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
      `;

      const params = [
        name,
        phone,
        eventType,
        address,
        mahalName,
        location,
        Number(price),
        JSON.stringify(dateList),  // Store as JSON string
        bookingDate || null,       // Optional single main date
        banquetId
      ];

      db.query(insertSql, params, (insertErr, result) => {
        if (insertErr) {
          console.error('Insert booking error:', insertErr);
          return res.status(500).json({ success: false, message: 'Failed to save booking.' });
        }

        // --- Send confirmation email (non-blocking) ---
        transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Booking Confirmation - Kumbam',
          html: `<h2>Hi ${name},</h2>
                 <p>Your booking for <b>${eventType}</b> at <b>${mahalName}</b> on <b>${dateList.join(', ')}</b> has been received.</p>
                 <p>Total Price: ₹${price}</p>`
        }).catch(e => console.error('Email send error:', e));

        return res.status(200).json({
          success: true,
          message: 'Booking successful',
          bookingId: result.insertId
        });
      });
    });
  } catch (e) {
    console.error('book-now top-level error:', e);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});






app.get('/api/booked-dates/:banquetId', (req, res) => {
  const { banquetId } = req.params;

  if (!banquetId) {
    return res.status(400).json({ success: false, message: 'banquetId is required' });
  }

  const query = 'SELECT dates FROM bookings WHERE banquet_id = ?';

  db.query(query, [banquetId], (err, results) => {
    if (err) {
      console.error('Error fetching booked dates:', err);
      return res.status(500).json({
        success: false,
        message: 'Database error while fetching booked dates',
      });
    }

    // If no bookings found
    if (!results.length) {
      return res.status(200).json({
        success: true,
        bookedDates: [],
      });
    }

    // Merge all booked dates into one array
    const bookedDates = results.flatMap(row => {
      try {
        // Try parsing JSON stored in `dates` column
        return JSON.parse(row.dates);
      } catch {
        // Fallback if stored as CSV string
        return String(row.dates || '')
          .split(',')
          .map(s => s.trim())
          .filter(Boolean);
      }
    });

    return res.status(200).json({
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



  // ✅ Booking Insert
  app.get('/banquets/:id', (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM banquet_halls WHERE id = ?', [id], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    if (!result.length) return res.status(404).json({ error: 'Not found' });
    res.json(result[0]);
  });
});


 app.listen(5000, '0.0.0.0', () => {
    console.log('✅ Server running on port 5000');
  });
