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
// Add new banquet with images
app.post('/api/banquets', (req, res) => {
  const { name, category, address, capacity, price, description, images } = req.body;

  // Insert banquet hall
  const hallSql = `INSERT INTO banquet_halls (name, category, address, capacity, price, description) VALUES (?, ?, ?, ?, ?, ?)`;
  db.query(hallSql, [name, category, address, capacity, price, description], (err, hallResult) => {
    if (err) return res.status(500).send(err);

    const banquetId = hallResult.insertId;

    // Insert images if provided
    if (images && images.length > 0) {
      const imageValues = images.map(img => [banquetId, img.url]); // <-- img.url instead of plain string
      db.query(`INSERT INTO banquet_images (banquet_id, image_url) VALUES ?`, [imageValues], (imgErr) => {
        if (imgErr) return res.status(500).send(imgErr);
        res.json({ message: 'Banquet added successfully', banquetId });
      });
    } else {
      res.json({ message: 'Banquet added without images', banquetId });
    }
  });
});

// Fetch a single banquet with images
app.get('/api/banquet/:id', (req, res) => {
  const banquetId = req.params.id;

  const sql = `
    SELECT b.*, GROUP_CONCAT(i.image_url SEPARATOR '|||') AS images
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
      images: results[0].images
        ? results[0].images.split('|||').map(url => ({ url })) // <-- return as objects
        : []
    };

    res.json(banquet);
  });
});

// Fetch all banquets with images
// app.get('/api/banquets', (req, res) => {
//   const sql = `
//     SELECT b.*, GROUP_CONCAT(i.image_url SEPARATOR '|||') AS images
//     FROM banquet_halls b
//     LEFT JOIN banquet_images i ON b.id = i.banquet_id
//     GROUP BY b.id
//   `;

//   db.query(sql, (err, results) => {
//     if (err) return res.status(500).send(err);

//     const formatted = results.map(row => ({
//       ...row,
//       images: row.images
//         ? row.images.split('|||').map(url => ({ url })) // <-- return as objects
//         : []
//     }));

//     res.json(formatted);
//   });
// });
app.get('/api/banquets', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM banquet_halls');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error while fetching banquets' });
  }
});


// Category-wise Mahals List:
app.get('/api/categories', (req, res) => {
    db.query('SELECT DISTINCT category FROM banquet_halls', (err, results) => {
      if (err) return res.status(500).send(err);
      res.json(results.map(r => r.category));
    });
  });


  // Booking Endpoint:
// app.post('/api/book-now', async (req, res) => {
//   try {
//     const {
//       banquetId,
//       name,
//       phone,
//       email,
//       eventType,
//       address,
//       price,
//       dates,
//       bookingDate
//     } = req.body;

//     // 1️⃣ Required fields check
//     const requiredFields = { banquetId, name, phone, email, eventType, address, price, dates };
//     for (const [key, value] of Object.entries(requiredFields)) {
//       if (
//         value === undefined ||
//         value === null ||
//         (typeof value === 'string' && !value.trim()) ||
//         (Array.isArray(value) && value.length === 0)
//       ) {
//         return res.status(400).json({ success: false, message: `Missing required field: ${key}` });
//       }
//     }

//     // 2️⃣ Fetch hall details
//     const [hall] = await new Promise((resolve, reject) => {
//       db.query(
//         'SELECT name AS mahalName, address AS location FROM banquet_halls WHERE id = ?',
//         [banquetId],
//         (err, rows) => (err ? reject(err) : resolve(rows))
//       );
//     });

//     if (!hall) {
//       return res.status(404).json({ success: false, message: 'Banquet hall not found.' });
//     }

//     const mahalName = hall.mahalName;
//     const location = hall.location;

//     // 3️⃣ Phone validation
//     if (!/^[6-9]\d{9}$/.test(String(phone))) {
//       return res.status(400).json({ success: false, message: 'Invalid phone number. Must be 10 digits starting with 6-9.' });
//     }

//     // 4️⃣ Email validation
//     if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email))) {
//       return res.status(400).json({ success: false, message: 'Invalid email format.' });
//     }

//     // 5️⃣ Normalize dates
//     const dateList = Array.isArray(dates)
//       ? dates.map(d => String(d).trim()).filter(Boolean)
//       : String(dates).split(',').map(d => d.trim()).filter(Boolean);

//     if (dateList.length === 0) {
//       return res.status(400).json({ success: false, message: 'At least one booking date is required.' });
//     }

//     // 6️⃣ Check already booked dates
//     const existingDates = await new Promise((resolve, reject) => {
//       db.query(
//         'SELECT dates FROM bookings WHERE banquet_id = ?',
//         [banquetId],
//         (err, rows) => {
//           if (err) return reject(err);
//           const all = rows.flatMap(r => {
//             try {
//               return JSON.parse(r.dates); // stored as JSON array
//             } catch {
//               return String(r.dates || '')
//                 .split(',')
//                 .map(s => s.trim())
//                 .filter(Boolean);
//             }
//           });
//           resolve(all);
//         }
//       );
//     });

//     const alreadyBooked = dateList.filter(d => existingDates.includes(d));
//     if (alreadyBooked.length > 0) {
//       return res.status(409).json({
//         success: false,
//         message: `These dates are already booked: ${alreadyBooked.join(', ')}`
//       });
//     }

//     // 7️⃣ Insert booking
//     const result = await new Promise((resolve, reject) => {
//       db.query(
//         `
//         INSERT INTO bookings 
//         (name, phone, event_type, address, mahal_name, location, price, dates, booking_date, status, banquet_id, email)
//         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
//         `,
//         [
//           name.trim(),
//           phone.trim(),
//           eventType.trim(),
//           address.trim(),
//           mahalName,
//           location,
//           Number(price),
//           JSON.stringify(dateList), // store as JSON
//           bookingDate || null,
//           banquetId,
//           email.trim()
//         ],
//         (err, result) => (err ? reject(err) : resolve(result))
//       );
//     });

//     // 8️⃣ Success
//     return res.status(200).json({
//       success: true,
//       message: 'Booking successful',
//       bookingId: result.insertId
//     });

//   } catch (e) {
//     console.error('book-now error:', e);
//     return res.status(500).json({ success: false, message: 'Server error.' });
//   }
// });



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





app.use('/api/initiate-payment', async (req, res) => {
  const { amount, phone, email, hallId, bookingId } = req.body;

  if (!amount || !phone || !email || !hallId || !bookingId) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  const transactionId = `TXN_${Date.now()}`;
  const payload = {
    merchantId: process.env.PHONEPE_MERCHANT_ID,
    merchantTransactionId: transactionId,
    merchantUserId: process.env.PHONEPE_USER_ID,
    amount: amount * 100,
    redirectUrl: `${process.env.PHONEPE_CALLBACK_URL}?transactionId=${transactionId}&bookingId=${bookingId}`,
    redirectMode: 'POST',
    mobileNumber: phone,
    paymentInstrument: { type: 'UPI_INTENT' },
  };

  const base64Payload = Buffer.from(JSON.stringify(payload)).toString('base64');
  const stringToSign = base64Payload + '/pg/v1/pay' + process.env.PHONEPE_SALT_KEY;
  const xVerify = crypto.createHash('sha256').update(stringToSign).digest('hex') + `###${process.env.PHONEPE_SALT_INDEX}`;

  try {
    const response = await axios.post(
      'https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/pay',
      { request: base64Payload },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-VERIFY': xVerify,
          accept: 'application/json',
        },
      }
    );

    const redirectUrl = response?.data?.data?.instrumentResponse?.redirectInfo?.url;
    if (!redirectUrl) {
      return res.status(502).json({ success: false, message: 'No payment link from PhonePe' });
    }

    await db.promise().query(
      `INSERT INTO payments (transaction_id, booking_id, status, amount, method, email, phone) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [transactionId, bookingId, 'PENDING', amount, 'UPI', email, phone]
    );

    res.json({ success: true, paymentUrl: redirectUrl });
  } catch (err) {
    console.error('Payment Error:', err?.response?.data || err.message);
    res.status(500).json({ success: false, message: 'Failed to initiate payment' });
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


 app.listen(5000, '0.0.0.0', () => {
    console.log('✅ Server running on port 5000');
  });
