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
      banquetId,
      name,
      phone,
      email,
      eventType,
      address,
      price,
      dates,
      bookingDate
    } = req.body;

    // 1️⃣ Check required fields & tell which is missing
    const requiredFields = {
      banquetId,
      name,
      phone,
      email,
      eventType,
      address,
      price,
      dates
    };

    for (const [key, value] of Object.entries(requiredFields)) {
      if (
        value === undefined ||
        value === null ||
        (typeof value === 'string' && !value.trim()) ||
        (Array.isArray(value) && value.length === 0)
      ) {
        return res.status(400).json({
          success: false,
          message: `Missing required field: ${key}`
        });
      }
    }

    // 2️⃣ Fetch mahalName & location from DB
    const [hall] = await new Promise((resolve, reject) => {
     db.query('SELECT name AS mahalName, address AS location FROM banquet_halls WHERE id = ?', [banquetId],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });

    if (!hall) {
      return res.status(404).json({
        success: false,
        message: 'Banquet hall not found.'
      });
    }

    const mahalName = hall.mahalName;
    const location = hall.location;

    // 3️⃣ Phone validation
    const phoneRegex = /^[6-9]\d{9}$/;
    if (!phoneRegex.test(String(phone))) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number. Must be 10 digits starting with 6-9.'
      });
    }

    // 4️⃣ Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(String(email))) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format.'
      });
    }

    // 5️⃣ Normalize dates
    const dateList = Array.isArray(dates)
      ? dates.map(d => String(d).trim()).filter(Boolean)
      : String(dates).split(',').map(d => d.trim()).filter(Boolean);

    if (dateList.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'At least one booking date is required.'
      });
    }

    // 6️⃣ Check if dates are already booked
    const existingDates = await new Promise((resolve, reject) => {
      db.query(
        'SELECT booking_dates FROM bookings WHERE banquet_id = ?',
        [banquetId],
        (err, rows) => {
          if (err) reject(err);
          else {
            resolve(
              rows.flatMap(r => {
                try {
                  return JSON.parse(r.dates);
                } catch {
                  return String(r.dates || '')
                    .split(',')
                    .map(s => s.trim())
                    .filter(Boolean);
                }
              })
            );
          }
        }
      );
    });

    const alreadyBooked = dateList.filter(d => existingDates.includes(d));
    if (alreadyBooked.length > 0) {
      return res.status(409).json({
        success: false,
        message: `These dates are already booked: ${alreadyBooked.join(', ')}`
      });
    }

    // 7️⃣ Insert booking
    await new Promise((resolve, reject) => {
      db.query(
        `
        INSERT INTO bookings 
        (name, phone, event_type, address, mahal_name, location, price, dates, booking_date, status, banquet_id, email)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        `,
        [
          name.trim(),
          phone.trim(),
          eventType.trim(),
          address.trim(),
          mahalName,
          location,
          Number(price),
          JSON.stringify(dateList),
          bookingDate || null,
          banquetId,
          email.trim()
        ],
        (err, result) => {
          if (err) reject(err);
          else resolve(result);
        }
      );
    });

    // 8️⃣ Success response
    return res.status(200).json({
      success: true,
      message: 'Booking successful'
    });

  } catch (e) {
    console.error('book-now error:', e);
    return res.status(500).json({
      success: false,
      message: 'Server error.'
    });
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


app.post('/initiate-payment', async (req, res) => {
  try {
    const { amount, email, phone, bookingId, hallId } = req.body;

    if (!amount || !email || !phone || !bookingId || !hallId) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    // 💰 Create Razorpay Order
    const order = await razorpay.orders.create({
      amount: amount * 100, // in paisa
      currency: 'INR',
      receipt: `receipt_${bookingId}`,
    });

    // 💾 Save payment initiation in DB
    db.query(
      `INSERT INTO payments (booking_id, hall_id, amount, email, phone, razorpay_order_id, status)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [bookingId, hallId, amount, email, phone, order.id, 'created'],
      (err, result) => {
        if (err) {
          console.error('❌ MySQL INSERT Error:', err);
          return res.status(500).json({ success: false, message: 'Database error' });
        }

        // ✅ Respond to frontend
        res.status(200).json({
          success: true,
          orderId: order.id,
          amount: order.amount,
          key: process.env.RAZORPAY_KEY_ID,
        });
      }
    );
  } catch (err) {
    console.error('❌ Razorpay Error:', err);
    res.status(500).json({
      success: false,
      message: 'Payment initiation failed',
      error: err?.message || 'Unknown error',
    });
  }
});


app.post('/verify-payment', async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, bookingId } = req.body;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature || !bookingId) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  const key_secret = process.env.RAZORPAY_KEY_SECRET;
  const generated_signature = crypto
    .createHmac('sha256', key_secret)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');

  if (generated_signature === razorpay_signature) {
    // ✅ Signature matched - mark as paid
    db.query(
      `UPDATE payments SET status = ? WHERE razorpay_order_id = ?`,
      ['paid', razorpay_order_id],
      (err, result) => {
        if (err) {
          console.error('MySQL Error:', err);
          return res.status(500).json({ success: false, message: 'Database update failed' });
        }

        return res.status(200).json({ success: true, message: 'Payment verified successfully' });
      }
    );
  } else {
    return res.status(400).json({ success: false, message: 'Invalid signature' });
  }
})


// ✅ Filter available halls for a given date
app.get('/api/available-halls', (req, res) => {
  const { date } = req.query;
  const query = `
    SELECT * FROM halls WHERE id NOT IN (
      SELECT hall_id FROM bookings WHERE FIND_IN_SET(?, booking_dates)
    )
  `;

  db.query(query, [date], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: 'Error fetching halls' });
    res.json({ success: true, availableHalls: result });
  });
});

// GET all booked dates for a hall
// app.get('/api/booked-dates/:hallId', (req, res) => {
//   const { hallId } = req.params;
//   const query = 'SELECT booking_dates FROM bookings WHERE hall_id = ?';
//   db.query(query, [hallId], (err, results) => {
//     if (err) return res.status(500).json({ success: false, message: 'Failed to fetch booked dates' });

//     const booked = results.flatMap(r => r.booking_dates.split(',').map(d => d.trim()));
//     res.json({ success: true, bookedDates: [...new Set(booked)] });
//   });
// });



app.get('/api/muhurtham-2025/:id', (req, res) => {
  const { id } = req.params;

  db.query(
    'SELECT * FROM muhurtham_dates_2025 WHERE mahal_id = ?',
    [id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err });

      if (result.length === 0) {
        return res.status(404).json({ message: 'No muhurtham dates found' });
      }

      const rawValarpirai = JSON.parse(result[0].valarpirai_dates);
      const rawTheipirai = JSON.parse(result[0].theipirai_dates);

      // Construct YYYY-MM-DD dates for each day across all 12 months of 2025
      const generateFullDates = (daysArray) => {
        const fullDates = [];

        for (let month = 1; month <= 12; month++) {
          daysArray.forEach(day => {
            const dayStr = String(day).padStart(2, '0');
            const monthStr = String(month).padStart(2, '0');
            fullDates.push(`2025-${monthStr}-${dayStr}`);
          });
        }

        return fullDates;
      };

      const valarpirai = generateFullDates(rawValarpirai);
      const theipirai = generateFullDates(rawTheipirai);

      res.json({ valarpirai, theipirai });
    }
  );
});


// 📆 Get Booked Dates by Hall, Month & Year
// app.get('/api/booked-dates/:hallId/:month/:year', (req, res) => {
//   const { hallId, month, year } = req.params;

//   if (!hallId || !month || !year) {
//     return res.status(400).json({ success: false, message: 'Missing hallId, month, or year' });
//   }

//   const startDate = `${year}-${month.padStart(2, '0')}-01`;
//   const endDate = `${year}-${month.padStart(2, '0')}-31`;

//   const query = `
//     SELECT booking_dates FROM bookings 
//     WHERE hall_id = ? AND booking_dates BETWEEN ? AND ?
//   `;

//   db.query(query, [hallId, startDate, endDate], (err, results) => {
//     if (err) return res.status(500).json({ success: false, message: 'DB error' });

//     const booked = results.flatMap(row => row.booking_dates.split(',').map(d => d.trim()));
//     res.json({ success: true, bookedDates: [...new Set(booked)] });
//   });
// });


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


// Admin Login:


app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await db.promise().query(
    'SELECT * FROM users WHERE email = ? AND role = "admin"',
    [email]
  );

  if (rows.length === 0) {
    return res.json({ success: false, message: 'Admin user not found' });
  }

  const user = rows[0];

  // If you're using bcrypt (recommended):
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.json({ success: false, message: 'Incorrect password' });

  res.json({
    success: true,
    token: 'mocked-token',
    role: user.role
  });
});

// ✅ Inside index.js or server.js
// Get all users
app.get('/api/admin/users', (req, res) => {
  db.query('SELECT * FROM users', (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'DB error' });
    res.json({ success: true, users: results });
  });
});



// Add user
app.post('/api/admin/users', (req, res) => {
  console.log("BODY RECEIVED:", req.body); // ✅ Debug
  const { name, email, phone } = req.body;

  if (!name || !email || !phone) {
    return res.status(400).json({ success: false, message: 'Missing fields' });
  }

  db.query(
    'INSERT INTO users (full_name, phone, email) VALUES (?, ?, ?)',
    [name, email, phone],
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: 'Insert failed', error: err });
      res.json({ success: true, id: result.insertId });
    }
  );
});


// Add user
app.put('/api/admin/users/:id', (req, res) => {
  const { id } = req.params;
  const { full_name, email, phone } = req.body;

  if (!full_name || !email || !phone) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  db.query(
    'UPDATE users SET full_name=?, email=?, phone=? WHERE id=?',
    [full_name, email, phone, id],
    (err) => {
      if (err) {
        console.error('Update error:', err);
        return res.status(500).json({ success: false, message: 'Update failed' });
      }
      res.json({ success: true });
    }
  );
});

// Delete user
app.delete('/api/admin/users/:id', (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM users WHERE id=?', [id], (err) => {
    if (err) return res.status(500).json({ success: false, message: 'Delete failed' });
    res.json({ success: true });
  });
});


app.post('/api/verify-email-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'Email and OTP are required' });
  }

  try {
    // 1️⃣ Find the user
    const [userRows] = await db.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    if (userRows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const userId = userRows[0].id;

    // 2️⃣ Get latest OTP record
    const [otpRows] = await db.execute(
      'SELECT otp, otp_expiry, verified FROM otp_verification WHERE user_id = ? ORDER BY id DESC LIMIT 1',
      [userId]
    );
    if (otpRows.length === 0) {
      return res.status(404).json({ success: false, message: 'No OTP found for this user' });
    }
    const otpData = otpRows[0];

    // 3️⃣ Already verified?
    if (otpData.verified) {
      return res.json({ success: true, message: 'OTP already verified' });
    }

    // 4️⃣ OTP match check
    if (String(otpData.otp) !== String(otp)) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    // 5️⃣ Expiry check
    if (otpData.otp_expiry && new Date(otpData.otp_expiry) < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP expired' });
    }

    // 6️⃣ Mark as verified
    await db.execute(
      'UPDATE otp_verification SET verified = 1 WHERE user_id = ?',
      [userId]
    );

    return res.json({ success: true, message: 'OTP verified successfully' });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET booked dates by mahal_name
app.get('/api/booked-dates/:hallId', (req, res) => {
  const { hallId } = req.params;

  const query = 'SELECT dates FROM bookings WHERE hall_id = ?';

  db.query(query, [hallId], (err, results) => {
    if (err) {
      console.error('Error fetching booked dates:', err);
      return res.status(500).json({
        success: false,
        message: 'Database error while fetching booked dates',
      });
    }

    if (!results || results.length === 0) {
      return res.status(200).json({
        success: true,
        bookedDates: [],
      });
    }

    // If dates are stored as JSON strings or comma-separated values, parse them
    const bookedDates = results
      .map(row => {
        if (typeof row.dates === 'string') {
          try {
            return JSON.parse(row.dates);
          } catch {
            return row.dates.split(',').map(date => date.trim());
          }
        }
        return row.dates;
      })
      .flat();

    res.status(200).json({
      success: true,
      bookedDates,
    });
  });
});


    // Flatten and clean up dates
    const bookedDates = results
      .flatMap(row => row.dates.split(',').map(date => date.trim()))
      .filter(date => date); // remove empty strings

    const uniqueDates = [...new Set(bookedDates)];

    res.json({
      success: true,
      bookedDates: uniqueDates,
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
