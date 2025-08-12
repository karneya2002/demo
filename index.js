  // 📁 server.js
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
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET,
});

  // ✅ Nodemailer Setup
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  // ✅ Routes
  // const paymentRoute = require('./routes/Payment');
  // app.use('/api', paymentRoute);

  // ✅ User Signup
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

  // ✅ User Login & OTP
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
            text: `Your OTP is ${otp}`,
          }, (err) => {
            if (err) return res.json({ success: false });
            res.json({ success: true, token: otp, phone: user.phone, username: user.full_name });
          });
        }
      );
    });
  });

  // ✅ OTP Verification
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

  // ✅ Forgot & Reset Password
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
        text: `Your OTP is ${otp}`,
      }, (err) => {
        if (err) return res.json({ success: false });
        res.json({ success: true });
      });
    });
  });

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
  // Resend-otp:
  app.post('/api/resend-email-otp', (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ success: false, message: 'Email required' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 5 * 60000); // 5 minutes

  db.query(
    'INSERT INTO otp_verification (email, otp, expires_at) VALUES (?, ?, ?)',
    [email, otp, expiresAt],
    (err) => {
      if (err) return res.status(500).json({ success: false, message: 'DB Error' });

      transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Resend OTP - KUMBAM',
        text: `Your OTP is ${otp}`,
      }, (err) => {
        if (err) return res.status(500).json({ success: false, message: 'Failed to send OTP' });
        res.json({ success: true, message: 'OTP sent successfully' });
      });
    }
  );
});


  // ✅ Banquet Endpoints
  app.get('/api/banquets', (req, res) => {
    db.query('SELECT * FROM banquet_halls', (err, results) => {
      if (err) return res.status(500).send(err);
      res.json(results);
    });
  });

  // Categories
  app.get('/api/categories', (req, res) => {
    db.query('SELECT DISTINCT category FROM banquet_halls', (err, results) => {
      if (err) return res.status(500).send(err);
      res.json(results.map(r => r.category));
    });
  });

  // ✅ Booking Insert
  app.get('/banquets/:id', (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM banquet_halls WHERE id = ?', [id], (err, result) => {
      if (err) return res.status(500).json({ error: err });
      res.json(result[0]);
    });
  });

  

  // Get Booked Dates
  // app.get('/api/bookings', (req, res) => {
  //   const { mahalId, month, year } = req.query;
  //   const start = `${year}-${month.padStart(2, '0')}-01`;
  //   const end = `${year}-${month.padStart(2, '0')}-31`;

  //   db.query(
  //     `SELECT booked_date FROM bookings WHERE mahal_id = ? AND booked_date BETWEEN ? AND ?`,
  //     [mahalId, start, end],
  //     (err, result) => {
  //       if (err) return res.status(500).json({ error: err });
  //       res.json(result.map(r => r.booked_date));
  //     }
  //   );
  // });

  // // Post Booking
  // app.post('/api/bookings', (req, res) => {
  //   const { mahalId, userId, dates } = req.body;
  //   const insertValues = dates.map(date => [userId, mahalId, date]);

  //   db.query(
  //     'INSERT INTO bookings (user_id, mahal_id, booked_date) VALUES ?',
  //     [insertValues],
  //     (err, result) => {
  //       if (err) return res.status(500).json({ error: err });
  //       res.json({ success: true, message: 'Booking confirmed' });
  //     }
  //   );
  // });

//   app.post('/api/initiate-payment', (req, res) => {
//   const { hallId, hallName, amount, selectedDates } = req.body;

//   if (!hallId || !amount || !hallName || !selectedDates) {
//     return res.status(400).json({ success: false, message: 'Missing required fields.' });
//   }

//   const transactionId = `TXN_${Date.now()}`;
//   const merchantId = process.env.PHONEPE_CLIENT_ID;
//   const saltKey = process.env.PHONEPE_CLIENT_SECRET;
//   const callbackUrl = process.env.CALLBACK_URL;

//   const payload = {
//     merchantId,
//     merchantTransactionId: transactionId,
//     merchantUserId: `USER_${hallId}`,
//     amount: parseInt(amount * 100),
//     redirectUrl: callbackUrl,
//     redirectMode: 'POST',
//     callbackUrl,
//     paymentInstrument: {
//       type: 'UPI_INTENT',
//     },
//   };

//   const base64Payload = Buffer.from(JSON.stringify(payload)).toString('base64');
//   const xVerify = crypto
//     .createHash('sha256')
//     .update(base64Payload + '/pg/v1/pay' + saltKey)
//     .digest('hex') + '###1';

//   const upiUrl = `upi://pay?pa=phonepe@upi&pn=${hallName}&tid=${transactionId}&tr=${transactionId}&am=${amount}&cu=INR`;

//   res.json({
//     success: true,
//     paymentUrl: upiUrl,
//     transactionId,
//   });
// });

  // ✅ Book Now Endpoint
app.post('/api/book-now', async (req, res) => {
  const { hallId, name, phone, email, eventType, address, dates, totalPrice } = req.body;

  if (!hallId || !name || !phone || !email || !eventType || !address || !dates || !totalPrice) {
    return res.status(400).json({ success: false, message: 'Please fill all fields.' });
  }

  const phoneRegex = /^[6-9]\d{9}$/;
  if (!phoneRegex.test(phone)) {
    return res.status(400).json({ success: false, message: 'Invalid phone number.' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, message: 'Invalid email format.' });
  }

  const dateList = dates.split(',').map(d => d.trim());
  const checkQuery = `
    SELECT * FROM bookings 
    WHERE hall_id = ? AND booking_dates IN (${dateList.map(() => '?').join(',')})
  `;

  db.query(checkQuery, [hallId, ...dateList], async (checkErr, existing) => {
    if (checkErr) return res.status(500).json({ success: false, message: 'Server error checking existing bookings.' });
    if (existing.length > 0) {
      return res.status(409).json({ success: false, message: 'Selected date(s) already booked.' });
    }

    const insertQuery = `
      INSERT INTO bookings (hall_id, name, phone, email, event_type, address, booking_dates, total_price)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(insertQuery, [hallId, name, phone, email, eventType, address, dates, totalPrice], async (insertErr, result) => {
      if (insertErr) return res.status(500).json({ success: false, message: 'Failed to save booking.' });

      // ✅ Send confirmation email to user
      transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Booking Confirmation - Kumbam',
        html: `<h2>Hi ${name},</h2><p>Your booking for ${eventType} on ${dates} has been received.</p>`
      });

      return res.status(200).json({
        success: true,
        message: 'Booking successful',
        bookingId: result.insertId,
      });
    });
  });
});

// ✅ PhonePe Payment Gateway
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
app.get('/api/booked-dates/:hallId', (req, res) => {
  const { hallId } = req.params;
  const query = 'SELECT booking_dates FROM bookings WHERE hall_id = ?';
  db.query(query, [hallId], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Failed to fetch booked dates' });

    const booked = results.flatMap(r => r.booking_dates.split(',').map(d => d.trim()));
    res.json({ success: true, bookedDates: [...new Set(booked)] });
  });
});



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
app.get('/api/booked-dates/:hallId/:month/:year', (req, res) => {
  const { hallId, month, year } = req.params;

  if (!hallId || !month || !year) {
    return res.status(400).json({ success: false, message: 'Missing hallId, month, or year' });
  }

  const startDate = `${year}-${month.padStart(2, '0')}-01`;
  const endDate = `${year}-${month.padStart(2, '0')}-31`;

  const query = `
    SELECT booking_dates FROM bookings 
    WHERE hall_id = ? AND booking_dates BETWEEN ? AND ?
  `;

  db.query(query, [hallId, startDate, endDate], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'DB error' });

    const booked = results.flatMap(row => row.booking_dates.split(',').map(d => d.trim()));
    res.json({ success: true, bookedDates: [...new Set(booked)] });
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





  // ✅ Start Server
  app.listen(5000, '0.0.0.0', () => {
    console.log('✅ Server running on port 5000');
  });
