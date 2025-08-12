// routes/paymentStatus.js or inside your payment route file
const express = require('express');
const router = express.Router();
const axios = require('axios');
const crypto = require('crypto');
const db = require('../index');


router.get('/payment-status/:transactionId', async (req, res) => {
  try {
    const { transactionId } = req.params;
    const merchantId = process.env.PHONEPE_MERCHANT_ID;
    const saltKey = process.env.PHONEPE_SALT_KEY;
    const saltIndex = process.env.PHONEPE_SALT_INDEX;

    const statusUrl = `/pg/v1/status/${merchantId}/${transactionId}`;
    const baseUrl = 'https://api-preprod.phonepe.com';

    // Create hash
    const stringToHash = statusUrl + saltKey;
    const hash = crypto.createHash('sha256').update(stringToHash).digest('hex');
    const xVerify = `${hash}###${saltIndex}`;

    const response = await axios.get(`${baseUrl}${statusUrl}`, {
      headers: {
        'Content-Type': 'application/json',
        'X-VERIFY': xVerify,
        'X-MERCHANT-ID': merchantId,
      }
    });

    res.json({
      success: true,
      message: 'Payment status fetched',
      data: response.data,
    });
  } catch (error) {
    console.error('Error getting payment status:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch payment status',
      error: error.message,
    });
  }
});

module.exports = router;
