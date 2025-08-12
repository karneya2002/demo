const express = require('express');
const router = express.Router();
const db = require('../index');

router.get('/muhurtham-2025/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [rows] = await db.promise().query(
      'SELECT valarpirai_dates, theipirai_dates FROM muhurtham_dates_2025 WHERE mahal_id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'No muhurtham dates found' });
    }

    const valarpirai = JSON.parse(rows[0].valarpirai_dates || '[]');
    const theipirai = JSON.parse(rows[0].theipirai_dates || '[]');

    res.json({ valarpirai, theipirai });
  } catch (err) {
    console.error('❌ Error fetching muhurtham dates:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
