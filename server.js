// server.js (진단용 코드)
const express = require('express');
const cors = require('cors');
const db = require('./db'); // 실제 데이터베이스 연결 모듈

const app = express();
app.use(cors());
app.use(express.json());

// 서버가 켜졌는지 확인하는 기본 주소
app.get('/', (req, res) => {
    res.send('✅ Canvas X server is running!');
});

// 데이터베이스 연결만 테스트하는 주소
app.get('/api/db-test', async (req, res) => {
    try {
        // 현재 시간을 조회하는 간단한 쿼리를 실행합니다.
        const timeResult = await db.query('SELECT NOW()');
        res.json({ 
            message: '✅ Database connection successful!',
            time: timeResult.rows[0].now 
        });
    } catch (error) {
        console.error('🔴 Database Connection Error:', error);
        res.status(500).json({ 
            message: '🔴 Database connection failed.',
            error: error.message 
        });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`✅ Canvas X Diagnostic Server is running on port ${PORT}`);
});
