const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('./db');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');

const app = express();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // 환경변수 권장

// --- CORS 설정 ---
const whitelist = [
    'http://localhost:3000',
    'https://canvasx.netlify.app'
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || whitelist.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

// --- 파일 업로드 설정 ---
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir + '/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// --- JWT 인증 미들웨어 ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: '인증 토큰이 없습니다.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: '토큰이 유효하지 않습니다.' });
        req.user = user;
        next();
    });
}

// =============================================
// API Endpoints
// =============================================

// 회원가입
app.post('/api/users/signup', async (req, res) => {
    const { email, password, nickname } = req.body;
    if (!email || !password || !nickname) 
        return res.status(400).json({ message: '모든 필드를 입력해주세요.' });

    try {
        // 이메일 중복 체크
        const emailCheck = await db.query('SELECT id FROM users WHERE email = $1', [email]);
        if (emailCheck.rows.length > 0) {
            return res.status(409).json({ message: '이미 등록된 이메일입니다.' });
        }

        // 닉네임 중복 체크
        const nickCheck = await db.query('SELECT id FROM users WHERE nickname = $1', [nickname]);
        if (nickCheck.rows.length > 0) {
            return res.status(409).json({ message: '이미 사용 중인 닉네임입니다.' });
        }

        // 비밀번호 해싱
        const password_hash = await bcrypt.hash(password, 10);

        // UUID 생성
        const newUserId = uuidv4();

        // 사용자 등록 (id 포함)
        const newUser = await db.query(
            'INSERT INTO users (id, email, password_hash, nickname) VALUES ($1, $2, $3, $4) RETURNING id, email, nickname',
            [newUserId, email, password_hash, nickname]
        );

        res.status(201).json(newUser.rows[0]);
    } catch (error) {
        console.error('회원가입 오류:', error);
        res.status(500).json({ message: '회원가입 중 오류가 발생했습니다.' });
    }
});

// 로그인 (JWT 토큰 발급)
app.post('/api/users/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ message: '이메일과 비밀번호를 모두 입력해주세요.' });

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0)
            return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });

        const user = result.rows[0];
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid)
            return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });

        // JWT 생성
        const payload = { id: user.id, email: user.email, nickname: user.nickname };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: '로그인 성공!', token, user: payload });
    } catch (error) {
        console.error('로그인 오류:', error);
        res.status(500).json({ message: '로그인 중 오류가 발생했습니다.' });
    }
});

// 경매 목록 조회 (공개)
app.get('/api/auctions', async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM auctions WHERE status = 'active' ORDER BY id ASC");
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: '경매 목록 조회 실패' });
    }
});

// 경매 상세 조회 (공개)
app.get('/api/auctions/:id', async (req, res) => {
    try {
        const auctionResult = await db.query('SELECT * FROM auctions WHERE id = $1', [req.params.id]);
        if (auctionResult.rows.length === 0) return res.status(404).json({ message: '경매를 찾을 수 없습니다.' });
        const bidsResult = await db.query("SELECT b.amount, u.nickname FROM bids b JOIN users u ON b.user_id = u.id WHERE b.auction_id = $1 ORDER BY b.created_at DESC", [req.params.id]);
        res.json({ auction: auctionResult.rows[0], bids: bidsResult.rows });
    } catch (error) {
        res.status(500).json({ message: '경매 상세 정보 조회 실패' });
    }
});

// 입찰 (로그인 필요 -> 인증 미들웨어 적용)
app.post('/api/auctions/:id/bid', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { amount } = req.body;
    const { id } = req.params;

    if (!amount)
        return res.status(400).json({ message: '입찰 금액을 입력해주세요.' });

    try {
        await db.query('BEGIN');

        // 경매 잠금 (FOR UPDATE)
        const auctionResult = await db.query("SELECT * FROM auctions WHERE id = $1 FOR UPDATE", [id]);
        if (auctionResult.rows.length === 0) throw new Error('존재하지 않는 경매입니다.');

        const auction = auctionResult.rows[0];
        if (new Date() > new Date(auction.end_time)) throw new Error('종료된 경매입니다.');
        const minBid = auction.current_highest_bid || auction.starting_bid;
        if (amount <= minBid) throw new Error(`입찰 금액은 현재 최고가(${minBid}원)보다 커야 합니다.`);

        // 사용자 존재 확인 (이미 토큰 검증했지만 한번 더 체크 가능)
        const userCheck = await db.query('SELECT id FROM users WHERE id = $1', [userId]);
        if (userCheck.rows.length === 0) throw new Error('유효하지 않은 사용자입니다.');

        // 경매 정보 업데이트
        await db.query(
            'UPDATE auctions SET current_highest_bid = $1, current_winner_id = $2 WHERE id = $3',
            [amount, userId, id]
        );

        // 입찰 내역 기록
        await db.query(
            'INSERT INTO bids (auction_id, user_id, amount) VALUES ($1, $2, $3)',
            [id, userId, amount]
        );

        await db.query('COMMIT');
        res.status(201).json({ message: '입찰 성공!' });
    } catch (error) {
        await db.query('ROLLBACK');
        console.error('입찰 오류:', error);
        res.status(400).json({ message: error.message });
    }
});

// 그 외 API도 필요 시 authenticateToken 미들웨어 추가 가능

// 서버 시작
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`✅ Canvas X server is running on port ${PORT}`);
});
