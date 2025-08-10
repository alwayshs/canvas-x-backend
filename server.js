// ===================================================================
// server.js (메인 서버 프로그램) - 최종 클린 버전
// ===================================================================
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('./db');

const app = express();

// --- CORS 설정 ---
const whitelist = [
    'http://localhost:3000',
    'https://cool-semifreddo-6004a7.netlify.app'
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

// =============================================
// API Endpoints
// =============================================

// --- 1. 사용자 인증 API ---
app.post('/api/users/signup', async (req, res) => {
    const { email, password, nickname } = req.body;
    if (!email || !password || !nickname) return res.status(400).json({ message: '모든 필드를 입력해주세요.' });
    try {
        const password_hash = await bcrypt.hash(password, 10);
        const newUser = await db.query(
            'INSERT INTO users (id, email, password_hash, nickname) VALUES ($1, $2, $3, $4) RETURNING id, email, nickname',
            [nickname, email, password_hash, nickname]
        );
        res.status(201).json(newUser.rows[0]);
    } catch (error) {
        res.status(500).json({ message: '회원가입 중 오류 발생 (이메일/닉네임 중복 가능성)' });
    }
});

app.post('/api/users/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
        const user = result.rows[0];
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });
        res.json({ message: '로그인 성공!', user: { id: user.id, email: user.email, nickname: user.nickname } });
    } catch (error) {
        res.status(500).json({ message: '로그인 중 오류 발생' });
    }
});

// --- 2. 경매 API ---
app.get('/api/auctions', async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM auctions WHERE status = 'active' ORDER BY id ASC");
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: '경매 목록 조회 실패' });
    }
});

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

app.post('/api/auctions/:id/bid', async (req, res) => {
    const { userId, amount } = req.body;
    const { id } = req.params;
    try {
        await db.query('BEGIN');
        const auctionResult = await db.query("SELECT * FROM auctions WHERE id = $1 FOR UPDATE", [id]);
        const auction = auctionResult.rows[0];
        if (!auction || new Date() > new Date(auction.end_time)) throw new Error('종료된 경매입니다.');
        if (amount <= (auction.current_highest_bid || auction.starting_bid)) throw new Error('입찰 금액이 현재 최고가보다 낮습니다.');
        
        await db.query('UPDATE auctions SET current_highest_bid = $1, current_winner_id = $2 WHERE id = $3', [amount, userId, id]);
        await db.query('INSERT INTO bids (auction_id, user_id, amount) VALUES ($1, $2, $3)', [id, userId, amount]);
        await db.query('COMMIT');
        res.status(201).json({ message: '입찰 성공!' });
    } catch (error) {
        await db.query('ROLLBACK');
        res.status(400).json({ message: error.message });
    }
});

// --- 3. 대시보드 API ---
app.get('/api/users/:userId/won-auctions', async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM auctions WHERE final_winner_id = $1 ORDER BY id DESC", [req.params.userId]);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: '낙찰 내역 조회 실패' });
    }
});

// --- 4. 결제 API (시뮬레이션) ---
app.post('/api/payments/confirm', async (req, res) => {
    const { auctionId, userId } = req.body;
    try {
        const result = await db.query(
            "UPDATE auctions SET status = 'paid' WHERE id = $1 AND final_winner_id = $2 AND status = 'ended' RETURNING *",
            [auctionId, userId]
        );
        if (result.rows.length === 0) throw new Error('결제할 수 없는 경매입니다.');
        res.status(200).json({ message: '결제가 성공적으로 완료되었습니다.' });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// --- 5. 광고 업로드 API ---
app.post('/api/ad-content/upload', upload.single('adFile'), async (req, res) => {
    const { auctionId, userId } = req.body;
    const file = req.file;
    if (!file) return res.status(400).json({ message: '파일이 없습니다.' });
    try {
        const contentUrl = `/uploads/${file.filename}`;
        await db.query('BEGIN');
        const auctionResult = await db.query(
            "SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND status = 'paid' FOR UPDATE",
            [auctionId, userId]
        );
        if (auctionResult.rows.length === 0) throw new Error('업로드 권한이 없습니다.');

        await db.query(
            'INSERT INTO ad_content (auction_id, owner_id, content_type, content_url, approval_status) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (auction_id) DO UPDATE SET content_url = $4, approval_status = $5',
            [auctionId, userId, file.mimetype, contentUrl, 'pending_approval']
        );
        await db.query("UPDATE auctions SET status = 'pending_approval' WHERE id = $1", [auctionId]);
        await db.query('COMMIT');
        res.status(201).json({ message: '광고가 성공적으로 업로드되었으며, 관리자 승인을 기다리고 있습니다.' });
    } catch (error) {
        await db.query('ROLLBACK');
        res.status(400).json({ message: error.message });
    }
});

// --- 6. 관리자 API ---
app.get('/api/admin/pending-ads', async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM ad_content WHERE approval_status = 'pending_approval' ORDER BY upload_time ASC");
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: '승인 대기 광고 목록 조회 실패' });
    }
});

app.patch('/api/admin/ad-content/:id/status', async (req, res) => {
    const { id } = req.params;
    const { newStatus } = req.body;
    if (!['approved', 'rejected'].includes(newStatus)) {
        return res.status(400).json({ message: '유효하지 않은 상태 값입니다.' });
    }
    try {
        await db.query('BEGIN');
        const adResult = await db.query("UPDATE ad_content SET approval_status = $1 WHERE id = $2 RETURNING auction_id", [newStatus, id]);
        if (adResult.rows.length === 0) throw new Error('해당 콘텐츠를 찾을 수 없습니다.');
        if (newStatus === 'approved') {
            const { auction_id } = adResult.rows[0];
            await db.query("UPDATE auctions SET status = 'completed' WHERE id = $1", [auction_id]);
        }
        await db.query('COMMIT');
        res.status(200).json({ message: `콘텐츠 상태가 '${newStatus}'(으)로 성공적으로 변경되었습니다.` });
    } catch (error) {
        await db.query('ROLLBACK');
        res.status(500).json({ message: error.message || '상태 변경 중 오류 발생' });
    }
});

// 서버 시작
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`✅ Canvas X server is running at http://localhost:${PORT}`);
});
