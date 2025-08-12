// ===================================================================
// server.refactor.js - 리팩터링된 Canvas X 메인 서버 (관리자 인증 강화, 트랜잭션/동기화 개선)
// 주요 변경점 요약:
//  - uuid import 추가
//  - fetch가 없을 경우 node-fetch 폴백
//  - 트랜잭션을 안정적으로 처리하기 위해 DB 클라이언트(연결)를 명시적으로 사용
//  - offerToSecondBidder 등 중요한 DB 변경 로직은 같은 트랜잭션(client)에서 실행
//  - 파일 경로 안전 처리
//  - manageAuctions 날짜/ID 생성 로직 개선
//  - 에러 로그 및 관리자 액션 로깅 추가 (간단한 예)
// ===================================================================

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// db 모듈은 기존대로 ./db 에서 query랑 connect/pool을 제공한다고 가정합니다.
// 예) module.exports = { query: (text, params) => pool.query(text, params), connect: () => pool.connect(), pool }
const db = require('./db');

// node 버전에서 global fetch가 없을 경우를 대비
let fetchFn = global.fetch;
if (!fetchFn) {
    try {
        fetchFn = require('node-fetch');
    } catch (e) {
        console.warn('fetch is not available and node-fetch is not installed. 결제/환불 외부 호출이 실패할 수 있습니다.');
    }
}

const app = express();

// --- CORS 설정 ---
const whitelist = [
    'http://localhost:3000',
    'https://cool-semifreddo-6004a7.netlify.app',
    'https://canvasx.netlify.app'
];
const corsOptions = {
    origin: function (origin, callback) {
        // production에서는 origin이 반드시 존재하도록 정책 변경 권장
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
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir + '/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// JWT 시크릿 키
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-secret-key-for-canvas-x';
const TOSS_SECRET_KEY = process.env.TOSS_SECRET_KEY || 'test_sk_ma60RZblrqRmG7MmYpZ68wzYWBn1';

// --- JWT 인증 미들웨어 ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// --- 관리자 확인 미들웨어 ---
function isAdmin(req, res, next) {
    if (req.user && req.user.is_admin) {
        next();
    } else {
        res.status(403).json({ message: '관리자 권한이 필요합니다.' });
    }
}

// helper: DB 연결(클라이언트) 가져오기 (db.connect 또는 db.pool.connect 중 사용 가능)
async function getDbClient() {
    if (typeof db.connect === 'function') {
        return await db.connect();
    }
    if (db.pool && typeof db.pool.connect === 'function') {
        return await db.pool.connect();
    }
    throw new Error('DB client를 얻을 수 없습니다. ./db 모듈이 connect 또는 pool.connect를 제공해야 합니다.');
}

// =============================================
// 자동 경매 관리 시스템 (Scheduler)
// =============================================
const MINIMUM_ACTIVE_AUCTIONS = 3; // 항상 유지할 최소 활성 경매 수

function formatDateToYMD(date) {
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
}

function getAuctionEndTimeFromDate(date) {
    // 예: 주어진 날짜 기준으로 전날 09:00을 종료시간으로 설정
    const end = new Date(date);
    end.setDate(end.getDate() - 1);
    end.setHours(9, 0, 0, 0);
    return end;
}

async function manageAuctions() {
    console.log('[Scheduler] Running auction management task...');
    const client = await getDbClient();
    try {
        await client.query('BEGIN');

        // 1) 종료 시간이 지난 경매들을 'ended' 상태로 변경
        const endedResult = await client.query(
            "UPDATE auctions SET status = 'ended', final_bid = current_highest_bid, final_winner_id = current_winner_id WHERE end_time < NOW() AND status = 'active' RETURNING id"
        );
        if (endedResult.rows.length > 0) {
            console.log(`[Scheduler] ${endedResult.rows.length} auctions have ended.`);
        }

        // 2) 현재 활성 상태인 경매 수 확인
        const activeResult = await client.query("SELECT COUNT(*) FROM auctions WHERE status = 'active'");
        const activeCount = parseInt(activeResult.rows[0].count, 10);
        console.log(`[Scheduler] Found ${activeCount} active auctions.`);

        // 3) 부족한 만큼 새로운 경매 생성
        let newAuctionsNeeded = MINIMUM_ACTIVE_AUCTIONS - activeCount;
        if (newAuctionsNeeded > 0) {
            console.log(`[Scheduler] Creating ${newAuctionsNeeded} new auctions...`);
            const lastAuctionRes = await client.query("SELECT MAX(id) as last_id FROM auctions");
            let lastId = lastAuctionRes.rows[0].last_id;

            // lastId가 YYYY-MM-DD 또는 숫자일 수 있음
            let lastDate = new Date();
            if (lastId) {
                const parsed = new Date(String(lastId));
                if (!isNaN(parsed.getTime())) lastDate = parsed;
            }

            for (let i = 0; i < newAuctionsNeeded; i++) {
                lastDate.setDate(lastDate.getDate() + 1);
                const newAuctionId = formatDateToYMD(lastDate); // 'YYYY-MM-DD'
                const newEndTime = getAuctionEndTimeFromDate(lastDate);

                await client.query(
                    "INSERT INTO auctions (id, start_time, end_time, status, starting_bid) VALUES ($1, NOW(), $2, 'active', 10000) ON CONFLICT (id) DO NOTHING",
                    [newAuctionId, newEndTime]
                );
                console.log(`[Scheduler] Created new auction for ${newAuctionId}`);
            }
        }

        await client.query('COMMIT');
        console.log('[Scheduler] Auction management finished.');
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('[Scheduler] Error during auction management:', error);
    } finally {
        try { client.release(); } catch (e) { /* ignore */ }
    }
}

// =============================================
// 공통 로직: 차순위 입찰자에게 낙찰 기회를 넘기는 함수
// - 중요한 점: 이 함수는 반드시 같은 DB client(트랜잭션 내)에서 호출되어야 함
// =============================================
async function offerToSecondBidder(client, auctionId) {
    // 1. 해당 경매의 2번째로 높은 입찰 기록을 찾음
    const secondBidderResult = await client.query(
        "SELECT user_id, amount FROM bids WHERE auction_id = $1 ORDER BY amount DESC, created_at ASC LIMIT 1 OFFSET 1",
        [auctionId]
    );

    if (secondBidderResult.rows.length > 0) {
        const secondBidder = secondBidderResult.rows[0];
        // 차순위 입찰자에게 낙찰 권한을 이전
        await client.query(
            "UPDATE auctions SET status = 'ended', final_winner_id = $1, final_bid = $2 WHERE id = $3",
            [secondBidder.user_id, secondBidder.amount, auctionId]
        );
        console.log(`[Second Chance] Offered auction ${auctionId} to ${secondBidder.user_id} for ${secondBidder.amount}`);
        return { status: 'offered', to: secondBidder.user_id };
    } else {
        // 차순위가 없으면 유찰 처리
        await client.query(
            "UPDATE auctions SET status = 'failed', final_winner_id = NULL, final_bid = NULL WHERE id = $1",
            [auctionId]
        );
        console.log(`[Second Chance] No second bidder for auction ${auctionId}. Marked as failed.`);
        return { status: 'failed' };
    }
}

// =============================================
// API Endpoints
// =============================================

// --- 1. 사용자 인증 API ---
app.post('/api/users/signup', async (req, res) => {
    const { email, password, nickname } = req.body;
    if (!email || !password || !nickname)
        return res.status(400).json({ message: '모든 필드를 입력해주세요.' });

    try {
        const emailCheck = await db.query('SELECT id FROM users WHERE email = $1', [email]);
        if (emailCheck.rows.length > 0) return res.status(409).json({ message: '이미 등록된 이메일입니다.' });

        const nickCheck = await db.query('SELECT id FROM users WHERE nickname = $1', [nickname]);
        if (nickCheck.rows.length > 0) return res.status(409).json({ message: '이미 사용 중인 닉네임입니다.' });

        const password_hash = await bcrypt.hash(password, 10);
        const newUserId = uuidv4();

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

app.post('/api/users/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });

        const user = result.rows[0];
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다.' });

        const userPayload = { id: user.id, nickname: user.nickname, is_admin: user.is_admin };
        const accessToken = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '1d' });

        res.json({ message: '로그인 성공!', accessToken, user: userPayload });
    } catch (error) {
        console.error('로그인 오류:', error);
        res.status(500).json({ message: '로그인 중 오류 발생' });
    }
});

// --- 2. 경매 API ---
app.get('/api/auctions', async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM auctions WHERE status = 'active' ORDER BY id ASC");
        res.json(result.rows);
    } catch (error) {
        console.error('경매 목록 조회 실패:', error);
        res.status(500).json({ message: '경매 목록 조회 실패' });
    }
});

app.get('/api/auctions/:id', async (req, res) => {
    try {
        const auctionResult = await db.query('SELECT * FROM auctions WHERE id = $1', [req.params.id]);
        if (auctionResult.rows.length === 0) return res.status(404).json({ message: '경매를 찾을 수 없습니다.' });

        const bidsResult = await db.query(
            `SELECT b.amount, u.nickname FROM bids b
             JOIN users u ON b.user_id = u.id
             WHERE b.auction_id = $1
             ORDER BY b.created_at DESC`,
            [req.params.id]
        );

        res.json({ auction: auctionResult.rows[0], bids: bidsResult.rows });
    } catch (error) {
        console.error('경매 상세 조회 실패:', error);
        res.status(500).json({ message: '경매 상세 정보 조회 실패' });
    }
});

// 입찰 API: 트랜잭션 및 FOR UPDATE로 동시성 제어
app.post('/api/auctions/:id/bid', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    const { id: auctionId } = req.params;
    const { id: userId } = req.user;

    const client = await getDbClient();
    try {
        await client.query('BEGIN');

        const auctionResult = await client.query("SELECT * FROM auctions WHERE id = $1 FOR UPDATE", [auctionId]);
        const auction = auctionResult.rows[0];
        if (!auction || new Date() > new Date(auction.end_time)) throw new Error('종료된 경매입니다.');
        if (amount <= (auction.current_highest_bid || auction.starting_bid)) throw new Error('입찰 금액이 현재 최고가보다 낮습니다.');

        await client.query('UPDATE auctions SET current_highest_bid = $1, current_winner_id = $2 WHERE id = $3', [amount, userId, auctionId]);
        await client.query('INSERT INTO bids (auction_id, user_id, amount) VALUES ($1, $2, $3)', [auctionId, userId, amount]);

        await client.query('COMMIT');
        res.status(201).json({ message: '입찰 성공!' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('입찰 실패:', error);
        res.status(400).json({ message: error.message });
    } finally {
        try { client.release(); } catch (e) { /* ignore */ }
    }
});

// --- 3. 대시보드 API (수정) ---
app.get('/api/users/:userId/won-auctions', authenticateToken, async (req, res) => {
    if (req.user.id !== req.params.userId && !req.user.is_admin) return res.sendStatus(403);
    try {
        const result = await db.query(
            "SELECT * FROM auctions WHERE final_winner_id = $1 AND status != 'active' ORDER BY id DESC",
            [req.params.userId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('낙찰 내역 조회 실패:', error);
        res.status(500).json({ message: '낙찰 내역 조회 실패' });
    }
});

// --- 4. 결제 API (실제 연동은 별도 구현) ---
app.post('/api/payments/request', authenticateToken, async (req, res) => {
    const { auctionId } = req.body;
    const { id: userId } = req.user;
    try {
        const auctionResult = await db.query(
            "SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND status = 'ended'",
            [auctionId, userId]
        );
        const auction = auctionResult.rows[0];

        if (!auction) return res.status(403).json({ message: '결제 대상 경매가 아니거나 권한이 없습니다.' });

        res.json({
            amount: auction.final_bid,
            orderId: `canvasx_${auctionId}_${new Date().getTime()}`,
            orderName: `Canvas X - ${auctionId} 광고권`
        });
    } catch (error) {
        console.error('결제 요청 생성 실패:', error);
        res.status(500).json({ message: '결제 정보를 생성하는 중 오류가 발생했습니다.' });
    }
});

app.post('/api/payments/confirm', authenticateToken, async (req, res) => {
    const { paymentKey, orderId, amount } = req.body;
    try {
        if (!fetchFn) throw new Error('fetch 함수가 사용 불가합니다.');

        const response = await fetchFn('https://api.tosspayments.com/v1/payments/confirm', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${Buffer.from(TOSS_SECRET_KEY + ':').toString('base64')}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ paymentKey, orderId, amount }),
        });

        const paymentData = await response.json();
        if (!response.ok) throw new Error(paymentData.message || '결제 승인에 실패했습니다.');

        const auctionId = orderId.split('_')[1];
        await db.query("UPDATE auctions SET status = 'paid', payment_key = $1 WHERE id = $2", [paymentKey, auctionId]);

        res.status(200).json({ message: '결제가 성공적으로 완료되었습니다.', ...paymentData });
    } catch (error) {
        console.error('결제 확인 실패:', error);
        res.status(400).json({ message: error.message });
    }
});

// --- 4.5. 낙찰 포기 및 환불 API (트랜잭션 안정화) ---
app.post('/api/auctions/:auctionId/cancel', authenticateToken, async (req, res) => {
    const { auctionId } = req.params;
    const { id: userId } = req.user;

    const client = await getDbClient();
    try {
        await client.query('BEGIN');
        const auctionResult = await client.query(
            "SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND status = 'ended' FOR UPDATE",
            [auctionId, userId]
        );
        if (auctionResult.rows.length === 0) throw new Error('낙찰을 포기할 수 없는 상태입니다.');

        // 동일한 트랜잭션(client) 내에서 차순위에게 기회를 제공
        await offerToSecondBidder(client, auctionId);

        await client.query('COMMIT');
        res.status(200).json({ message: '낙찰을 포기했습니다. 차순위 입찰자에게 기회가 넘어갑니다.' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('낙찰 포기 실패:', error);
        res.status(400).json({ message: error.message });
    } finally {
        try { client.release(); } catch (e) { /* ignore */ }
    }
});

app.post('/api/auctions/:auctionId/refund', authenticateToken, async (req, res) => {
    const { auctionId } = req.params;
    const { id: userId } = req.user;

    const client = await getDbClient();
    try {
        await client.query('BEGIN');
        const auctionResult = await client.query(
            "SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 FOR UPDATE",
            [auctionId, userId]
        );
        if (auctionResult.rows.length === 0) throw new Error('환불을 요청할 수 없는 경매입니다.');

        const auction = auctionResult.rows[0];
        const auctionDate = new Date(auction.id);
        const refundDeadline = new Date(auctionDate.getFullYear(), auctionDate.getMonth(), auctionDate.getDate(), 17, 0, 0);

        if (new Date() > refundDeadline) throw new Error('환불 가능한 시간이 지났습니다 (당일 17시까지).');

        const paymentKey = auction.payment_key;
        if (!paymentKey) throw new Error('결제 정보를 찾을 수 없어 환불할 수 없습니다.');

        // 외부 환불 API 호출은 트랜잭션 안에서 오래 걸리면 안되지만,
        // 안전을 위해 우리는 여기서 호출 후 DB 변경을 진행함.
        if (!fetchFn) throw new Error('fetch 함수가 사용 불가합니다.');

        const refundResponse = await fetchFn(`https://api.tosspayments.com/v1/payments/${paymentKey}/cancel`, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${Buffer.from(TOSS_SECRET_KEY + ':').toString('base64')}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ cancelReason: '고객 변심' }),
        });

        if (!refundResponse.ok) {
            const refundError = await refundResponse.json();
            throw new Error(refundError.message || '토스페이먼츠 환불 처리 중 오류가 발생했습니다.');
        }

        console.log(`[Refund] Refund processed for auction ${auctionId}`);

        // 같은 트랜잭션(client) 내에서 차순위에게 기회를 제공 및 광고 삭제
        await offerToSecondBidder(client, auctionId);

        const adContentResult = await client.query("DELETE FROM ad_content WHERE auction_id = $1 RETURNING content_url", [auctionId]);
        if (adContentResult.rows.length > 0) {
            // 안전하게 파일 경로 처리
            const contentUrl = adContentResult.rows[0].content_url;
            const safePath = path.join(__dirname, contentUrl.replace(/^\//, ''));
            fs.unlink(safePath, (err) => { if (err) console.error("Error deleting refunded ad file:", err); });
        }

        await client.query('COMMIT');
        res.status(200).json({ message: '환불이 요청되었습니다. 차순위 입찰자에게 기회가 넘어갑니다.' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('환불 처리 실패:', error);
        res.status(400).json({ message: error.message });
    } finally {
        try { client.release(); } catch (e) { /* ignore */ }
    }
});

// --- 5. 광고 업로드 API (트랜잭션 개선) ---
app.post('/api/ad-content/upload', authenticateToken, upload.single('adFile'), async (req, res) => {
    const { auctionId } = req.body;
    const { id: userId } = req.user;
    const file = req.file;
    if (!file) return res.status(400).json({ message: '파일이 없습니다.' });

    const client = await getDbClient();
    try {
        const contentUrl = `/uploads/${file.filename}`;
        await client.query('BEGIN');

        const auctionResult = await client.query(
            "SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND status = 'paid' FOR UPDATE",
            [auctionId, userId]
        );
        if (auctionResult.rows.length === 0) throw new Error('업로드 권한이 없거나 경매 상태가 올바르지 않습니다.');

        await client.query(
            'INSERT INTO ad_content (auction_id, owner_id, content_type, content_url, approval_status) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (auction_id) DO UPDATE SET content_url = EXCLUDED.content_url, approval_status = EXCLUDED.approval_status, upload_time = CURRENT_TIMESTAMP',
            [auctionId, userId, file.mimetype, contentUrl, 'pending_approval']
        );
        await client.query("UPDATE auctions SET status = 'pending_approval' WHERE id = $1", [auctionId]);

        await client.query('COMMIT');
        res.status(201).json({ message: '광고가 성공적으로 업로드되었으며, 관리자 승인을 기다리고 있습니다.' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('광고 업로드 실패:', error);
        res.status(400).json({ message: error.message });
    } finally {
        try { client.release(); } catch (e) { /* ignore */ }
    }
});

// --- 6. 광고 업로드 취소 API (트랜잭션 개선) ---
app.delete('/api/ad-content/:auctionId', authenticateToken, async (req, res) => {
    const { auctionId } = req.params;
    const { id: userId } = req.user;

    const client = await getDbClient();
    try {
        await client.query('BEGIN');
        const adContentResult = await client.query(
            "SELECT * FROM ad_content WHERE auction_id = $1 AND owner_id = $2 AND approval_status = 'pending_approval'",
            [auctionId, userId]
        );
        if (adContentResult.rows.length === 0) throw new Error('취소할 수 있는 업로드 내역이 없거나 권한이 없습니다.');

        const adContent = adContentResult.rows[0];
        await client.query("DELETE FROM ad_content WHERE id = $1", [adContent.id]);
        await client.query("UPDATE auctions SET status = 'paid' WHERE id = $1", [auctionId]);

        const safePath = path.join(__dirname, adContent.content_url.replace(/^\//, ''));
        fs.unlink(safePath, (err) => { if (err) console.error("Error deleting file:", err); });

        await client.query('COMMIT');
        res.status(200).json({ message: '업로드가 성공적으로 취소되었습니다.' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('업로드 취소 실패:', error);
        res.status(400).json({ message: error.message });
    } finally {
        try { client.release(); } catch (e) { /* ignore */ }
    }
});

// --- 7. 관리자 API (관리자 인증 추가) ---
app.get('/api/admin/pending-ads', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM ad_content WHERE approval_status = 'pending_approval' ORDER BY upload_time ASC");
        res.json(result.rows);
    } catch (error) {
        console.error('관리자 대기 광고 조회 실패:', error);
        res.status(500).json({ message: '승인 대기 광고 목록 조회 실패' });
    }
});

app.patch('/api/admin/ad-content/:id/status', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { newStatus } = req.body;
    if (!['approved', 'rejected'].includes(newStatus)) return res.status(400).json({ message: '유효하지 않은 상태 값입니다.' });

    const client = await getDbClient();
    try {
        await client.query('BEGIN');
        const adResult = await client.query("UPDATE ad_content SET approval_status = $1 WHERE id = $2 RETURNING auction_id, owner_id", [newStatus, id]);
        if (adResult.rows.length === 0) throw new Error('해당 콘텐츠를 찾을 수 없습니다.');

        const { auction_id } = adResult.rows[0];
        const newAuctionStatus = (newStatus === 'approved') ? 'completed' : 'rejected';
        await client.query("UPDATE auctions SET status = $1 WHERE id = $2", [newAuctionStatus, auction_id]);

        // 간단한 관리자 로그 기록 (테이블 존재 시)
        try {
            await client.query("INSERT INTO admin_logs (admin_id, action, target_id) VALUES ($1, $2, $3)", [req.user.id, `ad_${newStatus}`, auction_id]);
        } catch (e) {
            // admin_logs 테이블이 없으면 무시
        }

        await client.query('COMMIT');
        res.status(200).json({ message: `콘텐츠 상태가 '${newStatus}'(으)로 성공적으로 변경되었습니다.` });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('관리자 승인/거절 실패:', error);
        res.status(500).json({ message: error.message || '상태 변경 중 오류 발생' });
    } finally {
        try { client.release(); } catch (e) { /* ignore */ }
    }
});

// 서버 시작
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`✅ Canvas X server is running on port ${PORT}`);

    // 서버 시작 시 즉시 한 번 경매 상태 점검
    manageAuctions();

    // 1시간마다 경매 상태 자동 점검
    setInterval(manageAuctions, 3600 * 1000);
});
