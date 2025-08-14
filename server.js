// ===================================================================
// server.js - 리팩터링된 Canvas X 메인 서버
// ===================================================================

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
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

// --- 미들웨어 ---
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

function isAdmin(req, res, next) {
    if (req.user && req.user.is_admin) {
        next();
    } else {
        res.status(403).json({ message: '관리자 권한이 필요합니다.' });
    }
}

async function getDbClient() {
    if (typeof db.connect === 'function') {
        return await db.connect();
    }
    if (db.pool && typeof db.pool.connect === 'function') {
        return await db.pool.connect();
    }
    throw new Error('DB client를 얻을 수 없습니다.');
}

function getBidIncrement(currentBid) {
    if (currentBid >= 100000000) return 2500000;
    if (currentBid >= 50000000) return 1000000;
    if (currentBid >= 10000000) return 500000;
    if (currentBid >= 5000000) return 250000;
    if (currentBid >= 1000000) return 100000;
    if (currentBid >= 250000) return 50000;
    if (currentBid >= 50000) return 10000;
    return 5000;
}

// --- 자동 경매 관리 시스템 (Scheduler) ---
const MINIMUM_ACTIVE_AUCTIONS = 3;

async function manageAuctions() {
    console.log('[Scheduler] Running auction management task...');
    const client = await db.connect();
    try {
        await client.query('BEGIN');

        const endedResult = await client.query(
            "UPDATE auctions SET status = 'ended', final_bid = current_highest_bid, final_winner_id = current_winner_id WHERE end_time < NOW() AND status = 'active' RETURNING id"
        );
        if (endedResult.rows.length > 0) {
            console.log(`[Scheduler] ${endedResult.rows.length} auctions have ended and winners are finalized.`);
        }

        const activeResult = await client.query("SELECT COUNT(*) FROM auctions WHERE status = 'active'");
        const activeCount = parseInt(activeResult.rows[0].count, 10);
        
        let newAuctionsNeeded = MINIMUM_ACTIVE_AUCTIONS - activeCount;
        if (newAuctionsNeeded > 0) {
            const lastAuctionRes = await client.query("SELECT MAX(id) as last_id FROM auctions");
            
            let lastDate;
            if (lastAuctionRes.rows[0].last_id) {
                lastDate = new Date(lastAuctionRes.rows[0].last_id + 'T00:00:00'); // 문자열 → Date
            } else {
                const now = new Date();
                lastDate = new Date(now.getFullYear(), now.getMonth(), now.getDate()); // 오늘 날짜
            }

            for (let i = 0; i < newAuctionsNeeded; i++) {
                lastDate.setDate(lastDate.getDate() + 1); // 하루 더하기
                const newAuctionId = lastDate.toISOString().slice(0, 10);

                // KST 오전 9시를 UTC로 변환
                // KST = UTC+9 → UTC 시간 = KST - 9시간
                const endTimeUTC = new Date(
                    lastDate.getFullYear(),
                    lastDate.getMonth(),
                    lastDate.getDate() - 1, // 광고일 하루 전
                    0, 0, 0, 0 // UTC 기준 0시 = KST 오전 9시
                );

                await client.query(
                    "INSERT INTO auctions (id, start_time, end_time, status, starting_bid) VALUES ($1, NOW(), $2, 'active', 10000) ON CONFLICT (id) DO NOTHING",
                    [newAuctionId, endTimeUTC]
                );
            }
        }

        await client.query('COMMIT');
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('[Scheduler] Error during auction management:', error);
    } finally {
        client.release();
    }
}

// --- 공통 로직: 차순위 입찰자에게 기회 제공 (수정) ---
async function offerToSecondBidder(client, auctionId, forfeitedUserIds = []) {
    // FIX: 이미 포기한 사용자들을 제외하고, 그 다음으로 높은 금액을 제시한 '다른' 사용자를 찾습니다.
    const secondBidderResult = await client.query(
        `SELECT user_id, MAX(amount) as max_bid
         FROM bids 
         WHERE auction_id = $1 AND user_id NOT IN (${forfeitedUserIds.map((_, i) => `$${i + 2}`).join(',')})
         GROUP BY user_id
         ORDER BY max_bid DESC
         LIMIT 1`,
        [auctionId, ...forfeitedUserIds]
    );

    if (secondBidderResult.rows.length > 0) {
        const secondBidder = secondBidderResult.rows[0];
        await client.query(
            "UPDATE auctions SET status = 'ended', final_winner_id = $1, final_bid = $2, current_winner_id = $1, current_highest_bid = $2 WHERE id = $3",
            [secondBidder.user_id, secondBidder.max_bid, auctionId]
        );
        console.log(`[Second Chance] Offered auction ${auctionId} to ${secondBidder.user_id}`);
    } else {
        await client.query(
            "UPDATE auctions SET status = 'failed', final_winner_id = NULL, final_bid = NULL WHERE id = $1",
            [auctionId]
        );
        console.log(`[Second Chance] No other bidders for auction ${auctionId}. Marked as failed.`);
    }
}

// =============================================
// API Endpoints
// =============================================

// --- 1. 사용자 인증 API (수정) ---
app.post('/api/users/signup', async (req, res) => {
    // ci, di 값을 추가로 받습니다.
    const { email, password, nickname, ci, di } = req.body; 
    if (!email || !password || !nickname || !ci || !di) {
        return res.status(400).json({ message: '모든 필드를 입력해주세요.' });
    }
    try {
        // FIX: CI 또는 DI 값이 이미 데이터베이스에 있는지 확인하여 중복 가입을 방지합니다.
        const existingUser = await db.query(
            'SELECT id FROM users WHERE ci = $1 OR di = $2',
            [ci, di]
        );
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ message: '이미 본인인증을 통해 가입된 사용자입니다.' });
        }

        const password_hash = await bcrypt.hash(password, 10);
        const newUserId = uuidv4();
        
        const newUser = await db.query(
            'INSERT INTO users (id, email, password_hash, nickname, ci, di) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, nickname',
            [newUserId, email, password_hash, nickname, ci, di]
        );
        res.status(201).json(newUser.rows[0]);
    } catch (error) {
        console.error('Signup Error:', error);
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

app.get('/api/auctions', async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM auctions WHERE status = 'active' ORDER BY id ASC");
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: '경매 목록 조회 실패' });
    }
});

// --- 2. 경매 API (수정) ---
app.get('/api/auctions/:id', async (req, res) => {
    try {
        const auctionResult = await db.query('SELECT * FROM auctions WHERE id = $1', [req.params.id]);
        if (auctionResult.rows.length === 0) return res.status(404).json({ message: '경매를 찾을 수 없습니다.' });
        
        const auction = auctionResult.rows[0];
        const bidsResult = await db.query("SELECT b.amount, u.nickname FROM bids b JOIN users u ON b.user_id = u.id WHERE b.auction_id = $1 ORDER BY b.created_at DESC", [req.params.id]);

        // 최소 다음 입찰가를 계산하여 함께 전달
        const currentBid = auction.current_highest_bid || auction.starting_bid;
        const increment = getBidIncrement(currentBid);
        const minimumNextBid = currentBid + increment;

        res.json({ auction: { ...auction, minimumNextBid }, bids: bidsResult.rows });
    } catch (error) {
        res.status(500).json({ message: '경매 상세 정보 조회 실패' });
    }
});

app.post('/api/auctions/:id/bid', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    const { id: auctionId } = req.params;
    const { id: userId } = req.user;
    const client = await db.connect();
    try {
        await client.query('BEGIN');
        const auctionResult = await client.query("SELECT * FROM auctions WHERE id = $1 FOR UPDATE", [auctionId]);
        const auction = auctionResult.rows[0];

        // 입찰 유효성 검증 강화
        if (!auction || new Date() > new Date(auction.end_time)) throw new Error('종료된 경매입니다.');
        if (auction.current_winner_id === userId) throw new Error('이미 최고 입찰자입니다.');
        
        const currentBid = auction.current_highest_bid || auction.starting_bid;
        const increment = getBidIncrement(currentBid);
        const minimumNextBid = currentBid + increment;

        if (amount < minimumNextBid) {
            throw new Error(`입찰 금액은 최소 ₩${minimumNextBid.toLocaleString()} 이상이어야 합니다.`);
        }

        await client.query('UPDATE auctions SET current_highest_bid = $1, current_winner_id = $2 WHERE id = $3', [amount, userId, auctionId]);
        await client.query('INSERT INTO bids (auction_id, user_id, amount) VALUES ($1, $2, $3)', [auctionId, userId, amount]);
        await client.query('COMMIT');
        res.status(201).json({ message: '입찰 성공!' });
    } catch (error) {
        await client.query('ROLLBACK');
        res.status(400).json({ message: error.message });
    } finally {
        client.release();
    }
});

// --- 3. 대시보드 API (수정) ---
app.get('/api/users/:userId/won-auctions', authenticateToken, async (req, res) => {
    if (req.user.id !== req.params.userId && !req.user.is_admin) return res.sendStatus(403);
    try {
        const result = await db.query(
            "SELECT * FROM auctions WHERE final_winner_id = $1 AND status NOT IN ('active', 'cancelled', 'refunded', 'failed') ORDER BY id DESC",
            [req.params.userId]
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: '낙찰 내역 조회 실패' });
    }
});

// 신규: 참여중인 경매 목록 조회 API
app.get('/api/users/:userId/participating-auctions', authenticateToken, async (req, res) => {
    if (req.user.id !== req.params.userId && !req.user.is_admin) return res.sendStatus(403);
    try {
        // 사용자가 입찰한 모든 'active' 상태의 경매를 중복 없이 조회합니다.
        // 또한, 해당 경매에서 사용자의 최고 입찰액을 함께 조회합니다.
        const query = `
            SELECT DISTINCT ON (a.id)
                a.id,
                a.end_time,
                a.current_highest_bid,
                (SELECT amount FROM bids WHERE auction_id = a.id AND user_id = $1 ORDER BY amount DESC LIMIT 1) AS my_highest_bid
            FROM auctions a
            JOIN bids b ON a.id = b.auction_id
            WHERE a.status = 'active' AND b.user_id = $1
            ORDER BY a.id DESC;
        `;
        const result = await db.query(query, [req.params.userId]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching participating auctions:', error);
        res.status(500).json({ message: '참여중인 경매 내역 조회에 실패했습니다.' });
    }
});


// 신규: 결제 정보를 생성하고 클라이언트에 전달하는 API
app.post('/api/payments/request', authenticateToken, async (req, res) => {
    const { auctionId } = req.body;
    const { id: userId } = req.user;
    try {
        const auctionResult = await db.query(
            "SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND status = 'ended'",
            [auctionId, userId]
        );
        const auction = auctionResult.rows[0];

        if (!auction) {
            return res.status(403).json({ message: '결제 대상 경매가 아니거나 권한이 없습니다.' });
        }

        res.json({
            amount: auction.final_bid,
            orderId: `canvasx_${auctionId}_${new Date().getTime()}`,
            orderName: `Canvas X - ${auctionId} 광고권`
        });
    } catch (error) {
        console.error('Payment request error:', error);
        res.status(500).json({ message: '결제 정보를 생성하는 중 오류가 발생했습니다.' });
    }
});

app.post('/api/payments/confirm', authenticateToken, async (req, res) => {
    const { paymentKey, orderId, amount } = req.body;
    try {
        if (!fetchFn) throw new Error('fetch is not available');
        const response = await fetchFn('https://api.tosspayments.com/v1/payments/confirm', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${Buffer.from(TOSS_SECRET_KEY + ':').toString('base64')}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ paymentKey, orderId, amount }),
        });
        const paymentData = await response.json();
        if (!response.ok) throw new Error(paymentData.message || '결제 승인 실패');
        const auctionId = orderId.split('_')[1];
        await db.query("UPDATE auctions SET status = 'paid', payment_key = $1 WHERE id = $2", [paymentKey, auctionId]);
        res.status(200).json({ message: '결제가 성공적으로 완료되었습니다.', ...paymentData });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// --- 4. 낙찰 포기 및 환불 API (수정) ---
// --- 낙찰 포기 API ---
app.post('/api/auctions/:auctionId/cancel', authenticateToken, async (req, res) => {
    const { auctionId } = req.params;
    const { id: userId } = req.user;
    const client = await db.connect();
    try {
        await client.query('BEGIN');
        
        // 1. 먼저, 현재 경매의 모든 정보를 가져와 'auction' 변수에 저장합니다.
        const auctionResult = await client.query(
            "SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND status = 'ended' FOR UPDATE",
            [auctionId, userId]
        );
        if (auctionResult.rows.length === 0) throw new Error('낙찰을 포기할 수 없는 상태입니다.');
        
        const auction = auctionResult.rows[0]; // <- 여기에 이전 낙찰자 ID가 안전하게 저장됩니다.

        // 2. 그 다음, 경매 상태를 'cancelled'로 변경합니다.
        await client.query("UPDATE auctions SET status = 'cancelled' WHERE id = $1", [auctionId]);
        
        // 3. 마지막으로, 아까 저장해두었던 'auction.final_winner_id'를 이용해 차순위 입찰자를 찾습니다.
        await offerToSecondBidder(client, auctionId, [auction.final_winner_id]);
        
        await client.query('COMMIT');
        res.status(200).json({ message: '낙찰을 포기했습니다. 차순위 입찰자에게 기회가 넘어갑니다.' });
    } catch (error) {
        await client.query('ROLLBACK');
        res.status(400).json({ message: error.message });
    } finally {
        client.release();
    }
});

// --- 환불 API ---
app.post('/api/auctions/:auctionId/refund', authenticateToken, async (req, res) => {
    const { auctionId } = req.params;
    const { id: userId } = req.user;
    const client = await db.connect();
    try {
        await client.query('BEGIN');

        // 상태 조건을 실제 DB 상태에 맞게 확장
        const auctionResult = await client.query(
            "SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND status IN ('paid', 'completed') FOR UPDATE",
            [auctionId, userId]
        );

        if (auctionResult.rows.length === 0) throw new Error('환불을 요청할 수 없는 경매입니다.');

        const auction = auctionResult.rows[0];
        const auctionDate = new Date(auction.id);
        const refundDeadline = new Date(auctionDate.getFullYear(), auctionDate.getMonth(), auctionDate.getDate(), 17, 0, 0);
        if (new Date() > refundDeadline) throw new Error('환불 가능한 시간이 지났습니다 (당일 17시까지).');

        const paymentKey = auction.payment_key;
        if (!paymentKey) throw new Error('결제 정보를 찾을 수 없어 환불할 수 없습니다.');
        if (!fetchFn) throw new Error('fetch is not available');

        // 토스페이먼츠 환불 요청
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

        // 상태를 'refunded'로 변경
        await client.query("UPDATE auctions SET status = 'refunded' WHERE id = $1", [auctionId]);

        // 차순위 입찰자에게 기회 제공
        await offerToSecondBidder(client, auctionId, [auction.final_winner_id]);
        
        // 업로드된 광고 파일 삭제
        const adContentResult = await client.query("DELETE FROM ad_content WHERE auction_id = $1 RETURNING content_url", [auctionId]);
        if (adContentResult.rows.length > 0) {
            const safePath = path.join(__dirname, adContentResult.rows[0].content_url.replace(/^\//, ''));
            fs.unlink(safePath, (err) => { if (err) console.error("Error deleting refunded ad file:", err); });
        }

        await client.query('COMMIT');
        res.status(200).json({ message: '환불이 요청되었습니다.' });
    } catch (error) {
        await client.query('ROLLBACK');
        res.status(400).json({ message: error.message });
    } finally {
        client.release();
    }
});

app.post('/api/ad-content/upload', authenticateToken, upload.single('adFile'), async (req, res) => {
    const { auctionId } = req.body;
    const { id: userId } = req.user;
    const file = req.file;
    if (!file) return res.status(400).json({ message: '파일이 없습니다.' });
    const client = await getDbClient();
    try {
        const contentUrl = `/uploads/${file.filename}`;
        await client.query('BEGIN');
        const auctionResult = await client.query("SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND (status = 'paid' OR status = 'rejected') FOR UPDATE", [auctionId, userId]);
        if (auctionResult.rows.length === 0) throw new Error('업로드 권한이 없거나 경매 상태가 올바르지 않습니다.');
        await client.query('INSERT INTO ad_content (auction_id, owner_id, content_type, content_url, approval_status) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (auction_id) DO UPDATE SET content_url = EXCLUDED.content_url, approval_status = EXCLUDED.approval_status, upload_time = CURRENT_TIMESTAMP', [auctionId, userId, file.mimetype, contentUrl, 'pending_approval']);
        await client.query("UPDATE auctions SET status = 'pending_approval' WHERE id = $1", [auctionId]);
        await client.query('COMMIT');
        res.status(201).json({ message: '광고가 성공적으로 업로드되었으며, 관리자 승인을 기다리고 있습니다.' });
    } catch (error) {
        await client.query('ROLLBACK');
        res.status(400).json({ message: error.message });
    } finally {
        client.release();
    }
});

app.delete('/api/ad-content/:auctionId', authenticateToken, async (req, res) => {
    const { auctionId } = req.params;
    const { id: userId } = req.user;
    const client = await getDbClient();
    try {
        await client.query('BEGIN');
        const adContentResult = await client.query("SELECT * FROM ad_content WHERE auction_id = $1 AND owner_id = $2 AND approval_status = 'pending_approval'", [auctionId, userId]);
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
        res.status(400).json({ message: error.message });
    } finally {
        client.release();
    }
});

app.get('/api/admin/pending-ads', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM ad_content WHERE approval_status = 'pending_approval' ORDER BY upload_time ASC");
        res.json(result.rows);
    } catch (error) {
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
        await client.query('COMMIT');
        res.status(200).json({ message: `콘텐츠 상태가 '${newStatus}'(으)로 성공적으로 변경되었습니다.` });
    } catch (error) {
        await client.query('ROLLBACK');
        res.status(500).json({ message: error.message || '상태 변경 중 오류 발생' });
    } finally {
        client.release();
    }
});

// --- 7. 아카이브 API (수정) ---
app.get('/api/archive', async (req, res) => {
    try {
        // 1. 역대 최고가 낙찰 광고 (상위 5개)
        const topBidsQuery = `
            SELECT a.id, a.final_bid, ad.content_url 
            FROM auctions a
            LEFT JOIN ad_content ad ON a.id = ad.auction_id
            WHERE a.status IN ('completed', 'approved') AND a.final_bid IS NOT NULL
            ORDER BY a.final_bid DESC
            LIMIT 5;
        `;
        const topBidsResult = await db.query(topBidsQuery);

        // 2. 지난달 최고의 광고 (상위 5개 - 인기도는 시뮬레이션)
        const lastMonthQuery = `
            SELECT a.id, a.final_bid, ad.content_url, ad.likes
            FROM auctions a
            LEFT JOIN ad_content ad ON a.id = ad.auction_id
            WHERE a.status IN ('completed', 'approved') 
              AND a.id >= date_trunc('month', current_date - interval '1 month')::date::text
              AND a.id < date_trunc('month', current_date)::date::text
            ORDER BY ad.likes DESC NULLS LAST, a.final_bid DESC
            LIMIT 5;
        `;
        const lastMonthResult = await db.query(lastMonthQuery);

        // 3. 데이터 기반 기록 보관소
        const records = {
            firstAd: null,
            fiercestAuction: null,
            mostParticipantsAuction: null,
            allTimePopular: null,
            finalHourFrenzy: null,
        };

        // 3-1. 최초의 광고
        const firstAdRes = await db.query("SELECT a.id, ad.content_url FROM auctions a LEFT JOIN ad_content ad ON a.id = ad.auction_id WHERE a.status IN ('completed', 'approved') ORDER BY a.id ASC LIMIT 1");
        if (firstAdRes.rows.length > 0) {
            records.firstAd = firstAdRes.rows[0];
        }
        
        // 3-2. 가장 치열했던 경매
        const fiercestAuctionRes = await db.query("SELECT auction_id, COUNT(*) as count FROM bids GROUP BY auction_id ORDER BY count DESC LIMIT 1");
        if (fiercestAuctionRes.rows.length > 0) {
            const fiercestId = fiercestAuctionRes.rows[0].auction_id;
            const fiercestData = await db.query("SELECT a.id, a.final_bid, ad.content_url FROM auctions a LEFT JOIN ad_content ad ON a.id = ad.auction_id WHERE a.id = $1", [fiercestId]);
            if (fiercestData.rows.length > 0) {
                records.fiercestAuction = { ...fiercestData.rows[0], count: fiercestAuctionRes.rows[0].count };
            }
        }

        // 3-3. 최다 참여자 경매
        const mostParticipantsRes = await db.query("SELECT auction_id, COUNT(DISTINCT user_id) as count FROM bids GROUP BY auction_id ORDER BY count DESC LIMIT 1");
        if (mostParticipantsRes.rows.length > 0) {
            const mostParticipantsId = mostParticipantsRes.rows[0].auction_id;
            const mostParticipantsData = await db.query("SELECT a.id, a.final_bid, ad.content_url FROM auctions a LEFT JOIN ad_content ad ON a.id = ad.auction_id WHERE a.id = $1", [mostParticipantsId]);
            if (mostParticipantsData.rows.length > 0) {
                records.mostParticipantsAuction = { ...mostParticipantsData.rows[0], count: mostParticipantsRes.rows[0].count };
            }
        }

        // 3-4. 역대 최고의 인기 광고
        const allTimePopularRes = await db.query(`
            SELECT a.id, a.final_bid, ad.content_url, ad.likes 
            FROM auctions a
            JOIN ad_content ad ON a.id = ad.auction_id
            WHERE a.status IN ('completed', 'approved') 
            ORDER BY ad.likes DESC NULLS LAST, a.final_bid DESC 
            LIMIT 1
        `);
        if (allTimePopularRes.rows.length > 0) {
            records.allTimePopular = allTimePopularRes.rows[0];
        }

        // 3-5. 마지막 1시간의 광란
        const finalHourFrenzyRes = await db.query(`
            SELECT b.auction_id, COUNT(b.id) as count
            FROM bids b
            JOIN auctions a ON b.auction_id = a.id
            WHERE b.created_at BETWEEN (a.end_time - INTERVAL '1 hour') AND a.end_time
            GROUP BY b.auction_id
            ORDER BY count DESC
            LIMIT 1;
        `);
        if (finalHourFrenzyRes.rows.length > 0) {
            const frenzyId = finalHourFrenzyRes.rows[0].auction_id;
            const frenzyData = await db.query("SELECT a.id, a.final_bid, ad.content_url FROM auctions a LEFT JOIN ad_content ad ON a.id = ad.auction_id WHERE a.id = $1", [frenzyId]);
            if (frenzyData.rows.length > 0) {
                records.finalHourFrenzy = { ...frenzyData.rows[0], count: finalHourFrenzyRes.rows[0].count };
            }
        }

        res.json({
            topBids: topBidsResult.rows,
            lastMonthBest: lastMonthResult.rows,
            records: records
        });

    } catch (error) {
        console.error('Error fetching archive data:', error);
        res.status(500).json({ message: '아카이브 데이터를 불러오는 중 오류가 발생했습니다.' });
    }
});

// --- 8. 인기도 API (신규) ---
// 광고에 '좋아요'를 추가하는 API
app.post('/api/ads/:auctionId/like', authenticateToken, async (req, res) => {
    const { auctionId } = req.params;
    try {
        // ad_content 테이블에서 해당 광고의 likes를 1 증가시킵니다.
        const result = await db.query(
            "UPDATE ad_content SET likes = likes + 1 WHERE auction_id = $1 RETURNING likes",
            [auctionId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: '좋아요를 누를 광고를 찾을 수 없습니다.' });
        }

        res.status(200).json({ message: '좋아요가 반영되었습니다.', newLikes: result.rows[0].likes });
    } catch (error) {
        console.error('Error liking ad:', error);
        res.status(500).json({ message: '좋아요 처리 중 오류가 발생했습니다.' });
    }
});

// 서버 시작
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`✅ Canvas X server is running on port ${PORT}`);
    manageAuctions();
    setInterval(manageAuctions, 3600 * 1000);
});
