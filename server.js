// ===================================================================
// server.js (메인 서버 프로그램) - 관리자 인증 강화 버전
// ===================================================================
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('./db');

const app = express();

// --- CORS 설정 ---
const whitelist = [
    'http://localhost:3000',
    'https://cool-semifreddo-6004a7.netlify.app',
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

// JWT 시크릿 키
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-secret-key-for-canvas-x';
const TOSS_SECRET_KEY = 'test_sk_ma60RZblrqRmG7MmYpZ68wzYWBn1';

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

// =============================================
// 자동 경매 관리 시스템 (Scheduler)
// =============================================
const MINIMUM_ACTIVE_AUCTIONS = 3; // 항상 유지할 최소 활성 경매 수

async function manageAuctions() {
    console.log('[Scheduler] Running daily auction management task...');
    try {
        await db.query('BEGIN');

        // 1. 종료 시간이 지난 경매들을 'ended' 상태로 변경하고, 최종 낙찰자 정보 확정
        const endedResult = await db.query(
            "UPDATE auctions SET status = 'ended', final_bid = current_highest_bid, final_winner_id = current_winner_id WHERE end_time < NOW() AND status = 'active' RETURNING id"
        );
        if (endedResult.rows.length > 0) {
            console.log(`[Scheduler] ${endedResult.rows.length} auctions have ended.`);
        }

        // 2. 현재 활성 상태인 경매 수 확인
        const activeResult = await db.query("SELECT COUNT(*) FROM auctions WHERE status = 'active'");
        const activeCount = parseInt(activeResult.rows[0].count, 10);
        console.log(`[Scheduler] Found ${activeCount} active auctions.`);

        // 3. 부족한 만큼 새로운 경매 생성
        let newAuctionsNeeded = MINIMUM_ACTIVE_AUCTIONS - activeCount;
        if (newAuctionsNeeded > 0) {
            console.log(`[Scheduler] Creating ${newAuctionsNeeded} new auctions...`);
            const lastAuctionRes = await db.query("SELECT MAX(id) as last_id FROM auctions");
            let lastDate = lastAuctionRes.rows[0].last_id ? new Date(lastAuctionRes.rows[0].last_id) : new Date();

            for (let i = 0; i < newAuctionsNeeded; i++) {
                lastDate.setDate(lastDate.getDate() + 1);
                const newAuctionId = lastDate.toISOString().slice(0, 10); // 'YYYY-MM-DD'

                // 경매 종료 시간 설정 함수 (예: 이전 날짜 9시)
                const getAuctionEndTime = (dateStr) => {
                    const date = new Date(dateStr);
                    date.setDate(date.getDate() - 1);
                    date.setHours(9, 0, 0, 0);
                    return date;
                };
                const newEndTime = getAuctionEndTime(newAuctionId);

                await db.query(
                    "INSERT INTO auctions (id, start_time, end_time, status, starting_bid) VALUES ($1, NOW(), $2, 'active', 10000)",
                    [newAuctionId, newEndTime]
                );
                console.log(`[Scheduler] Created new auction for ${newAuctionId}`);
            }
        }

        await db.query('COMMIT');
        console.log('[Scheduler] Auction management task finished successfully.');
    } catch (error) {
        await db.query('ROLLBACK');
        console.error('[Scheduler] Error during auction management:', error);
    }
}

// =============================================
// API Endpoints
// =============================================

// --- 1. 사용자 인증 API ---
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

// login
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
        res.status(500).json({ message: '로그인 중 오류 발생' });
    }
});

// --- 2. 경매 API ---
// 활성 경매 목록 조회
app.get('/api/auctions', async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM auctions WHERE status = 'active' ORDER BY id ASC");
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: '경매 목록 조회 실패' });
    }
});

// 경매 상세 조회 (입찰 내역 포함)
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
        res.status(500).json({ message: '경매 상세 정보 조회 실패' });
    }
});

// 입찰 API에 authenticateToken 미들웨어를 추가하여 보안 강화
app.post('/api/auctions/:id/bid', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    const { id: auctionId } = req.params;
    const { id: userId } = req.user; 

    try {
        await db.query('BEGIN');
        const auctionResult = await db.query("SELECT * FROM auctions WHERE id = $1 FOR UPDATE", [auctionId]);
        const auction = auctionResult.rows[0];
        if (!auction || new Date() > new Date(auction.end_time)) throw new Error('종료된 경매입니다.');
        if (amount <= (auction.current_highest_bid || auction.starting_bid)) throw new Error('입찰 금액이 현재 최고가보다 낮습니다.');
        
        await db.query('UPDATE auctions SET current_highest_bid = $1, current_winner_id = $2 WHERE id = $3', [amount, userId, auctionId]);
        await db.query('INSERT INTO bids (auction_id, user_id, amount) VALUES ($1, $2, $3)', [auctionId, userId, amount]);
        await db.query('COMMIT');
        res.status(201).json({ message: '입찰 성공!' });
    } catch (error) {
        await db.query('ROLLBACK');
        res.status(400).json({ message: error.message });
    }
});

// --- 3. 대시보드 API (수정) ---
app.get('/api/users/:userId/won-auctions', authenticateToken, async (req, res) => {
    // 본인 또는 관리자만 조회 가능
    if (req.user.id !== req.params.userId && !req.user.is_admin) return res.sendStatus(403);
    try {
        // FIX: final_winner_id가 본인이고, 상태가 'active'가 아닌 모든 경매를 조회합니다.
        // 이렇게 하면 취소/환불로 final_winner_id가 변경된 경매는 더 이상 보이지 않습니다.
        const result = await db.query(
            "SELECT * FROM auctions WHERE final_winner_id = $1 AND status != 'active' ORDER BY id DESC", 
            [req.params.userId]
        );
        res.json(result.rows);
    } catch (error) {
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

        if (!auction) {
            return res.status(403).json({ message: '결제 대상 경매가 아니거나 권한이 없습니다.' });
        }

        res.json({
            amount: auction.final_bid,
            orderId: `canvasx_${auctionId}_${new Date().getTime()}`,
            orderName: `Canvas X - ${auctionId} 광고권`
        });
    } catch (error) {
        res.status(500).json({ message: '결제 정보를 생성하는 중 오류가 발생했습니다.' });
    }
});

app.post('/api/payments/confirm', authenticateToken, async (req, res) => {
    const { paymentKey, orderId, amount } = req.body;
    
    try {
        const response = await fetch('https://api.tosspayments.com/v1/payments/confirm', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${Buffer.from(TOSS_SECRET_KEY + ':').toString('base64')}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ paymentKey, orderId, amount }),
        });

        const paymentData = await response.json();
        if (!response.ok) throw new Error(paymentData.message || '결제 승인에 실패했습니다.');

        // 결제 검증 성공 시, 우리 데이터베이스 상태를 'paid'로 변경하고 paymentKey를 저장
        const auctionId = orderId.split('_')[1];
        await db.query(
            "UPDATE auctions SET status = 'paid', payment_key = $1 WHERE id = $2",
            [paymentKey, auctionId]
        );

        res.status(200).json({ message: '결제가 성공적으로 완료되었습니다.', ...paymentData });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// --- 4.5. 낙찰 포기 및 환불 API (신규 및 수정) ---

// 공통 로직: 차순위 입찰자에게 낙찰 기회를 넘기는 함수
async function offerToSecondBidder(auctionId) {
    // 1. 해당 경매의 2번째로 높은 입찰 기록을 찾음
    const secondBidderResult = await db.query(
        "SELECT user_id, amount FROM bids WHERE auction_id = $1 ORDER BY amount DESC, created_at ASC LIMIT 1 OFFSET 1",
        [auctionId]
    );

    if (secondBidderResult.rows.length > 0) {
        // 2. 차순위 입찰자가 있으면, 그 사람을 새로운 낙찰자로 지정
        const secondBidder = secondBidderResult.rows[0];
        await db.query(
            "UPDATE auctions SET status = 'ended', final_winner_id = $1, final_bid = $2 WHERE id = $3",
            [secondBidder.user_id, secondBidder.amount, auctionId]
        );
        console.log(`[Second Chance] Offered auction ${auctionId} to ${secondBidder.user_id} for ${secondBidder.amount}`);
    } else {
        // 3. 차순위 입찰자가 없으면, 경매를 유찰 상태로 변경 (또는 재경매 로직 추가 가능)
        await db.query(
            "UPDATE auctions SET status = 'failed', final_winner_id = NULL, final_bid = NULL WHERE id = $1",
            [auctionId]
        );
        console.log(`[Second Chance] No second bidder for auction ${auctionId}. Marked as failed.`);
    }
}

// 낙찰 포기 API (결제 전)
app.post('/api/auctions/:auctionId/cancel', authenticateToken, async (req, res) => {
    const { auctionId } = req.params;
    const { id: userId } = req.user;

    try {
        await db.query('BEGIN');
        const auctionResult = await db.query("SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND status = 'ended' FOR UPDATE", [auctionId, userId]);
        if (auctionResult.rows.length === 0) throw new Error('낙찰을 포기할 수 없는 상태입니다.');

        await offerToSecondBidder(auctionId);
        
        await db.query('COMMIT');
        res.status(200).json({ message: '낙찰을 포기했습니다. 차순위 입찰자에게 기회가 넘어갑니다.' });
    } catch (error) {
        await db.query('ROLLBACK');
        res.status(400).json({ message: error.message });
    }
});

// 환불 요청 API (결제 후)
app.post('/api/auctions/:auctionId/refund', authenticateToken, async (req, res) => {
    const { auctionId } = req.params;
    const { id: userId } = req.user;

    try {
        await db.query('BEGIN');
        const auctionResult = await db.query("SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 FOR UPDATE", [auctionId, userId]);
        if (auctionResult.rows.length === 0) throw new Error('환불을 요청할 수 없는 경매입니다.');
        
        const auction = auctionResult.rows[0];
        const auctionDate = new Date(auction.id);
        const refundDeadline = new Date(auctionDate.getFullYear(), auctionDate.getMonth(), auctionDate.getDate(), 17, 0, 0);

        if (new Date() > refundDeadline) {
            throw new Error('환불 가능한 시간이 지났습니다 (당일 17시까지).');
        }
        
        // 데이터베이스에 저장된 paymentKey를 가져옵니다.
        const paymentKey = auction.payment_key;
        if (!paymentKey) {
            throw new Error('결제 정보를 찾을 수 없어 환불할 수 없습니다.');
        }
        
        // 실제 토스페이먼츠 환불 API 호출
        const refundResponse = await fetch(`https://api.tosspayments.com/v1/payments/${paymentKey}/cancel`, {
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
        
        console.log(`[Refund] Successfully processed refund for auction ${auctionId}`);

        await offerToSecondBidder(auctionId);

        // 업로드된 광고가 있다면 삭제
        const adContentResult = await db.query("DELETE FROM ad_content WHERE auction_id = $1 RETURNING content_url", [auctionId]);
        if (adContentResult.rows.length > 0) {
            const filePath = path.join(__dirname, adContentResult.rows[0].content_url);
            fs.unlink(filePath, (err) => {
                if (err) console.error("Error deleting refunded ad file:", err);
            });
        }

        await db.query('COMMIT');
        res.status(200).json({ message: '환불이 요청되었습니다. 차순위 입찰자에게 기회가 넘어갑니다.' });
    } catch (error) {
        await db.query('ROLLBACK');
        res.status(400).json({ message: error.message });
    }
});

// --- 5. 광고 업로드 API (수정) ---
app.post('/api/ad-content/upload', authenticateToken, upload.single('adFile'), async (req, res) => {
    const { auctionId } = req.body;
    const { id: userId } = req.user;
    const file = req.file;
    if (!file) return res.status(400).json({ message: '파일이 없습니다.' });
    try {
        const contentUrl = `/uploads/${file.filename}`;
        await db.query('BEGIN');
        const auctionResult = await db.query(
            "SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND status = 'paid' FOR UPDATE",
            [auctionId, userId]
        );
        
        await db.query(
            'INSERT INTO ad_content (auction_id, owner_id, content_type, content_url, approval_status) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (auction_id) DO UPDATE SET content_url = $4, approval_status = $5, upload_time = CURRENT_TIMESTAMP',
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

// --- 6. 광고 업로드 취소 API (신규) ---
app.delete('/api/ad-content/:auctionId', authenticateToken, async (req, res) => {
    const { auctionId } = req.params;
    const { id: userId } = req.user;
    try {
        await db.query('BEGIN');
        const adContentResult = await db.query(
            "SELECT * FROM ad_content WHERE auction_id = $1 AND owner_id = $2 AND approval_status = 'pending_approval'",
            [auctionId, userId]
        );
        if (adContentResult.rows.length === 0) throw new Error('취소할 수 있는 업로드 내역이 없거나 권한이 없습니다.');
        
        const adContent = adContentResult.rows[0];
        await db.query("DELETE FROM ad_content WHERE id = $1", [adContent.id]);
        await db.query("UPDATE auctions SET status = 'paid' WHERE id = $1", [auctionId]);

        const filePath = path.join(__dirname, adContent.content_url);
        fs.unlink(filePath, (err) => {
            if (err) console.error("Error deleting file:", err);
        });

        await db.query('COMMIT');
        res.status(200).json({ message: '업로드가 성공적으로 취소되었습니다.' });
    } catch (error) {
        await db.query('ROLLBACK');
        res.status(400).json({ message: error.message });
    }
});

// --- 7. 관리자 API (관리자 인증 추가) ---
app.get('/api/admin/pending-ads', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM ad_content WHERE approval_status = 'pending_approval' ORDER BY upload_time ASC");
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: '승인 대기 광고 목록 조회 실패' });
    }
});

// 광고 승인/거절
app.patch('/api/admin/ad-content/:id/status', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { newStatus } = req.body;
    if (!['approved', 'rejected'].includes(newStatus)) {
        return res.status(400).json({ message: '유효하지 않은 상태 값입니다.' });
    }
    try {
        await db.query('BEGIN');
        const adResult = await db.query("UPDATE ad_content SET approval_status = $1 WHERE id = $2 RETURNING auction_id", [newStatus, id]);
        if (adResult.rows.length === 0) throw new Error('해당 콘텐츠를 찾을 수 없습니다.');
        
        const { auction_id } = adResult.rows[0];
        // 광고가 거절되면, 해당 경매의 상태를 'rejected'로 변경하여 사용자가 재업로드할 수 있도록 합니다.
        const newAuctionStatus = (newStatus === 'approved') ? 'completed' : 'rejected';
        await db.query("UPDATE auctions SET status = $1 WHERE id = $2", [newAuctionStatus, auction_id]);
        
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
    console.log(`✅ Canvas X server is running on port ${PORT}`);

    // 서버 시작 시 즉시 한 번 경매 상태 점검
    manageAuctions();

    // 1시간마다 경매 상태 자동 점검
    setInterval(manageAuctions, 3600 * 1000);
});
