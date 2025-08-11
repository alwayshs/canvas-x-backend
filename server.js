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

// =============================================
// 자동 경매 관리 시스템 (Scheduler)
// =============================================
const MINIMUM_ACTIVE_AUCTIONS = 3; // 항상 유지할 최소 활성 경매 수

async function manageAuctions() {
    console.log('[Scheduler] Running daily auction management task...');
    try {
        await db.query('BEGIN');

        // 1. 종료 시간이 지난 경매들을 'ended' 상태로 변경하고, 최종 낙찰자 정보를 확정합니다.
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
            // 3-1. 데이터베이스에 있는 가장 마지막 경매 날짜를 찾습니다.
            const lastAuctionRes = await db.query("SELECT MAX(id) as last_id FROM auctions");
            let lastDate = lastAuctionRes.rows[0].last_id ? new Date(lastAuctionRes.rows[0].last_id) : new Date();

            for (let i = 0; i < newAuctionsNeeded; i++) {
                lastDate.setDate(lastDate.getDate() + 1); // 날짜를 하루씩 증가시킵니다.
                const newAuctionId = lastDate.toISOString().slice(0, 10); // 'YYYY-MM-DD' 형식

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
// POST /api/users/signup
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

        // 사용자 등록
        const newUser = await db.query(
            'INSERT INTO users (email, password_hash, nickname) VALUES ($1, $2, $3) RETURNING id, email, nickname',
            [email, password_hash, nickname]
        );

        res.status(201).json(newUser.rows[0]);
    } catch (error) {
        console.error('회원가입 오류:', error);
        res.status(500).json({ message: '회원가입 중 오류가 발생했습니다.' });
    }
});

// POST /api/users/login
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

        // 세션 또는 토큰 발급(필요 시 추가)
        res.json({ message: '로그인 성공!', user: { id: user.id, email: user.email, nickname: user.nickname } });
    } catch (error) {
        console.error('로그인 오류:', error);
        res.status(500).json({ message: '로그인 중 오류가 발생했습니다.' });
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

// POST /api/auctions/:id/bid
app.post('/api/auctions/:id/bid', async (req, res) => {
    const { userId, amount } = req.body;
    const { id } = req.params;

    if (!userId || !amount)
        return res.status(400).json({ message: '사용자 ID와 입찰 금액을 모두 입력해주세요.' });

    try {
        await db.query('BEGIN');

        // 경매 잠금 (FOR UPDATE)
        const auctionResult = await db.query("SELECT * FROM auctions WHERE id = $1 FOR UPDATE", [id]);
        if (auctionResult.rows.length === 0) throw new Error('존재하지 않는 경매입니다.');

        const auction = auctionResult.rows[0];
        if (new Date() > new Date(auction.end_time)) throw new Error('종료된 경매입니다.');
        const minBid = auction.current_highest_bid || auction.starting_bid;
        if (amount <= minBid) throw new Error(`입찰 금액은 현재 최고가(${minBid}원)보다 커야 합니다.`);

        // 사용자 존재 확인
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

// --- 3. 대시보드 API ---
app.get('/api/users/:userId/won-auctions', async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM auctions WHERE final_winner_id = $1 ORDER BY id DESC", [req.params.userId]);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: '낙찰 내역 조회 실패' });
    }
});

// --- 4. 결제 API (실제 연동) ---

// 결제 정보를 생성하고 클라이언트에 전달하는 API
app.post('/api/payments/request', async (req, res) => {
    const { auctionId, userId } = req.body;
    try {
        // 실제 DB에서 낙찰 정보 확인 (상태가 'ended'이고, final_winner_id가 일치하는지)
        const auctionResult = await db.query(
            "SELECT * FROM auctions WHERE id = $1 AND final_winner_id = $2 AND status = 'ended'",
            [auctionId, userId]
        );
        const auction = auctionResult.rows[0];

        if (!auction) {
            return res.status(403).json({ message: '결제 대상 경매가 아니거나 권한이 없습니다.' });
        }

        // 클라이언트에게 토스페이먼츠 결제창을 띄우는 데 필요한 정보를 전달
        res.json({
            amount: auction.final_bid,
            orderId: `canvasx_${auctionId}_${new Date().getTime()}`, // 고유한 주문 ID 생성
            orderName: `Canvas X - ${auctionId} 광고권`
        });
    } catch (error) {
        console.error('Payment request error:', error);
        res.status(500).json({ message: '결제 정보를 생성하는 중 오류가 발생했습니다.' });
    }
});

// 토스페이먼츠 결제 성공 후, 최종 승인을 처리하는 API
app.post('/api/payments/confirm', async (req, res) => {
    const { paymentKey, orderId, amount } = req.body;
    
    // 실제 운영 시에는 환경 변수로 안전하게 관리해야 합니다.
    const secretKey = process.env.TOSS_SECRET_KEY || 'YOUR_TOSS_PAYMENTS_SECRET_KEY';

    try {
        // 토스페이먼츠 서버에 결제 승인 요청
        const response = await fetch('https://api.tosspayments.com/v1/payments/confirm', {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${Buffer.from(secretKey + ':').toString('base64')}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ paymentKey, orderId, amount }),
        });

        const paymentData = await response.json();

        if (!response.ok) {
            throw new Error(paymentData.message || '결제 승인에 실패했습니다.');
        }

        // 결제 검증 성공 시, 우리 데이터베이스 상태를 'paid'로 변경
        const auctionId = orderId.split('_')[1];
        await db.query("UPDATE auctions SET status = 'paid' WHERE id = $1", [auctionId]);

        console.log(`Payment successful for orderId: ${orderId}`);
        res.status(200).json({ message: '결제가 성공적으로 완료되었습니다.', ...paymentData });

    } catch (error) {
        console.error('Payment confirmation error:', error);
        // (실제로는 결제 실패 시 토스페이먼츠에 결제 취소 API를 호출하는 로직도 필요)
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
    console.log(`✅ Canvas X server is running on port ${PORT}`);
    
    // 서버가 시작되면 즉시 한 번 경매 상태를 점검하고,
    manageAuctions(); 
    
    // 그 후 1시간마다 주기적으로 경매 상태를 점검하여 자동 관리합니다.
    setInterval(manageAuctions, 3600 * 1000); // 1시간 = 3600초 * 1000ms
});
