// ===================================================================
// db.js - 리팩터링된 서버와 호환되는 최종 버전
// ===================================================================
const { Pool } = require('pg');

const pool = new Pool({
    // Render 대시보드의 Environment 탭에 저장된 DATABASE_URL 주소를 자동으로 사용합니다.
    connectionString: process.env.DATABASE_URL, 
    // Render의 PostgreSQL 데이터베이스에 연결하기 위한 필수 보안 설정입니다.
    ssl: {
        rejectUnauthorized: false
    }
});

module.exports = {
    // 기존의 간단한 쿼리 기능
    query: (text, params) => pool.query(text, params),
    
    // 서버가 트랜잭션 관리를 위해 데이터베이스와 직접 연결할 수 있도록 connect 함수를 추가로 내보냅니다.
    connect: () => pool.connect(),

    // 리팩터링된 코드와의 호환성을 위해 pool 객체도 내보냅니다.
    pool: pool 
};
