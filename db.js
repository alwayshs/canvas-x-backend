// db.js - 최종 Render 배포용 버전
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
    query: (text, params) => pool.query(text, params),
};
