// db.js
// Node.js에서 PostgreSQL 데이터베이스와 통신하기 위한 설정 파일입니다.
// 'pg' 라이브러리가 필요합니다: npm install pg

const { Pool } = require('pg');

// 데이터베이스 연결 정보를 담는 'Pool'을 생성합니다.
// 실제 운영 시에는 이 정보들을 환경 변수로 안전하게 관리해야 합니다.
const pool = new Pool({
    user: 'postgres', // আপনার PostgreSQL 사용자 이름
    host: 'localhost',
    database: 'canvas_x_db', // 이전에 생성한 데이터베이스 이름
    password: 'jun142857%', // 데이터베이스 접속 비밀번호
    port: 5432,
});

// 다른 파일에서 이 연결 풀을 사용할 수 있도록 내보냅니다.
module.exports = {
    query: (text, params) => pool.query(text, params),
};
