CREATE TABLE IF NOT EXISTS login_failures (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    user_id      VARCHAR(64)  NOT NULL,
    attempted_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_time (user_id, attempted_at)
);

INSERT INTO login_failures (user_id, attempted_at) VALUES
    ('demo_user', NOW() - INTERVAL 5  MINUTE),
    ('demo_user', NOW() - INTERVAL 8  MINUTE),
    ('demo_user', NOW() - INTERVAL 12 MINUTE);

SELECT 'login_failures table created and seeded.' AS status;
