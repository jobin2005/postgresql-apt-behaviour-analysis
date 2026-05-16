-- ============================================================
-- University Sample Schema + Data
-- Designed to be a realistic attack surface for APT simulation
-- ============================================================

-- ── Departments ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS departments (
    dept_id     SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    building    TEXT,
    budget      NUMERIC(12,2)
);

-- ── Faculty ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS faculty (
    faculty_id  SERIAL PRIMARY KEY,
    dept_id     INT REFERENCES departments(dept_id),
    full_name   TEXT NOT NULL,
    email       TEXT UNIQUE,
    salary      NUMERIC(10,2),         -- sensitive
    role        TEXT DEFAULT 'lecturer'
);

-- ── Students ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS students (
    student_id  SERIAL PRIMARY KEY,
    full_name   TEXT NOT NULL,
    email       TEXT UNIQUE,
    dept_id     INT REFERENCES departments(dept_id),
    enrolled_on DATE DEFAULT CURRENT_DATE
);

-- ── Student Records (HIGH VALUE — PII + academic standing) ───
CREATE TABLE IF NOT EXISTS student_records (
    record_id       SERIAL PRIMARY KEY,
    student_id      INT REFERENCES students(student_id),
    date_of_birth   DATE,
    national_id     TEXT,              -- sensitive PII
    address         TEXT,
    phone           TEXT,
    gpa             NUMERIC(3,2),
    academic_status TEXT DEFAULT 'active',   -- active / probation / suspended
    advisor_id      INT REFERENCES faculty(faculty_id)
);

-- ── Financial Records (HIGH VALUE — tuition, aid, debt) ───────
CREATE TABLE IF NOT EXISTS financial_records (
    fin_id          SERIAL PRIMARY KEY,
    student_id      INT REFERENCES students(student_id),
    tuition_balance NUMERIC(10,2),
    financial_aid   NUMERIC(10,2),
    scholarship     TEXT,
    payment_status  TEXT DEFAULT 'pending',
    last_updated    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Courses ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS courses (
    course_id   SERIAL PRIMARY KEY,
    dept_id     INT REFERENCES departments(dept_id),
    title       TEXT NOT NULL,
    credits     INT,
    instructor  INT REFERENCES faculty(faculty_id)
);

-- ── Enrollments ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS enrollments (
    enrollment_id SERIAL PRIMARY KEY,
    student_id    INT REFERENCES students(student_id),
    course_id     INT REFERENCES courses(course_id),
    grade         CHAR(1),
    semester      TEXT
);

-- ── Exam Results ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS exam_results (
    result_id   SERIAL PRIMARY KEY,
    student_id  INT REFERENCES students(student_id),
    course_id   INT REFERENCES courses(course_id),
    exam_type   TEXT,   -- midterm / final / quiz
    score       NUMERIC(5,2),
    max_score   NUMERIC(5,2),
    taken_on    DATE
);

-- ── System Users (admin table — prime APT target) ─────────────
CREATE TABLE IF NOT EXISTS system_users (
    user_id     SERIAL PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,
    role        TEXT DEFAULT 'staff',       -- staff / admin / superadmin
    last_login  TIMESTAMP,
    is_active   BOOLEAN DEFAULT TRUE
);


-- ============================================================
-- Sample Data
-- ============================================================

INSERT INTO departments (name, building, budget) VALUES
    ('Computer Science',  'Block A', 450000.00),
    ('Mathematics',       'Block B', 320000.00),
    ('Physics',           'Block C', 290000.00),
    ('Administration',    'Main',    800000.00);

INSERT INTO faculty (dept_id, full_name, email, salary, role) VALUES
    (1, 'Dr. Priya Nair',     'p.nair@university.edu',   95000.00, 'professor'),
    (1, 'Dr. Arjun Menon',    'a.menon@university.edu',  88000.00, 'professor'),
    (2, 'Dr. Leela Varma',    'l.varma@university.edu',  82000.00, 'professor'),
    (3, 'Dr. Suresh Kumar',   's.kumar@university.edu',  79000.00, 'lecturer'),
    (4, 'Ms. Divya Thomas',   'd.thomas@university.edu', 65000.00, 'staff');

INSERT INTO students (full_name, email, dept_id, enrolled_on) VALUES
    ('Alice Mathew',     'alice@university.edu',   1, '2022-08-01'),
    ('Bob Iyer',         'bob@university.edu',     1, '2022-08-01'),
    ('Carol Pillai',     'carol@university.edu',   2, '2021-08-01'),
    ('David Nambiar',    'david@university.edu',   1, '2023-08-01'),
    ('Eva Krishnan',     'eva@university.edu',     3, '2021-08-01'),
    ('Frank Joseph',     'frank@university.edu',   2, '2022-08-01'),
    ('Grace Sebastian',  'grace@university.edu',   1, '2023-08-01'),
    ('Henry Zacharia',   'henry@university.edu',   3, '2020-08-01'),
    ('Irene Paul',       'irene@university.edu',   2, '2023-08-01'),
    ('James George',     'james@university.edu',   1, '2020-08-01');

INSERT INTO student_records (student_id, date_of_birth, national_id, address, phone, gpa, academic_status, advisor_id) VALUES
    (1,  '2001-03-12', 'NID-100001', '12 Rose St, Kochi',       '9876543201', 3.85, 'active',    1),
    (2,  '2000-07-24', 'NID-100002', '45 MG Road, Thrissur',    '9876543202', 3.10, 'active',    1),
    (3,  '2002-01-05', 'NID-100003', '7 Lake View, Trivandrum', '9876543203', 2.75, 'probation', 3),
    (4,  '1999-11-30', 'NID-100004', '88 Park Ave, Calicut',    '9876543204', 3.60, 'active',    2),
    (5,  '2001-09-18', 'NID-100005', '3 Hill Rd, Kannur',       '9876543205', 3.90, 'active',    4),
    (6,  '2000-05-22', 'NID-100006', '21 Beach Rd, Kollam',     '9876543206', 2.90, 'active',    3),
    (7,  '2003-02-14', 'NID-100007', '56 Temple Rd, Palakkad',  '9876543207', 3.40, 'active',    1),
    (8,  '1998-12-01', 'NID-100008', '9 Fort Rd, Kasaragod',    '9876543208', 3.75, 'active',    4),
    (9,  '2002-08-30', 'NID-100009', '14 River Rd, Alappuzha',  '9876543209', 3.20, 'active',    3),
    (10, '1999-04-17', 'NID-100010', '33 Station Rd, Kottayam', '9876543210', 3.55, 'active',    2);

INSERT INTO financial_records (student_id, tuition_balance, financial_aid, scholarship, payment_status) VALUES
    (1,   4500.00, 12000.00, 'Merit Award',        'paid'),
    (2,   9000.00,  8000.00,  NULL,                'pending'),
    (3,  11000.00,  5000.00,  NULL,                'overdue'),
    (4,   2000.00, 15000.00, 'Sports Scholarship', 'paid'),
    (5,      0.00, 18000.00, 'Full Scholarship',   'paid'),
    (6,   7500.00,  6000.00,  NULL,                'pending'),
    (7,   3200.00, 10000.00, 'Need-Based Grant',   'paid'),
    (8,   1500.00, 14000.00, 'Research Fellowship','paid'),
    (9,   8800.00,  4000.00,  NULL,                'overdue'),
    (10,  5000.00,  9000.00, 'Alumni Scholarship', 'pending');

INSERT INTO courses (dept_id, title, credits, instructor) VALUES
    (1, 'Introduction to PostgreSQL',  4, 1),
    (1, 'Database Security',           3, 2),
    (1, 'Operating Systems',           4, 1),
    (2, 'Linear Algebra',              4, 3),
    (3, 'Quantum Mechanics',           3, 4),
    (1, 'Machine Learning',            4, 2),
    (2, 'Discrete Mathematics',        3, 3),
    (1, 'Network Systems',             3, 1);

INSERT INTO enrollments (student_id, course_id, grade, semester) VALUES
    (1, 1, 'A', '2024-S1'), (1, 2, 'B', '2024-S1'),
    (2, 2, 'B', '2024-S1'), (2, 3, 'A', '2024-S1'),
    (3, 4, 'C', '2024-S1'), (3, 7, 'B', '2024-S1'),
    (4, 6, 'A', '2024-S1'), (4, 8, 'B', '2024-S1'),
    (5, 1, 'A', '2024-S1'), (5, 5, 'A', '2024-S1'),
    (6, 3, 'B', '2024-S1'), (7, 6, 'A', '2024-S1'),
    (8, 8, 'A', '2024-S1'), (9, 4, 'C', '2024-S1'),
    (10,1, 'B', '2024-S1'), (10,2, 'A', '2024-S1');

INSERT INTO exam_results (student_id, course_id, exam_type, score, max_score, taken_on) VALUES
    (1, 1, 'midterm', 88, 100, '2024-09-20'),
    (1, 1, 'final',   92, 100, '2024-11-30'),
    (2, 2, 'midterm', 74, 100, '2024-09-21'),
    (2, 2, 'final',   79, 100, '2024-12-01'),
    (3, 4, 'midterm', 61, 100, '2024-09-22'),
    (4, 6, 'midterm', 85, 100, '2024-09-20'),
    (5, 1, 'midterm', 95, 100, '2024-09-20'),
    (5, 1, 'final',   97, 100, '2024-11-30'),
    (8, 8, 'midterm', 90, 100, '2024-09-23'),
    (10,1, 'final',   83, 100, '2024-11-30');

INSERT INTO system_users (username, role, last_login, is_active) VALUES
    ('admin',       'superadmin', NOW() - INTERVAL '2 hours',  TRUE),
    ('db_operator', 'admin',      NOW() - INTERVAL '1 day',    TRUE),
    ('faculty_srv',  'staff',     NOW() - INTERVAL '3 hours',  TRUE),
    ('backup_user',  'staff',     NOW() - INTERVAL '7 days',   FALSE);