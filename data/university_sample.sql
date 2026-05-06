-- University Sample Schema

-- 1. Create Tables
CREATE TABLE students (
    student_id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE
);

CREATE TABLE courses (
    course_id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    credits INT
);

CREATE TABLE enrollments (
    enrollment_id SERIAL PRIMARY KEY,
    student_id INT REFERENCES students(student_id),
    course_id INT REFERENCES courses(course_id),
    grade CHAR(1)
);

-- 2. Sample Data
INSERT INTO students (name, email) VALUES ('Alice Smith', 'alice@university.edu');
INSERT INTO students (name, email) VALUES ('Bob Jones', 'bob@university.edu');

INSERT INTO courses (title, credits) VALUES ('Introduction to PostgreSQL', 4);
INSERT INTO courses (title, credits) VALUES ('Database Security', 3);

INSERT INTO enrollments (student_id, course_id, grade) VALUES (1, 1, 'A');
INSERT INTO enrollments (student_id, course_id, grade) VALUES (2, 2, 'B');
