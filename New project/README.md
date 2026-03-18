# CampusChain Vault: Secure Academic Report Storage with Blockchain

A full-stack project for secure cloud storage and management of student academic reports.

## Features
- Role-based login for `admin`, `faculty`, and `student`
- Admin dashboard to create users and monitor activity/status
- Encrypted file upload and storage using Fernet
- Blockchain-style immutable audit chain for upload/delete/recover operations
- Report verification against stored file hash + chain validity
- Recovery bin to restore deleted reports
- Professional responsive UI with icons and smooth animations

## Tech Stack
- Backend: Python, Flask, SQLite, Cryptography
- Frontend: HTML templates + CSS
- Cloud storage: AWS S3 (via boto3)

## Default Login Accounts
- Admin: `admin@campuschain.local` / `Admin@123`
- Faculty: `faculty@campuschain.local` / `Faculty@123`
- Student: `student@campuschain.local` / `Student@123`

## Run Locally (S3 Mode)
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Set env vars (cmd):
```cmd
set STORAGE_BACKEND=s3
set S3_BUCKET=your-bucket-name
set S3_REGION=ap-south-1
set S3_PREFIX=student-reports
python app.py
```

Or run:
```cmd
run_s3.cmd
```
(First edit `run_s3.cmd` and set your bucket name.)

Open: `http://localhost:5000`

## AWS S3 Recommendations
- Enable **Block Public Access**
- Enable **Versioning**
- Enable server-side encryption (SSE-S3 or SSE-KMS)
- Use least-privilege IAM credentials

### Suggested S3 Key Pattern
- `student-reports/<encrypted_file_name>.enc`

## Key Files
- `app.py` - Flask backend and routes
- `templates/` - Role dashboards and login pages
- `static/styles.css` - UI styles
- `campuschain.db` - SQLite database
- `run_s3.cmd` - quick start script for S3 mode

## Student Restrictions
- Allowed upload formats: PDF, DOC, DOCX
- Max file size per upload: 5 MB
- Max uploads per student per day: 3
