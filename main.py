import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from werkzeug.security import generate_password_hash, check_password_hash


DATABASE_URL = os.getenv("DATABASE_URL", "")
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_THIS_SECRET")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

CURRENCY = "NPR"
MIN_WITHDRAWAL = 100.0


app = FastAPI(
    title="NovaAI Earning Backend",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")

    return psycopg2.connect(
        DATABASE_URL,
        sslmode="require"
    )


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance NUMERIC(12,2) NOT NULL DEFAULT 0,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id UUID PRIMARY KEY,
            business TEXT NOT NULL,
            title TEXT NOT NULL,
            budget NUMERIC(12,2) NOT NULL,
            reward NUMERIC(12,2) NOT NULL,
            platform_fee NUMERIC(12,2) NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id UUID PRIMARY KEY,
            campaign_id UUID NOT NULL REFERENCES campaigns(id),
            user_id UUID NOT NULL REFERENCES users(id),
            reward NUMERIC(12,2) NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS withdrawals (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id),
            amount NUMERIC(12,2) NOT NULL,
            method TEXT NOT NULL,
            account TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS wallet_transactions (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id),
            type TEXT NOT NULL,
            amount NUMERIC(12,2) NOT NULL,
            balance_after NUMERIC(12,2) NOT NULL,
            reference_id TEXT,
            note TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    """)

    conn.commit()

    # Create admin account automatically if environment variables exist.
    if ADMIN_EMAIL and ADMIN_PASSWORD:
        cur.execute(
            "SELECT id FROM users WHERE email = %s",
            (ADMIN_EMAIL.lower(),)
        )

        existing = cur.fetchone()

        if not existing:
            admin_id = str(uuid.uuid4())

            cur.execute(
                """
                INSERT INTO users
                (id, name, email, password_hash, role)
                VALUES (%s, %s, %s, %s, 'admin')
                """,
                (
                    admin_id,
                    "NovaAI Admin",
                    ADMIN_EMAIL.lower(),
                    generate_password_hash(ADMIN_PASSWORD)
                )
            )

            conn.commit()

    cur.close()
    conn.close()


def create_token(user):
    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(days=30)
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )


def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    token = authorization.replace("Bearer ", "", 1).strip()

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        """
        SELECT id, name, email, balance, role, created_at
        FROM users
        WHERE id = %s
        """,
        (payload["sub"],)
    )

    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user


def admin_user(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )

    return user


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CampaignRequest(BaseModel):
    business: str
    title: str
    budget: float
    reward: float
    platform_fee: float = 0


class CompleteTaskRequest(BaseModel):
    task_id: str


class CreditRequest(BaseModel):
    user_id: str
    amount: float
    note: str = "Admin credit"


class WithdrawRequest(BaseModel):
    amount: float
    method: str
    account: str


class WithdrawalActionRequest(BaseModel):
    withdrawal_id: str
    action: str


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def root():
    return {
        "app": "NovaAI Earning Backend",
        "status": "online",
        "currency": CURRENCY
    }


@app.get("/status")
def status():
    return {
        "app": "NovaAI Earning Backend",
        "status": "running",
        "currency": CURRENCY,
        "min_withdrawal": MIN_WITHDRAWAL
    }


@app.post("/auth/register")
def register(data: RegisterRequest):

    if len(data.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters"
        )

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    email = data.email.lower().strip()

    cur.execute(
        "SELECT id FROM users WHERE email = %s",
        (email,)
    )

    if cur.fetchone():
        cur.close()
        conn.close()

        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    user_id = str(uuid.uuid4())

    cur.execute(
        """
        INSERT INTO users
        (id, name, email, password_hash)
        VALUES (%s, %s, %s, %s)
        RETURNING id, name, email, balance, role, created_at
        """,
        (
            user_id,
            data.name.strip(),
            email,
            generate_password_hash(data.password)
        )
    )

    user = cur.fetchone()

    conn.commit()

    token = create_token(user)

    cur.close()
    conn.close()

    return {
        "success": True,
        "token": token,
        "user": dict(user)
    }


@app.post("/auth/login")
def login(data: LoginRequest):

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        """
        SELECT id, name, email, password_hash,
               balance, role, created_at
        FROM users
        WHERE email = %s
        """,
        (data.email.lower().strip(),)
    )

    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user or not check_password_hash(
        user["password_hash"],
        data.password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    token = create_token(user)

    user.pop("password_hash", None)

    return {
        "success": True,
        "token": token,
        "user": dict(user)
    }


@app.get("/me")
def me(user=Depends(current_user)):
    return {
        "success": True,
        "user": dict(user)
    }


@app.get("/wallet")
def wallet(user=Depends(current_user)):

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        """
        SELECT id, type, amount, balance_after,
               reference_id, note, created_at
        FROM wallet_transactions
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 100
        """,
        (str(user["id"]),)
    )

    transactions = cur.fetchall()

    cur.close()
    conn.close()

    return {
        "success": True,
        "balance": float(user["balance"]),
        "currency": CURRENCY,
        "transactions": [
            dict(x) for x in transactions
        ]
    }


@app.get("/campaigns")
def campaigns(user=Depends(current_user)):

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        """
        SELECT id, business, title, budget,
               reward, platform_fee, status, created_at
        FROM campaigns
        WHERE status = 'active'
        ORDER BY created_at DESC
        """
    )

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return {
        "success": True,
        "campaigns": [dict(x) for x in rows]
    }


@app.post("/admin/campaigns")
def create_campaign(
    data: CampaignRequest,
    admin=Depends(admin_user)
):

    if data.budget <= 0 or data.reward <= 0:
        raise HTTPException(
            status_code=400,
            detail="Budget and reward must be greater than zero"
        )

    campaign_id = str(uuid.uuid4())

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        """
        INSERT INTO campaigns
        (id, business, title, budget, reward, platform_fee)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING *
        """,
        (
            campaign_id,
            data.business,
            data.title,
            data.budget,
            data.reward,
            data.platform_fee
        )
    )

    campaign = cur.fetchone()

    conn.commit()

    cur.close()
    conn.close()

    return {
        "success": True,
        "campaign": dict(campaign)
    }


@app.post("/tasks/complete")
def complete_task(
    data: CompleteTaskRequest,
    user=Depends(current_user)
):

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        cur.execute(
            """
            SELECT id, user_id, reward, status
            FROM tasks
            WHERE id = %s
            FOR UPDATE
            """,
            (data.task_id,)
        )

        task = cur.fetchone()

        if not task:
            raise HTTPException(
                status_code=404,
                detail="Task not found"
            )

        if str(task["user_id"]) != str(user["id"]):
            raise HTTPException(
                status_code=403,
                detail="This task does not belong to you"
            )

        if task["status"] == "completed":
            raise HTTPException(
                status_code=400,
                detail="Task already completed"
            )

        reward = float(task["reward"])

        cur.execute(
            """
            UPDATE users
            SET balance = balance + %s
            WHERE id = %s
            RETURNING balance
            """,
            (reward, str(user["id"]))
        )

        new_balance = cur.fetchone()["balance"]

        cur.execute(
            """
            UPDATE tasks
            SET status = 'completed'
            WHERE id = %s
            """,
            (data.task_id,)
        )

        cur.execute(
            """
            INSERT INTO wallet_transactions
            (id, user_id, type, amount, balance_after,
             reference_id, note)
            VALUES (%s, %s, 'earning', %s, %s, %s, %s)
            """,
            (
                str(uuid.uuid4()),
                str(user["id"]),
                reward,
                new_balance,
                data.task_id,
                "Task reward"
            )
        )

        conn.commit()

        return {
            "success": True,
            "reward": reward,
            "balance": float(new_balance)
        }

    except HTTPException:
        conn.rollback()
        raise

    except Exception:
        conn.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to complete task"
        )

    finally:
        cur.close()
        conn.close()


@app.post("/admin/credit")
def admin_credit(
    data: CreditRequest,
    admin=Depends(admin_user)
):

    if data.amount <= 0:
        raise HTTPException(
            status_code=400,
            detail="Amount must be greater than zero"
        )

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        cur.execute(
            """
            UPDATE users
            SET balance = balance + %s
            WHERE id = %s
            RETURNING balance
            """,
            (
                data.amount,
                data.user_id
            )
        )

        result = cur.fetchone()

        if not result:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        balance = result["balance"]

        cur.execute(
            """
            INSERT INTO wallet_transactions
            (id, user_id, type, amount, balance_after,
             reference_id, note)
            VALUES (%s, %s, 'admin_credit', %s, %s, %s, %s)
            """,
            (
                str(uuid.uuid4()),
                data.user_id,
                data.amount,
                balance,
                str(admin["id"]),
                data.note
            )
        )

        conn.commit()

        return {
            "success": True,
            "balance": float(balance)
        }

    except HTTPException:
        conn.rollback()
        raise

    finally:
        cur.close()
        conn.close()


@app.post("/withdraw")
def withdraw(
    data: WithdrawRequest,
    user=Depends(current_user)
):

    if data.amount < MIN_WITHDRAWAL:
        raise HTTPException(
            status_code=400,
            detail=f"Minimum withdrawal is {MIN_WITHDRAWAL} {CURRENCY}"
        )

    if not data.method.strip() or not data.account.strip():
        raise HTTPException(
            status_code=400,
            detail="Withdrawal method and account are required"
        )

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:

        cur.execute(
            """
            SELECT balance
            FROM users
            WHERE id = %s
            FOR UPDATE
            """,
            (str(user["id"]),)
        )

        row = cur.fetchone()

        if not row:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        balance = float(row["balance"])

        if balance < data.amount:
            raise HTTPException(
                status_code=400,
                detail="Insufficient balance"
            )

        withdrawal_id = str(uuid.uuid4())
        new_balance = balance - data.amount

        cur.execute(
            """
            UPDATE users
            SET balance = %s
            WHERE id = %s
            """,
            (
                new_balance,
                str(user["id"])
            )
        )

        cur.execute(
            """
            INSERT INTO withdrawals
            (id, user_id, amount, method, account)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                withdrawal_id,
                str(user["id"]),
                data.amount,
                data.method.strip(),
                data.account.strip()
            )
        )

        cur.execute(
            """
            INSERT INTO wallet_transactions
            (id, user_id, type, amount, balance_after,
             reference_id, note)
            VALUES (%s, %s, 'withdrawal', %s, %s, %s, %s)
            """,
            (
                str(uuid.uuid4()),
                str(user["id"]),
                -data.amount,
                new_balance,
                withdrawal_id,
                "Withdrawal request"
            )
        )

        conn.commit()

        return {
            "success": True,
            "withdrawal_id": withdrawal_id,
            "amount": data.amount,
            "balance": new_balance,
            "status": "pending"
        }

    except HTTPException:
        conn.rollback()
        raise

    finally:
        cur.close()
        conn.close()


@app.get("/admin/users")
def admin_users(admin=Depends(admin_user)):

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        """
        SELECT id, name, email, balance,
               role, created_at
        FROM users
        ORDER BY created_at DESC
        """
    )

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return {
        "success": True,
        "users": [dict(x) for x in rows]
    }


@app.get("/admin/withdrawals")
def admin_withdrawals(admin=Depends(admin_user)):

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute(
        """
        SELECT w.id, w.user_id, u.name, u.email,
               w.amount, w.method, w.account,
               w.status, w.created_at
        FROM withdrawals w
        JOIN users u ON u.id = w.user_id
        ORDER BY w.created_at DESC
        """
    )

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return {
        "success": True,
        "withdrawals": [dict(x) for x in rows]
    }


@app.post("/admin/withdrawal/action")
def withdrawal_action(
    data: WithdrawalActionRequest,
    admin=Depends(admin_user)
):

    if data.action not in ["approve", "reject"]:
        raise HTTPException(
            status_code=400,
            detail="Action must be approve or reject"
        )

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:

        cur.execute(
            """
            SELECT id, user_id, amount, status
            FROM withdrawals
            WHERE id = %s
            FOR UPDATE
            """,
            (data.withdrawal_id,)
        )

        withdrawal = cur.fetchone()

        if not withdrawal:
            raise HTTPException(
                status_code=404,
                detail="Withdrawal not found"
            )

        if withdrawal["status"] != "pending":
            raise HTTPException(
                status_code=400,
                detail="Withdrawal already processed"
            )

        if data.action == "approve":

            cur.execute(
                """
                UPDATE withdrawals
                SET status = 'approved'
                WHERE id = %s
                """,
                (data.withdrawal_id,)
            )

        else:

            cur.execute(
                """
                UPDATE users
                SET balance = balance + %s
                WHERE id = %s
                RETURNING balance
                """,
                (
                    withdrawal["amount"],
                    withdrawal["user_id"]
                )
            )

            new_balance = cur.fetchone()["balance"]

            cur.execute(
                """
                UPDATE withdrawals
                SET status = 'rejected'
                WHERE id = %s
                """,
                (data.withdrawal_id,)
            )

            cur.execute(
                """
                INSERT INTO wallet_transactions
                (id, user_id, type, amount, balance_after,
                 reference_id, note)
                VALUES (%s, %s, 'withdrawal_refund', %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    withdrawal["user_id"],
                    withdrawal["amount"],
                    new_balance,
                    data.withdrawal_id,
                    "Rejected withdrawal refund"
                )
            )

        conn.commit()

        return {
            "success": True,
            "status": (
                "approved"
                if data.action == "approve"
                else "rejected"
            )
        }

    except HTTPException:
        conn.rollback()
        raise

    finally:
        cur.close()
        conn.close()


@app.get("/admin/stats")
def admin_stats(admin=Depends(admin_user)):

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT COUNT(*) AS count FROM users")
    users = cur.fetchone()["count"]

    cur.execute("SELECT COALESCE(SUM(balance), 0) AS total FROM users")
    balance = cur.fetchone()["total"]

    cur.execute(
        "SELECT COUNT(*) AS count FROM withdrawals WHERE status='pending'"
    )
    pending_withdrawals = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) AS count FROM campaigns WHERE status='active'")
    active_campaigns = cur.fetchone()["count"]

    cur.close()
    conn.close()

    return {
        "success": True,
        "users": users,
        "total_balance": float(balance),
        "pending_withdrawals": pending_withdrawals,
        "active_campaigns": active_campaigns,
        "currency": CURRENCY
    }
