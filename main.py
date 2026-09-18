import os
import uuid
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "novaai_earning.db"))
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_THIS_SECRET")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
CURRENCY = "NPR"
MIN_WITHDRAWAL = 100.0

app = FastAPI(title="NovaAI Earning Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        balance REAL NOT NULL DEFAULT 0,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS campaigns (
        id TEXT PRIMARY KEY,
        business TEXT NOT NULL,
        title TEXT NOT NULL,
        budget REAL NOT NULL,
        reward REAL NOT NULL,
        platform_fee REAL NOT NULL DEFAULT 0,
        reward_pool REAL NOT NULL DEFAULT 0,
        maximum_tasks INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL,
        user_id TEXT,
        reward REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'available',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(campaign_id) REFERENCES campaigns(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS withdrawals (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        amount REAL NOT NULL,
        method TEXT NOT NULL,
        account TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS wallet_transactions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        balance_after REAL NOT NULL,
        reference_id TEXT,
        note TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_tasks_user_status
        ON tasks(user_id, status);

    CREATE INDEX IF NOT EXISTS idx_withdrawals_user
        ON withdrawals(user_id);

    CREATE INDEX IF NOT EXISTS idx_transactions_user
        ON wallet_transactions(user_id);
    """)

    if ADMIN_EMAIL and ADMIN_PASSWORD:
        existing = cur.execute(
            "SELECT id FROM users WHERE lower(email)=lower(?)",
            (ADMIN_EMAIL.strip(),)
        ).fetchone()

        if not existing:
            cur.execute(
                """
                INSERT INTO users
                (id, name, email, password_hash, balance, is_admin)
                VALUES (?, ?, ?, ?, 0, 1)
                """,
                (
                    str(uuid.uuid4()),
                    "NovaAI Admin",
                    ADMIN_EMAIL.strip().lower(),
                    generate_password_hash(ADMIN_PASSWORD),
                )
            )
        else:
            cur.execute(
                """
                UPDATE users
                SET is_admin=1
                WHERE lower(email)=lower(?)
                """,
                (ADMIN_EMAIL.strip().lower(),)
            )

    conn.commit()
    cur.close()
    conn.close()


@app.on_event("startup")
def startup():
    init_db()


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


def make_token(user):
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "is_admin": bool(user["is_admin"]),
        "exp": datetime.now(timezone.utc) + timedelta(days=30),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_token(authorization):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization required")

    parts = authorization.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization")

    return parts[1]


def current_user(authorization: str = Header(default=None)):
    token = get_token(authorization)

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )
        user_id = str(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    conn = get_db()
    row = conn.execute(
        """
        SELECT id, name, email, balance, is_admin, created_at
        FROM users
        WHERE id=?
        """,
        (user_id,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="User not found")

    return dict(row)


def admin_user(user=Depends(current_user)):
    if not bool(user["is_admin"]):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@app.get("/")
def root():
    return {
        "app": "NovaAI Earning Backend",
        "status": "running",
        "currency": CURRENCY,
        "database": "SQLite"
    }


@app.get("/status")
def status():
    return {
        "app": "NovaAI Earning Backend",
        "status": "running",
        "currency": CURRENCY,
        "min_withdrawal": MIN_WITHDRAWAL,
        "database": "SQLite"
    }


@app.post("/auth/register")
def register(data: RegisterRequest):
    name = data.name.strip()
    email = str(data.email).strip().lower()
    password = data.password

    if not name:
        raise HTTPException(status_code=400, detail="Name is required")

    if len(password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters"
        )

    conn = get_db()

    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE lower(email)=lower(?)",
            (email,)
        ).fetchone()

        if existing:
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )

        user_id = str(uuid.uuid4())

        conn.execute(
            """
            INSERT INTO users
            (id, name, email, password_hash, balance, is_admin)
            VALUES (?, ?, ?, ?, 0, 0)
            """,
            (
                user_id,
                name,
                email,
                generate_password_hash(password)
            )
        )

        conn.commit()

        user = conn.execute(
            """
            SELECT id, name, email, balance, is_admin, created_at
            FROM users
            WHERE id=?
            """,
            (user_id,)
        ).fetchone()

        token = make_token(dict(user))

        return {
            "success": True,
            "token": token,
            "user": dict(user)
        }

    finally:
        conn.close()


@app.post("/auth/login")
def login(data: LoginRequest):
    email = str(data.email).strip().lower()

    conn = get_db()

    try:
        user = conn.execute(
            """
            SELECT id, name, email, password_hash,
                   balance, is_admin, created_at
            FROM users
            WHERE lower(email)=lower(?)
            """,
            (email,)
        ).fetchone()

        if not user or not check_password_hash(
            user["password_hash"],
            data.password
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )

        token = make_token(dict(user))

        return {
            "success": True,
            "token": token,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "balance": float(user["balance"]),
                "is_admin": bool(user["is_admin"]),
                "created_at": user["created_at"]
            }
        }

    finally:
        conn.close()


@app.get("/me")
def me(user=Depends(current_user)):
    return {
        "success": True,
        "user": user
    }


@app.get("/wallet")
def wallet(user=Depends(current_user)):
    conn = get_db()

    transactions = conn.execute(
        """
        SELECT id, type, amount, balance_after,
               reference_id, note, created_at
        FROM wallet_transactions
        WHERE user_id=?
        ORDER BY created_at DESC
        """,
        (str(user["id"]),)
    ).fetchall()

    conn.close()

    return {
        "success": True,
        "balance": float(user["balance"]),
        "currency": CURRENCY,
        "transactions": [dict(x) for x in transactions]
    }


@app.get("/campaigns")
def campaigns(user=Depends(current_user)):
    conn = get_db()

    rows = conn.execute(
        """
        SELECT id, business, title, budget, reward,
               platform_fee, reward_pool, maximum_tasks,
               status, created_at
        FROM campaigns
        WHERE status='active'
        ORDER BY created_at DESC
        """
    ).fetchall()

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
    if data.budget <= 0:
        raise HTTPException(
            status_code=400,
            detail="Budget must be greater than zero"
        )

    if data.reward <= 0:
        raise HTTPException(
            status_code=400,
            detail="Reward must be greater than zero"
        )

    if data.platform_fee < 0 or data.platform_fee >= data.budget:
        raise HTTPException(
            status_code=400,
            detail="Invalid platform fee"
        )

    reward_pool = data.budget - data.platform_fee
    maximum_tasks = int(reward_pool // data.reward)

    if maximum_tasks < 1:
        raise HTTPException(
            status_code=400,
            detail="Budget is too small for the selected reward"
        )

    campaign_id = str(uuid.uuid4())

    conn = get_db()

    try:
        conn.execute(
            """
            INSERT INTO campaigns
            (id, business, title, budget, reward,
             platform_fee, reward_pool, maximum_tasks, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')
            """,
            (
                campaign_id,
                data.business.strip(),
                data.title.strip(),
                data.budget,
                data.reward,
                data.platform_fee,
                reward_pool,
                maximum_tasks
            )
        )

        for _ in range(maximum_tasks):
            conn.execute(
                """
                INSERT INTO tasks
                (id, campaign_id, reward, status)
                VALUES (?, ?, ?, 'available')
                """,
                (
                    str(uuid.uuid4()),
                    campaign_id,
                    data.reward
                )
            )

        conn.commit()

        campaign = conn.execute(
            """
            SELECT *
            FROM campaigns
            WHERE id=?
            """,
            (campaign_id,)
        ).fetchone()

        return {
            "success": True,
            "campaign": dict(campaign)
        }

    finally:
        conn.close()


@app.post("/tasks/complete")
def complete_task(
    data: CompleteTaskRequest,
    user=Depends(current_user)
):
    conn = get_db()

    try:
        conn.execute("BEGIN IMMEDIATE")

        task = conn.execute(
            """
            SELECT id, campaign_id, user_id, reward, status
            FROM tasks
            WHERE id=?
            """,
            (data.task_id,)
        ).fetchone()

        if not task:
            raise HTTPException(
                status_code=404,
                detail="Task not found"
            )

        if task["user_id"] is not None and str(task["user_id"]) != str(user["id"]):
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

        current = conn.execute(
            "SELECT balance FROM users WHERE id=?",
            (str(user["id"]),)
        ).fetchone()

        if not current:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        new_balance = float(current["balance"]) + reward

        conn.execute(
            """
            UPDATE users
            SET balance=?
            WHERE id=?
            """,
            (new_balance, str(user["id"]))
        )

        conn.execute(
            """
            UPDATE tasks
            SET status='completed', user_id=?
            WHERE id=?
            """,
            (str(user["id"]), data.task_id)
        )

        conn.execute(
            """
            INSERT INTO wallet_transactions
            (id, user_id, type, amount, balance_after,
             reference_id, note)
            VALUES (?, ?, 'earning', ?, ?, ?, ?)
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
            "balance": new_balance
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

    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            "SELECT balance FROM users WHERE id=?",
            (data.user_id,)
        ).fetchone()

        if not row:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        balance = float(row["balance"]) + data.amount

        conn.execute(
            """
            UPDATE users
            SET balance=?
            WHERE id=?
            """,
            (balance, data.user_id)
        )

        conn.execute(
            """
            INSERT INTO wallet_transactions
            (id, user_id, type, amount, balance_after,
             reference_id, note)
            VALUES (?, ?, 'admin_credit', ?, ?, ?, ?)
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
            "balance": balance
        }

    except HTTPException:
        conn.rollback()
        raise

    finally:
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

    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            "SELECT balance FROM users WHERE id=?",
            (str(user["id"]),)
        ).fetchone()

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

        conn.execute(
            """
            UPDATE users
            SET balance=?
            WHERE id=?
            """,
            (new_balance, str(user["id"]))
        )

        conn.execute(
            """
            INSERT INTO withdrawals
            (id, user_id, amount, method, account, status)
            VALUES (?, ?, ?, ?, ?, 'pending')
            """,
            (
                withdrawal_id,
                str(user["id"]),
                data.amount,
                data.method.strip(),
                data.account.strip()
            )
        )

        conn.execute(
            """
            INSERT INTO wallet_transactions
            (id, user_id, type, amount, balance_after,
             reference_id, note)
            VALUES (?, ?, 'withdrawal', ?, ?, ?, ?)
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
        conn.close()


@app.get("/admin/users")
def admin_users(admin=Depends(admin_user)):
    conn = get_db()

    rows = conn.execute(
        """
        SELECT id, name, email, balance,
               is_admin, created_at
        FROM users
        ORDER BY created_at DESC
        """
    ).fetchall()

    conn.close()

    return {
        "success": True,
        "users": [dict(x) for x in rows]
    }


@app.get("/admin/withdrawals")
def admin_withdrawals(admin=Depends(admin_user)):
    conn = get_db()

    rows = conn.execute(
        """
        SELECT w.id, w.user_id, u.name, u.email,
               w.amount, w.method, w.account,
               w.status, w.created_at
        FROM withdrawals w
        JOIN users u ON u.id=w.user_id
        ORDER BY w.created_at DESC
        """
    ).fetchall()

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

    try:
        conn.execute("BEGIN IMMEDIATE")

        withdrawal = conn.execute(
            """
            SELECT id, user_id, amount, status
            FROM withdrawals
            WHERE id=?
            """,
            (data.withdrawal_id,)
        ).fetchone()

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
            conn.execute(
                """
                UPDATE withdrawals
                SET status='approved'
                WHERE id=?
                """,
                (data.withdrawal_id,)
            )

        else:
            current = conn.execute(
                """
                SELECT balance
                FROM users
                WHERE id=?
                """,
                (str(withdrawal["user_id"]),)
            ).fetchone()

            if not current:
                raise HTTPException(
                    status_code=404,
                    detail="User not found"
                )

            new_balance = (
                float(current["balance"]) +
                float(withdrawal["amount"])
            )

            conn.execute(
                """
                UPDATE users
                SET balance=?
                WHERE id=?
                """,
                (
                    new_balance,
                    str(withdrawal["user_id"])
                )
            )

            conn.execute(
                """
                UPDATE withdrawals
                SET status='rejected'
                WHERE id=?
                """,
                (data.withdrawal_id,)
            )

            conn.execute(
                """
                INSERT INTO wallet_transactions
                (id, user_id, type, amount, balance_after,
                 reference_id, note)
                VALUES (?, ?, 'withdrawal_refund', ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    str(withdrawal["user_id"]),
                    float(withdrawal["amount"]),
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
        conn.close()


@app.get("/admin/stats")
def admin_stats(admin=Depends(admin_user)):
    conn = get_db()

    users = conn.execute(
        "SELECT COUNT(*) AS count FROM users"
    ).fetchone()["count"]

    balance = conn.execute(
        "SELECT COALESCE(SUM(balance), 0) AS total FROM users"
    ).fetchone()["total"]

    pending_withdrawals = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM withdrawals
        WHERE status='pending'
        """
    ).fetchone()["count"]

    active_campaigns = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM campaigns
        WHERE status='active'
        """
    ).fetchone()["count"]

    conn.close()

    return {
        "success": True,
        "users": users,
        "total_balance": float(balance or 0),
        "pending_withdrawals": pending_withdrawals,
        "active_campaigns": active_campaigns,
        "currency": CURRENCY
    }
