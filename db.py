"""
db.py — طبقة قاعدة بيانات موحدة تدعم SQLite (تطوير) وPostgreSQL (إنتاج)
نظام عزل متعدد المستأجرين: كل جدول يحمل tenant_id، وداخل المستأجر store_id.
إضافات الإصدار PWA: client_uid (منع تكرار الفواتير)، updated_at (مزامنة دلتا)،
subscription_expires_at (إدارة الاشتراك).
"""
import os
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "pos.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

IS_POSTGRES = DATABASE_URL.startswith("postgres")

SCHEMA_SQLITE = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, plan TEXT DEFAULT 'monthly', status TEXT DEFAULT 'active',
    subscription_expires_at TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS stores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, location TEXT DEFAULT '', phone TEXT DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    default_store_id INTEGER REFERENCES stores(id),
    name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'cashier', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    store_id INTEGER NOT NULL REFERENCES stores(id) ON DELETE CASCADE, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    store_id INTEGER NOT NULL REFERENCES stores(id) ON DELETE CASCADE,
    category_id INTEGER REFERENCES categories(id),
    name TEXT NOT NULL, sku TEXT, barcode TEXT,
    price REAL NOT NULL DEFAULT 0, cost REAL NOT NULL DEFAULT 0,
    stock REAL NOT NULL DEFAULT 0, min_stock REAL NOT NULL DEFAULT 5,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    store_id INTEGER NOT NULL REFERENCES stores(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    client_uid TEXT,
    subtotal REAL NOT NULL, tax REAL NOT NULL DEFAULT 0, total REAL NOT NULL,
    payment_method TEXT DEFAULT 'cash', customer_name TEXT DEFAULT '', note TEXT DEFAULT '',
    created_at TEXT NOT NULL, client_created_at TEXT,
    UNIQUE(tenant_id, client_uid));
CREATE TABLE IF NOT EXISTS sale_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sale_id INTEGER NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
    product_name TEXT NOT NULL, qty REAL NOT NULL, unit_price REAL NOT NULL, line_total REAL NOT NULL);
CREATE TABLE IF NOT EXISTS stock_movements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    store_id INTEGER NOT NULL REFERENCES stores(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    type TEXT NOT NULL, qty_change REAL NOT NULL, note TEXT DEFAULT '',
    user_id INTEGER REFERENCES users(id), created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_products_tenant_store ON products(tenant_id, store_id);
CREATE INDEX IF NOT EXISTS idx_sales_tenant_store ON sales(tenant_id, store_id, created_at);
CREATE INDEX IF NOT EXISTS idx_sale_items_sale ON sale_items(sale_id);
"""

# مخطط مطابق لـ PostgreSQL للإنتاج (يُولَّد ملف schema_postgres.sql منفصل)
SCHEMA_POSTGRES = """
CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, plan TEXT DEFAULT 'monthly',
    status TEXT DEFAULT 'active', subscription_expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS stores (
    id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, location TEXT DEFAULT '', phone TEXT DEFAULT '', created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    default_store_id INTEGER REFERENCES stores(id), name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, role TEXT DEFAULT 'cashier', created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    store_id INTEGER NOT NULL REFERENCES stores(id) ON DELETE CASCADE, category_id INTEGER,
    name TEXT NOT NULL, sku TEXT, barcode TEXT, price REAL NOT NULL DEFAULT 0, cost REAL NOT NULL DEFAULT 0,
    stock REAL NOT NULL DEFAULT 0, min_stock REAL NOT NULL DEFAULT 5,
    created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS sales (
    id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    store_id INTEGER NOT NULL REFERENCES stores(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id),
    client_uid TEXT, subtotal REAL NOT NULL, tax REAL NOT NULL DEFAULT 0, total REAL NOT NULL,
    payment_method TEXT DEFAULT 'cash', customer_name TEXT DEFAULT '', note TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL, client_created_at TIMESTAMPTZ,
    UNIQUE(tenant_id, client_uid));
CREATE TABLE IF NOT EXISTS sale_items (
    id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sale_id INTEGER NOT NULL REFERENCES sales(id) ON DELETE CASCADE, product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
    product_name TEXT NOT NULL, qty REAL NOT NULL, unit_price REAL NOT NULL, line_total REAL NOT NULL);
CREATE TABLE IF NOT EXISTS stock_movements (
    id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    store_id INTEGER NOT NULL REFERENCES stores(id) ON DELETE CASCADE, product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    type TEXT NOT NULL, qty_change REAL NOT NULL, note TEXT DEFAULT '', user_id INTEGER REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS idx_products_tenant_store ON products(tenant_id, store_id);
CREATE INDEX IF NOT EXISTS idx_sales_tenant_store ON sales(tenant_id, store_id, created_at);
"""


class Database:
    """غلاف موحد: نفس الواجهة لـ SQLite وPostgreSQL."""
    def __init__(self):
        if IS_POSTGRES:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            self.conn = psycopg2.connect(DATABASE_URL)
            self.conn.autocommit = False
            self._cursor_factory = RealDictCursor
        else:
            os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
            self.conn = sqlite3.connect(DB_PATH)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")

    def _q(self, sql):
        return sql.replace("?", "%s") if IS_POSTGRES else sql

    def execute(self, sql, params=()):
        cur = self.conn.cursor(cursor_factory=self._cursor_factory) if IS_POSTGRES else self.conn.cursor()
        cur.execute(self._q(sql), params)
        return cur

    def fetchone(self, sql, params=()):
        cur = self.execute(sql, params)
        row = cur.fetchone()
        cur.close()
        return dict(row) if (IS_POSTGRES and row) else row

    def fetchall(self, sql, params=()):
        cur = self.execute(sql, params)
        rows = cur.fetchall()
        cur.close()
        return [dict(r) for r in rows] if IS_POSTGRES else rows

    def insert(self, sql, params=()):
        """ينفذ INSERT ويعرف المعرف المُولَّد (يعمل في كلا المحركين)."""
        cur = self.execute(sql, params)
        if IS_POSTGRES:
            # الاستدعاء يتوقع أن ينتهي SQL بـ RETURNING id
            row = cur.fetchone()
            new_id = row["id"] if row else None
        else:
            new_id = cur.lastrowid
        cur.close()
        return new_id

    def commit(self): self.conn.commit()
    def rollback(self): self.conn.rollback()
    def close(self): self.conn.close()


def get_db():
    return Database()


def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def init_db():
    db = get_db()
    schema = SCHEMA_POSTGRES if IS_POSTGRES else SCHEMA_SQLITE
    for stmt in schema.split(";"):
        if stmt.strip():
            db.execute(stmt)
    db.commit()
    # ترحيل القواعد القديمة: إضافة الأعمدة الجديدة إن لم تكن موجودة
    if not IS_POSTGRES:
        cols = [r[1] for r in db.execute("PRAGMA table_info(sales)").fetchall()]
        if "client_uid" not in cols:
            db.execute("ALTER TABLE sales ADD COLUMN client_uid TEXT")
        if "client_created_at" not in cols:
            db.execute("ALTER TABLE sales ADD COLUMN client_created_at TEXT")
        pcols = [r[1] for r in db.execute("PRAGMA table_info(products)").fetchall()]
        if "updated_at" not in pcols:
            db.execute("ALTER TABLE products ADD COLUMN updated_at TEXT")
            db.execute("UPDATE products SET updated_at = created_at")
        tcols = [r[1] for r in db.execute("PRAGMA table_info(tenants)").fetchall()]
        if "subscription_expires_at" not in tcols:
            db.execute("ALTER TABLE tenants ADD COLUMN subscription_expires_at TEXT")
        db.commit()
    db.close()


def seed_db():
    db = get_db()
    if db.fetchone("SELECT COUNT(*) c FROM tenants")["c"] > 0:
        db.close()
        return
    import random
    random.seed(42)
    expiry = (datetime.utcnow() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
    # المستأجر الأول: مجموعة النور (فرعان)
    t1 = db.insert("INSERT INTO tenants (name, plan, status, subscription_expires_at, created_at) VALUES (?,?,?,?,?) RETURNING id" if IS_POSTGRES else
                   "INSERT INTO tenants (name, plan, status, subscription_expires_at, created_at) VALUES (?,?,?,?,?)",
                   ("مجموعة النور التجارية", "yearly", "active", expiry, now_str()))
    s1a = db.insert("INSERT INTO stores (tenant_id, name, location, phone, created_at) VALUES (?,?,?,?,?)" + (" RETURNING id" if IS_POSTGRES else ""),
                    (t1, "النور - فرع المدينة", "شارع الجمهورية، وسط المدينة", "01001112233", now_str()))
    s1b = db.insert("INSERT INTO stores (tenant_id, name, location, phone, created_at) VALUES (?,?,?,?,?)" + (" RETURNING id" if IS_POSTGRES else ""),
                    (t1, "النور - فرع الجامعة", "حي الجامعة", "01004445566", now_str()))
    u1 = db.insert("INSERT INTO users (tenant_id, default_store_id, name, email, password_hash, role, created_at) VALUES (?,?,?,?,?,?,?)" + (" RETURNING id" if IS_POSTGRES else ""),
                   (t1, s1a, "أحمد النور", "owner@alnour.com", generate_password_hash("demo1234"), "owner", now_str()))
    db.insert("INSERT INTO users (tenant_id, default_store_id, name, email, password_hash, role, created_at) VALUES (?,?,?,?,?,?,?)" + (" RETURNING id" if IS_POSTGRES else ""),
              (t1, s1a, "محمد الكاشير", "cashier@alnour.com", generate_password_hash("demo1234"), "cashier", now_str()))
    # المستأجر الثاني: سوق البركة (فرع واحد، اشتراك شهري)
    t2 = db.insert("INSERT INTO tenants (name, plan, status, subscription_expires_at, created_at) VALUES (?,?,?,?,?)" + (" RETURNING id" if IS_POSTGRES else ""),
                   ("سوق البركة", "monthly", "active", expiry, now_str()))
    s2 = db.insert("INSERT INTO stores (tenant_id, name, location, phone, created_at) VALUES (?,?,?,?,?)" + (" RETURNING id" if IS_POSTGRES else ""),
                   (t2, "البركة - المركزي", "السوق المركزي، محل 15", "01122334455", now_str()))
    db.insert("INSERT INTO users (tenant_id, default_store_id, name, email, password_hash, role, created_at) VALUES (?,?,?,?,?,?,?)" + (" RETURNING id" if IS_POSTGRES else ""),
              (t2, s2, "خديجة البركة", "owner@baraka.com", generate_password_hash("demo1234"), "owner", now_str()))
    # منتجات لكل فرع
    catalog = [("أرز بسمتي 1كجم","RICE-001",65,52,120,10),("سكر 1كجم","SUG-001",32,26,200,20),
               ("زيت عباد الشمس 1.5ل","OIL-001",145,120,80,8),("حليب مبستر 1ل","MILK-001",28,22,150,15),
               ("خبز توست","BRD-001",12,8,60,12),("شاي كبس 200غ","TEA-001",45,35,90,10),
               ("صابون غسيل","SOAP-01",18,12,110,15),("عصير برتقال 1ل","JUI-001",25,18,3,10)]
    for store_id, tenant_id in ((s1a,t1),(s1b,t1),(s2,t2)):
        for name,sku,price,cost,stock,min_stock in catalog:
            db.insert("INSERT INTO products (tenant_id, store_id, name, sku, price, cost, stock, min_stock, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)" + (" RETURNING id" if IS_POSTGRES else ""),
                      (tenant_id, store_id, name, sku, price, cost, stock, min_stock, now_str(), now_str()))
    # مبيعات تجريبية للأيام السبعة الماضية
    for store_id, tenant_id in ((s1a,t1),(s1b,t1),(s2,t2)):
        prods = db.fetchall("SELECT id, price, name FROM products WHERE store_id=?", (store_id,))
        for day_offset in range(7):
            day = datetime.utcnow() - timedelta(days=day_offset)
            for _ in range(random.randint(3,9)):
                items = random.sample(list(prods), k=random.randint(1,4))
                subtotal = 0
                sale_time = day.replace(hour=random.randint(9,21), minute=random.randint(0,59)).strftime("%Y-%m-%d %H:%M:%S")
                sid = db.insert("INSERT INTO sales (tenant_id, store_id, user_id, subtotal, tax, total, payment_method, created_at) VALUES (?,?,?,?,?,?,?,?)" + (" RETURNING id" if IS_POSTGRES else ""),
                                (tenant_id, store_id, u1, 0, 0, 0, random.choice(["cash","card"]), sale_time))
                for p in items:
                    qty = random.randint(1,3); line = round(qty*p["price"],2); subtotal += line
                    db.insert("INSERT INTO sale_items (tenant_id, sale_id, product_id, product_name, qty, unit_price, line_total) VALUES (?,?,?,?,?,?,?)" + (" RETURNING id" if IS_POSTGRES else ""),
                              (tenant_id, sid, p["id"], p["name"], qty, p["price"], line))
                db.execute("UPDATE sales SET subtotal=?, total=? WHERE id=?", (round(subtotal,2), round(subtotal,2), sid))
    db.commit(); db.close()
    print("Seed completed: 2 tenants, 3 stores, demo users.")
