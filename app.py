"""
app.py — خادم SaaS متعدد المتاجر مع دعم PWA والمزامنة دون اتصال
جديد في هذا الإصدار:
- client_uid: مفتاح فريد لكل فاتورة يولّدها الجهاز المحلي — يمنع تكرار الفواتير تماماً (idempotency).
- /api/sync/bulk: استلام دفعة فواتير محلية مع نتيجة لكل فاتورة على حدة.
- /api/sync/delta: تنزيل التغييرات (منتجات + مبيعات) منذ وقت معين لتحديث الكاش المحلي.
- /api/subscription: حالة الاشتراك؛ إذا انتهى يُحظر الكتابة (402) لكن البيانات المحلية تُحفظ على الجهاز.
- دعم PostgreSQL عبر متغير DATABASE_URL (وإلا SQLite للتطوير).
"""
import os
import datetime as dt
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory
import jwt
from werkzeug.security import check_password_hash, generate_password_hash
from db import get_db, init_db, seed_db, now_str, IS_POSTGRES

app = Flask(__name__, static_folder="static", template_folder="templates")
DEFAULT_SECRET = "change-me-in-production-32chars-min!!"
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", DEFAULT_SECRET)
TOKEN_TTL_HOURS = 72
RET = " RETURNING id" if IS_POSTGRES else ""

# ===== تقوية الأمان (إصدار hardening) =====
# 1) تحذير إجباري عند ترك المفتاح الافتراضي (لا يمنع التشغيل للتطوير، لكنه يظهر بوضوح)
if app.config["SECRET_KEY"] == DEFAULT_SECRET:
    print("\n" + "!"*60)
    print("تحذير أمني: SECRET_KEY لا تزال القيمة الافتراضية — غيّرها قبل النشر!")
    print("!"*60 + "\n")

# 2) حد محاولات تسجيل الدخول (Rate Limiting) بسيط في الذاكرة — يمنع تجربة كلمات المرور
from collections import defaultdict
import time as _time
_login_attempts = defaultdict(list)  # ip -> [timestamps]
MAX_LOGIN_ATTEMPTS = 8
LOGIN_WINDOW_SEC = 300

def _rate_limited(ip):
    now = _time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < LOGIN_WINDOW_SEC]
    if len(_login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS:
        return True
    _login_attempts[ip].append(now)
    return False

# 3) ترويسات أمنية إجبارية على كل استجابة (لا تؤثر على الواجهة)
CORS_ORIGINS = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    if CORS_ORIGINS:
        origin = request.headers.get("Origin", "")
        if origin in CORS_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
    return resp  # لاسترجاع المعرف في PostgreSQL


# ---------------------------------------------------------------------------
# المصادقة + العزل الإلزامي + فحص الاشتراك
# ---------------------------------------------------------------------------
def issue_token(user):
    payload = {"user_id": user["id"], "tenant_id": user["tenant_id"], "role": user["role"],
               "exp": dt.datetime.utcnow() + dt.timedelta(hours=TOKEN_TTL_HOURS)}
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "غير مصرح: لم يتم إرسال رمز الدخول"}), 401
        try:
            payload = jwt.decode(auth[7:], app.config["SECRET_KEY"], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "انتهت صلاحية الجلسة، سجل الدخول مجدداً"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "رمز دخول غير صالح"}), 401
        g.user_id = payload["user_id"]; g.tenant_id = payload["tenant_id"]; g.role = payload["role"]
        db = get_db()
        default_store = db.fetchone("SELECT default_store_id FROM users WHERE id=? AND tenant_id=?", (g.user_id, g.tenant_id))
        requested = request.headers.get("X-Store-Id")
        store_id = int(requested) if requested else (default_store["default_store_id"] if default_store else None)
        if not store_id:
            db.close(); return jsonify({"error": "لم يتم تحديد فرع"}), 400
        store = db.fetchone("SELECT id, name FROM stores WHERE id=? AND tenant_id=?", (store_id, g.tenant_id))
        # فحص حالة الاشتراك
        tenant = db.fetchone("SELECT plan, status, subscription_expires_at FROM tenants WHERE id=?", (g.tenant_id,))
        db.close()
        if not store:
            return jsonify({"error": "هذا الفرع غير موجود أو لا يخص حسابك"}), 403
        g.store_id = store["id"]; g.store_name = store["name"]; g.tenant = tenant
        # إذا كان الاشتراك منتهياً/موقوفاً: نسمح بالقراءة لكن نحظر الكتابة (العميل يحفظ محلياً)
        exp = tenant["subscription_expires_at"] if tenant else None
        if exp and not isinstance(exp, str):
            exp = exp.strftime("%Y-%m-%d %H:%M:%S")
        suspended = bool(tenant) and (tenant["status"] == "suspended" or (exp and exp < now_str()))
        g.suspended = bool(suspended)
        if g.suspended and request.method in ("POST", "PUT", "DELETE") and request.path not in ("/api/subscription",):
            return jsonify({"error": "انتهى اشتراكك. بيانات مبيعاتك محفوظة على جهازك — جدد الاشتراك لمزامنتها.", "code": "SUBSCRIPTION_EXPIRED"}), 402
        return f(*args, **kwargs)
    return wrapper


def owner_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if g.role != "owner":
            return jsonify({"error": "هذه الصلاحية مخصصة لصاحب الحساب فقط"}), 403
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# ملفات الواجهة وملفات PWA
# ---------------------------------------------------------------------------
@app.route("/")
def index(): return send_from_directory("templates", "index.html")
@app.route("/static/<path:path>")
def static_files(path): return send_from_directory("static", path)
@app.route("/manifest.json")
def manifest(): return send_from_directory("static", "manifest.json")
@app.route("/sw.js")
def service_worker():
    resp = send_from_directory("static", "sw.js")
    resp.headers["Service-Worker-Allowed"] = "/"
    resp.headers["Cache-Control"] = "no-cache"
    return resp
@app.route("/icon-192.png")
def icon192(): return send_from_directory("static", "icon-192.png")
@app.route("/icon-512.png")
def icon512(): return send_from_directory("static", "icon-512.png")


# ---------------------------------------------------------------------------
# المصادقة
# ---------------------------------------------------------------------------
@app.route("/api/register", methods=["POST"])
def register():
    d = request.get_json(force=True)
    required = ["tenant_name","store_name","owner_name","email","password"]
    if not all(d.get(k) for k in required): return jsonify({"error": "جميع الحقول مطلوبة"}), 400
    if len(d["password"]) < 8: return jsonify({"error": "كلمة المرور يجب ألا تقل عن 8 أحرف"}), 400
    if _rate_limited(request.remote_addr):
        return jsonify({"error": "محاولات كثيرة جداً — حاول بعد 5 دقائق"}), 429
    db = get_db()
    if db.fetchone("SELECT 1 FROM users WHERE email=?", (d["email"],)):
        db.close(); return jsonify({"error": "هذا البريد مسجل مسبقاً"}), 409
    expiry = (dt.datetime.utcnow() + dt.timedelta(days=14)).strftime("%Y-%m-%d %H:%M:%S")  # تجربة 14 يوماً
    t = db.insert("INSERT INTO tenants (name, plan, status, subscription_expires_at, created_at) VALUES (?,?,?,?,?)"+RET,
                  (d["tenant_name"], d.get("plan","monthly"), "trial", expiry, now_str()))
    s = db.insert("INSERT INTO stores (tenant_id, name, location, phone, created_at) VALUES (?,?,?,?,?)"+RET,
                  (t, d["store_name"], d.get("location",""), d.get("phone",""), now_str()))
    u = db.insert("INSERT INTO users (tenant_id, default_store_id, name, email, password_hash, role, created_at) VALUES (?,?,?,?,?,?,?)"+RET,
                  (t, s, d["owner_name"], d["email"], generate_password_hash(d["password"]), "owner", now_str()))
    db.commit()
    user = db.fetchone("SELECT * FROM users WHERE id=?", (u,))
    token = issue_token(user)
    stores = db.fetchall("SELECT id, name, location FROM stores WHERE tenant_id=?", (t,))
    db.close()
    return jsonify({"token": token, "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]},
                    "stores": [dict(r) for r in stores], "active_store_id": s})


@app.route("/api/login", methods=["POST"])
def login():
    if _rate_limited(request.remote_addr):
        return jsonify({"error": "محاولات دخول كثيرة جداً — حاول بعد 5 دقائق"}), 429
    d = request.get_json(force=True)
    db = get_db()
    user = db.fetchone("SELECT * FROM users WHERE email=?", (d.get("email",""),))
    if not user or not check_password_hash(user["password_hash"], d.get("password","")):
        db.close(); return jsonify({"error": "بريد أو كلمة مرور غير صحيحة"}), 401
    token = issue_token(user)
    stores = db.fetchall("SELECT id, name, location FROM stores WHERE tenant_id=?", (user["tenant_id"],))
    db.close()
    return jsonify({"token": token, "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]},
                    "stores": [dict(r) for r in stores], "active_store_id": user["default_store_id"]})


@app.route("/api/me", methods=["GET"])
@login_required
def me():
    db = get_db()
    stores = db.fetchall("SELECT id, name, location FROM stores WHERE tenant_id=?", (g.tenant_id,))
    db.close()
    return jsonify({"user": {"id": g.user_id, "role": g.role}, "stores": [dict(r) for r in stores],
                    "active_store_id": g.store_id, "active_store_name": g.store_name, "suspended": g.suspended})


@app.route("/api/subscription", methods=["GET"])
@login_required
def subscription():
    t = g.tenant
    return jsonify({"plan": t["plan"], "status": t["status"],
                    "expires_at": t["subscription_expires_at"], "suspended": g.suspended,
                    "policy": "إذا انتهى الاشتراك أثناء العمل دون إنترنت: تستمر حفظ المبيعات محلياً على الجهاز، وتتوقف المزامنة حتى التجديد، ولا تُحذف أي بيانات أبداً."})


# ---------------------------------------------------------------------------
# الفروع
# ---------------------------------------------------------------------------
@app.route("/api/stores", methods=["GET"])
@login_required
def list_stores():
    db = get_db()
    rows = db.fetchall("SELECT id, name, location, phone FROM stores WHERE tenant_id=?", (g.tenant_id,))
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/stores", methods=["POST"])
@owner_required
def create_store():
    d = request.get_json(force=True)
    if not d.get("name"): return jsonify({"error": "اسم الفرع مطلوب"}), 400
    db = get_db()
    sid = db.insert("INSERT INTO stores (tenant_id, name, location, phone, created_at) VALUES (?,?,?,?,?)"+RET,
                    (g.tenant_id, d["name"], d.get("location",""), d.get("phone",""), now_str()))
    db.commit(); db.close()
    return jsonify({"id": sid, "name": d["name"]}), 201


# ---------------------------------------------------------------------------
# لوحة التحكم
# ---------------------------------------------------------------------------
@app.route("/api/dashboard", methods=["GET"])
@login_required
def dashboard():
    db = get_db()
    today = dt.datetime.utcnow().strftime("%Y-%m-%d")
    ts = db.fetchone("SELECT COUNT(*) c, COALESCE(SUM(total),0) s FROM sales WHERE tenant_id=? AND store_id=? AND CAST(created_at AS DATE)=?",
                     (g.tenant_id, g.store_id, today))
    week_ago = (dt.datetime.utcnow() - dt.timedelta(days=7)).strftime("%Y-%m-%d")
    wr = db.fetchone("SELECT COALESCE(SUM(total),0) s FROM sales WHERE tenant_id=? AND store_id=? AND CAST(created_at AS DATE)>=?",
                     (g.tenant_id, g.store_id, week_ago))["s"]
    low = db.fetchone("SELECT COUNT(*) c FROM products WHERE tenant_id=? AND store_id=? AND stock<=min_stock", (g.tenant_id, g.store_id))["c"]
    pc = db.fetchone("SELECT COUNT(*) c FROM products WHERE tenant_id=? AND store_id=?", (g.tenant_id, g.store_id))["c"]
    top = db.fetchall("""SELECT si.product_name, SUM(si.qty) qty, SUM(si.line_total) revenue FROM sale_items si
        JOIN sales s ON s.id=si.sale_id WHERE s.tenant_id=? AND s.store_id=? AND CAST(s.created_at AS DATE)>=?
        GROUP BY si.product_id, si.product_name ORDER BY revenue DESC LIMIT 5""", (g.tenant_id, g.store_id, week_ago))
    daily = db.fetchall("""SELECT CAST(created_at AS DATE) AS d, COALESCE(SUM(total),0) AS revenue, COUNT(*) AS sales_count
        FROM sales WHERE tenant_id=? AND store_id=? AND CAST(created_at AS DATE)>=? GROUP BY CAST(created_at AS DATE) ORDER BY d""",
        (g.tenant_id, g.store_id, week_ago))
    db.close()
    return jsonify({"today_count": ts["c"], "today_revenue": round(ts["s"],2), "week_revenue": round(wr,2),
                    "low_stock": low, "products_count": pc, "top_products": [dict(r) for r in top],
                    "daily": [dict(r) for r in daily], "store_name": g.store_name, "suspended": g.suspended})


# ---------------------------------------------------------------------------
# المنتجات والمخزون
# ---------------------------------------------------------------------------
@app.route("/api/products", methods=["GET"])
@login_required
def list_products():
    q = request.args.get("search","").strip()
    db = get_db()
    if q:
        rows = db.fetchall("""SELECT * FROM products WHERE tenant_id=? AND store_id=? AND (name LIKE ? OR sku LIKE ? OR barcode LIKE ?) ORDER BY name""",
                           (g.tenant_id, g.store_id, f"%{q}%", f"%{q}%", f"%{q}%"))
    else:
        rows = db.fetchall("SELECT * FROM products WHERE tenant_id=? AND store_id=? ORDER BY name", (g.tenant_id, g.store_id))
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/products", methods=["POST"])
@owner_required
def create_product():
    d = request.get_json(force=True)
    if not d.get("name"): return jsonify({"error": "اسم المنتج مطلوب"}), 400
    db = get_db()
    pid = db.insert("""INSERT INTO products (tenant_id, store_id, name, sku, barcode, price, cost, stock, min_stock, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)"""+RET,
        (g.tenant_id, g.store_id, d["name"], d.get("sku",""), d.get("barcode",""), float(d.get("price",0)),
         float(d.get("cost",0)), float(d.get("stock",0)), float(d.get("min_stock",5)), now_str(), now_str()))
    if float(d.get("stock",0)) > 0:
        db.insert("""INSERT INTO stock_movements (tenant_id, store_id, product_id, type, qty_change, note, user_id, created_at)
            VALUES (?,?,?,?,?,?,?,?)"""+RET,
            (g.tenant_id, g.store_id, pid, "restock", float(d["stock"]), "رصيد افتتاحي", g.user_id, now_str()))
    db.commit(); db.close()
    return jsonify({"id": pid}), 201

@app.route("/api/products/<int:pid>", methods=["PUT"])
@owner_required
def update_product(pid):
    d = request.get_json(force=True)
    db = get_db()
    row = db.fetchone("SELECT * FROM products WHERE id=? AND tenant_id=? AND store_id=?", (pid, g.tenant_id, g.store_id))
    if not row: db.close(); return jsonify({"error": "المنتج غير موجود"}), 404
    db.execute("UPDATE products SET name=?, sku=?, barcode=?, price=?, cost=?, min_stock=?, updated_at=? WHERE id=?",
               (d.get("name",row["name"]), d.get("sku",row["sku"]), d.get("barcode",row["barcode"]),
                float(d.get("price",row["price"])), float(d.get("cost",row["cost"])), float(d.get("min_stock",row["min_stock"])), now_str(), pid))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/products/<int:pid>/restock", methods=["POST"])
@owner_required
def restock(pid):
    d = request.get_json(force=True); qty = float(d.get("qty",0))
    if qty <= 0: return jsonify({"error": "الكمية يجب أن تكون موجبة"}), 400
    db = get_db()
    if not db.fetchone("SELECT id FROM products WHERE id=? AND tenant_id=? AND store_id=?", (pid, g.tenant_id, g.store_id)):
        db.close(); return jsonify({"error": "المنتج غير موجود"}), 404
    db.execute("UPDATE products SET stock=stock+?, updated_at=? WHERE id=?", (qty, now_str(), pid))
    db.insert("""INSERT INTO stock_movements (tenant_id, store_id, product_id, type, qty_change, note, user_id, created_at)
        VALUES (?,?,?,?,?,?,?,?)"""+RET, (g.tenant_id, g.store_id, pid, "restock", qty, d.get("note",""), g.user_id, now_str()))
    db.commit(); db.close()
    return jsonify({"ok": True})

@app.route("/api/products/<int:pid>", methods=["DELETE"])
@owner_required
def delete_product(pid):
    db = get_db()
    cur = db.execute("DELETE FROM products WHERE id=? AND tenant_id=? AND store_id=?", (pid, g.tenant_id, g.store_id))
    db.commit(); affected = cur.rowcount if hasattr(cur,"rowcount") else 0; db.close()
    if affected == 0: return jsonify({"error": "المنتج غير موجود"}), 404
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# المبيعات — مع منع التكرار المطلق عبر client_uid
# ---------------------------------------------------------------------------
def _create_sale_core(db, sale_data):
    """ينشئ فاتورة واحدة (مع خصم المخزون وحركة المخزون). يفترض أن client_uid غير موجود."""
    items = sale_data["items"]; subtotal = 0.0; validated = []
    for it in items:
        prod = db.fetchone("SELECT * FROM products WHERE id=? AND tenant_id=? AND store_id=?",
                           (it["product_id"], g.tenant_id, g.store_id))
        if not prod: return None, "المنتج غير موجود في هذا الفرع"
        qty = float(it["qty"])
        if qty <= 0: return None, "كمية غير صالحة"
        if prod["stock"] < qty: return None, f"المخزون غير كافٍ لـ {prod['name']} (المتوفر: {prod['stock']})"
        line = round(qty*prod["price"],2); subtotal += line; validated.append((prod, qty, line))
    tax = round(subtotal*float(sale_data.get("tax_rate",0))/100,2); total = round(subtotal+tax,2)
    client_time = sale_data.get("client_created_at") or now_str()
    sid = db.insert("""INSERT INTO sales (tenant_id, store_id, user_id, client_uid, subtotal, tax, total, payment_method,
        customer_name, note, created_at, client_created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"""+RET,
        (g.tenant_id, g.store_id, g.user_id, sale_data.get("client_uid"), round(subtotal,2), tax, total,
         sale_data.get("payment_method","cash"), sale_data.get("customer_name",""), sale_data.get("note",""), now_str(), client_time))
    for prod, qty, line in validated:
        db.insert("""INSERT INTO sale_items (tenant_id, sale_id, product_id, product_name, qty, unit_price, line_total)
            VALUES (?,?,?,?,?,?,?)"""+RET, (g.tenant_id, sid, prod["id"], prod["name"], qty, prod["price"], line))
        db.execute("UPDATE products SET stock=stock-?, updated_at=? WHERE id=?", (qty, now_str(), prod["id"]))
        db.insert("""INSERT INTO stock_movements (tenant_id, store_id, product_id, type, qty_change, note, user_id, created_at)
            VALUES (?,?,?,?,?,?,?,?)"""+RET, (g.tenant_id, g.store_id, prod["id"], "sale", -qty, f"فاتورة #{sid}", g.user_id, now_str()))
    return {"id": sid, "total": total}, None

@app.route("/api/sales", methods=["POST"])
@login_required
def create_sale():
    d = request.get_json(force=True)
    if not d.get("items"): return jsonify({"error": "السلة فارغة"}), 400
    db = get_db()
    # التفرد المطلق: إذا وصلت نفس الفاتورة (client_uid) مسبقاً نعيدها دون إنشاء جديدة
    if d.get("client_uid"):
        existing = db.fetchone("SELECT id, total FROM sales WHERE tenant_id=? AND client_uid=?", (g.tenant_id, d["client_uid"]))
        if existing:
            db.close()
            return jsonify({"id": existing["id"], "total": existing["total"], "deduplicated": True})
    result, err = _create_sale_core(db, d)
    if err: db.rollback(); db.close(); return jsonify({"error": err}), 400
    db.commit(); db.close()
    return jsonify(result), 201

@app.route("/api/sync/bulk", methods=["POST"])
@login_required
def sync_bulk():
    """استلام دفعة فواتير محلية. كل فاتورة بمعرفها client_uid الفريد.
    النتيجة لكل فاتورة: synced / already_synced / error — فشل واحدة لا يفشل الباقي."""
    sales = request.get_json(force=True).get("sales", [])
    results = []
    db = get_db()
    for s in sales:
        if not s.get("client_uid"):
            results.append({"client_uid": s.get("client_uid"), "status": "error", "error": "client_uid مفقود"}); continue
        existing = db.fetchone("SELECT id, total FROM sales WHERE tenant_id=? AND client_uid=?", (g.tenant_id, s["client_uid"]))
        if existing:
            results.append({"client_uid": s["client_uid"], "status": "already_synced", "sale_id": existing["id"]}); continue
        result, err = _create_sale_core(db, s)
        if err:
            db.rollback()
            results.append({"client_uid": s["client_uid"], "status": "error", "error": err})
        else:
            db.commit()
            results.append({"client_uid": s["client_uid"], "status": "synced", "sale_id": result["id"], "total": result["total"]})
    db.close()
    return jsonify({"results": results, "synced_count": sum(1 for r in results if r["status"] in ("synced","already_synced"))})

@app.route("/api/sync/delta", methods=["GET"])
@login_required
def sync_delta():
    """تنزيل التغييرات منذ وقت معين لتحديث الكاش المحلي (منتجات + مبيعات الفرع النشط)."""
    since = request.args.get("since", "1970-01-01")
    db = get_db()
    products = db.fetchall("SELECT * FROM products WHERE tenant_id=? AND store_id=? AND updated_at>=?", (g.tenant_id, g.store_id, since))
    sales = db.fetchall("SELECT * FROM sales WHERE tenant_id=? AND store_id=? AND created_at>=? ORDER BY created_at", (g.tenant_id, g.store_id, since))
    db.close()
    return jsonify({"server_time": now_str(), "products": [dict(r) for r in products], "sales": [dict(r) for r in sales]})

@app.route("/api/sales", methods=["GET"])
@login_required
def list_sales():
    db = get_db()
    rows = db.fetchall("""SELECT s.*, u.name cashier_name FROM sales s LEFT JOIN users u ON u.id=s.user_id
        WHERE s.tenant_id=? AND s.store_id=? ORDER BY s.created_at DESC LIMIT 100""", (g.tenant_id, g.store_id))
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/sales/<int:sid>", methods=["GET"])
@login_required
def sale_detail(sid):
    db = get_db()
    sale = db.fetchone("SELECT * FROM sales WHERE id=? AND tenant_id=? AND store_id=?", (sid, g.tenant_id, g.store_id))
    if not sale: db.close(); return jsonify({"error": "الفاتورة غير موجودة"}), 404
    items = db.fetchall("SELECT * FROM sale_items WHERE sale_id=? AND tenant_id=?", (sid, g.tenant_id))
    db.close()
    return jsonify({"sale": dict(sale), "items": [dict(r) for r in items]})

@app.route("/api/movements", methods=["GET"])
@login_required
def movements():
    db = get_db()
    rows = db.fetchall("""SELECT m.*, p.name product_name FROM stock_movements m LEFT JOIN products p ON p.id=m.product_id
        WHERE m.tenant_id=? AND m.store_id=? ORDER BY m.created_at DESC LIMIT 50""", (g.tenant_id, g.store_id))
    db.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db(); seed_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
