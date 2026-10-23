"""
remove_demo_accounts.py — يُشغَّل يدوياً قبل النشر فقط.
يحذف الحسابات التجريبية (demo1234) ويطبع تحذيراً. لا يمس أي بيانات مبيعات.
الاستخدام: python3 remove_demo_accounts.py  (سيطلب تأكيداً)
"""
import sys
from db import get_db, init_db

DEMO_EMAILS = ["owner@alnour.com", "cashier@alnour.com", "owner@baraka.com"]

if __name__ == "__main__":
    init_db()
    db = get_db()
    users = db.fetchall("SELECT id, email, tenant_id FROM users WHERE email IN (?,?,?)", DEMO_EMAILS)
    if not users:
        print("لا توجد حسابات تجريبية — تم حذفها مسبقاً."); sys.exit(0)
    print(f"سيتم حذف {len(users)} حسابات تجريبية (ولن تتمكن من الدخول بها بعد الآن):")
    for u in users: print("  -", u["email"])
    ans = input("اكتب 'نعم' للتأكيد: ")
    if ans.strip() != "نعم":
        print("تم الإلغاء."); sys.exit(0)
    for u in users:
        db.execute("DELETE FROM users WHERE id=?", (u["id"],))
    db.commit(); db.close()
    print("تم حذف الحسابات التجريبية. أنشئ حسابك الإداري عبر واجهة التسجيل.")
