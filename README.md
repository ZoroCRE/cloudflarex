# Cloudflare Bulk Manager

لوحة تحكم محلية عربية لإدارة DNS Records على عدة Cloudflare Zones دفعة واحدة.

## التشغيل

```bash
cd /home/ubuntu/cloudflare-bulk-dashboard
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python app.py
```

ثم افتح: http://127.0.0.1:5000

## API Token

أنشئ Token من Cloudflare بصلاحيات محدودة:

- `Zone:Read`
- `DNS:Edit`

لإضافة Rules لاحقًا، نضيف الصلاحية الخاصة بنوع الـ Rules المطلوب. لا تستخدم Global API Key.

## ما يعمل حاليًا

- تسجيل دخول مؤقت بالتوكن داخل الذاكرة فقط.
- جلب جميع الـ active zones مع pagination.
- لصق قائمة domains أو رفع TXT/CSV.
- مطابقة القائمة مع الدومينات الموجودة بالحساب.
- إضافة أو تحديث A, AAAA, CNAME, TXT, MX, NS, CAA, SRV.
- Preview قبل التنفيذ.
- Apply جماعي مع تأكيد.
- سجل نجاح وفشل العملية.

## ملاحظات

- لا يتم حفظ التوكن على القرص.
- هذه نسخة أولى محلية؛ قبل تعريضها للإنترنت يجب إضافة HTTPS، مصادقة للوحة نفسها، CSRF protection، وتخزين جلسات آمن.
- تطبيق الـ Rulesets / Redirect Rules / WAF سيكون في المرحلة التالية بعد تحديد الأنواع المطلوبة.
