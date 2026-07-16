# Penetration Test: Web Management Server - Dual Exploitation Chain

## Title
Penetration Test: Web Management Server - Dual Exploitation Chain

## Executive Summary
أجري اختبار اختراق لخادم إدارة ويب يعمل على نظام تشغيل حديث ويوفر خدمات إدارة محتوى عبر واجهة أمامية عامة. أظهر الاختبار أن الخادم يعاني من سلسلة من الثغرات أدت في النهاية إلى سيطرة كاملة على النظام، بدءاً من نقطة وصول واحدة خالية من المصادقة.

الخادم يستضيف نظام إدارة Nginx-UI، وهو تطبيق ويب لإدارة خوادم Nginx. كانت الملفات الاحتياطية التي ينشئها التطبيق متاحة عبر رابط API عام من دون مصادقة، ما سمح باستخراج قاعدة بيانات تحتوي على كلمات مرور مشفرة. بعد كسر تشفير إحداها، تم الوصول إلى النظام عبر SSH بحساب مستخدم عادي. من هناك، كشفت المراجعة الداخلية عن وجود إصدار ضعيف من آلية عزل الحزم (snap subsystem) يمكن استغلاله عبر سباق على التوقيت (TOCTOU race condition) ليؤدي إلى تنفيذ كود بصلاحيات الجذر.

تمكن الاختبار من إثبات الانتقال من مستخدم عادي إلى صلاحيات الجذر الكاملة على الخادم.

| Attribute | Value |
|---|---|
| Identifier | CVE-2026-3888 |
| Weakness Class | CWE-862 |
## Technical Analysis
The weakness was assessed from an application-security and infrastructure-risk perspective. The core issue is classified as **Security Control Weakness** and was documented in a sanitized form suitable for public portfolio publication.

**Finding 1: Unauthenticated Backup API (CWE-862)**
The `/api/backup` endpoint on the Nginx-UI web management application provided a full system backup without requiring authentication. The response contained an `X-Backup-Security` header carrying the encryption key and IV, making decryption straightforward.

**Finding 2: Weak Credential Strength (CWE-521)**
The extracted `database.db` file contained bcrypt-hashed passwords. Using hashcat with the rockyou wordlist, the password for user `jonathan` was successfully cracked.

**Finding 3: TOCTOU Race in snap-confine (CWE-367 — CVE-2026-3888)**
The snap subsystem's `snap-update-ns` component creates a temporary `.snap` directory as staging ground for mount namespace operations. A TOCTOU window exists between reading files from this staging directory and performing mount operations. By replacing the directory contents with attacker-controlled copies at the precise moment, a malicious dynamic linker can be injected. On subsequent invocation of the SUID `snap-confine` binary, the compromised linker executes attacker code with root privileges, creating a SUID shell for persistent access.

## Impact
- Loss of confidentiality, integrity, or availability depending on exposure and business context.
- Increased operational risk and potential regulatory exposure if sensitive data is processed.

## Remediation
1. إضافة مصادقة إلزامية لواجهة API `/api/backup` ومنع الوصول إليها من دون تفويض مناسب.
2. تشفير محتويات النسخ الاحتياطي باستخدام مفتاح مشفر لا يُخزن مع الملف نفسه.
3. فرض سياسة كلمات مرور قوية تشمل متطلبات الطول والتعقيد، مع تطبيق قفل بعد عدة محاولات فاشلة.
4. تحديث snapd إلى إصدار أحدث (3.0 أو أعلى) لمعالجة ثغرة CVE-2026-3888.
5. إزالة بت SUID من `/usr/lib/snapd/snap-confine` إذا لم يكن ضرورياً، أو تفعيل وسم `nosuid` على نقاط التثبيت الخاصة بـ snap.
6. تطبيق سياسة التحديثات الأمنية الدورية لجميع مكونات النظام.
7. تفعيل نظام مراقبة لاكتشاف محاولات استغلال سباقات التوقيت والوصول غير المصرح به إلى واجهات API.

## Lessons Learned & Mitigation Strategy
- Treat every integration boundary as untrusted, especially when application logic forwards user-controlled values to filesystems, shells, parsers, or external tools.
- Security reviews should validate the complete exploit chain, not only the first vulnerable endpoint; low-severity misconfigurations can become critical when chained.
- Public-facing documentation should describe risk, root cause, and remediation without exposing operational identifiers, credentials, or reusable exploitation artifacts.
- Defensive controls should combine preventive validation, runtime least privilege, telemetry, and patch governance to reduce both exploitability and blast radius.

## Publication Sanitization Notes
- Sensitive infrastructure identifiers, IP addresses, hostnames, credentials, hashes, and e-mail addresses were replaced with explicit placeholders.
- Reusable operational evidence was minimized or abstracted to keep the document suitable for public GitHub publication.
- The document uses a consultant-style structure aligned with common web security testing report practices such as OWASP WSTG reporting expectations.
