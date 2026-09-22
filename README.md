# Browser Permission Audit

A small, offline Python tool for reviewing the permissions requested by Chromium-style browser extension manifests. It turns `manifest.json` permissions into an explainable risk summary without installing the extension, executing its code, or sending the manifest anywhere.

> Permissions describe capability, not intent. A high score means **review carefully**, not “malicious.”

## Why this exists
Browser extensions can request access to tabs, browsing history, cookies, downloads, web origins, debugging APIs, and other sensitive capabilities. Raw manifest files are easy to overlook during code review. Browser Permission Audit provides a deterministic first-pass review that is useful locally and in CI.

## Features
- Reads a `manifest.json` file or an extension directory.
- Supports common Manifest V2 and V3 permission layouts.
- Separates API permissions from host access, including V2 host patterns in `permissions`.
- Flags broad host access such as `<all_urls>` and powerful APIs such as `debugger`, `nativeMessaging`, `proxy`, and cookies/history access.
- Flags legacy Manifest V2 and `unsafe-eval` in string CSP declarations.
- Produces a bounded 0–100 review score and `low`, `moderate`, `high`, or `critical` risk level.
- Human-readable and JSON output.
- CI-friendly `--fail-on` threshold and meaningful exit codes.
- Reusable Python API.
- Fully offline; no telemetry, browser-store access, extension installation, or code execution.

## Preview
```text
$ browser-permission-audit examples/manifest.safe.json
Example Notes Extension — risk: LOW (12/100)
Manifest: V3 | API permissions: 2 | Host permissions: 1
- MEDIUM Can access matching web origins. [https://example.com/*]
- LOW    Requests 'activeTab' browser capability. [activeTab]
- LOW    Requests 'storage' browser capability. [storage]
```

For screenshots, capture the terminal output above; the project intentionally has no GUI.

## Requirements
- Python 3.10+
- No runtime dependencies

## Installation
```bash
git clone https://github.com/rad03i2/browser-permission-audit.git
cd browser-permission-audit
python -m pip install -e .
```

For development:
```bash
python -m pip install -e . pytest
```

## Usage
Audit a manifest or directory:
```bash
browser-permission-audit path/to/manifest.json
browser-permission-audit path/to/unpacked-extension
```

Machine-readable output:
```bash
browser-permission-audit extension/ --json
```

Fail CI when the result is at least high risk:
```bash
browser-permission-audit extension/ --fail-on high
```

Exit codes: `0` successful audit below the configured threshold, `1` invalid/unreadable input, `2` configured risk threshold reached.

### Python API
```python
from browser_permission_audit import audit_path

report = audit_path("extension")
print(report.risk, report.score)
for finding in report.findings:
    print(finding.severity, finding.message)
```

## Configuration and scoring
There is deliberately no config file or environment-variable requirement. Rules are deterministic and versioned in source. Known API permissions receive small-to-high review weights; broad host access receives a high weight; specific host access receives a moderate weight. Scores are capped at 100. Unknown API permissions receive a small review weight rather than being silently ignored.

This score is a prioritization aid, not a security verdict. Optional permissions are included because they remain capabilities the extension may request later.

## Project structure
```text
src/browser_permission_audit/
  __init__.py       Public API
  core.py           Manifest loading, validation, rules, scoring
  cli.py            Command-line interface
tests/               Core and CLI tests
examples/            Safe sample manifest
.github/workflows/   Cross-platform CI
```

## Testing
```bash
python -m compileall -q src tests
pytest -q
```
CI runs these checks on Ubuntu, Windows, and macOS with Python 3.10, 3.12, and 3.13, plus a CLI smoke test against the sample manifest.

## Security & privacy
The tool reads only the supplied local manifest. It does not inspect browser profiles, browsing history, cookies, installed extensions, or credentials. It performs no network requests and never executes extension JavaScript. See [SECURITY.md](SECURITY.md).

## Limitations
- This is static manifest analysis, not malware detection or a complete extension security audit.
- A legitimate extension can need powerful permissions; a low-permission extension can still contain unsafe code.
- Content scripts, JavaScript behavior, remote services, supply-chain risk, and store reputation are not analyzed.
- Browser-specific permission semantics can evolve; rules must be maintained over time.
- CSP object forms and every vendor-specific manifest field are not exhaustively interpreted.

## Optional roadmap
Future work may add Firefox-specific manifest semantics, configurable organization policies, and deeper static analysis of content-script declarations. These are not claimed as current features.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md). Please include tests and keep analysis offline and explainable.

## License
MIT — see [LICENSE](LICENSE).

## Author
**Radwan Abdulhadi Ahmed**  
**رضوان عبدالهادي أحمد**  
GitHub: [@rad03i2](https://github.com/rad03i2)

---

# تدقيق صلاحيات المتصفح — العربية

أداة Python صغيرة تعمل محليًا ومن دون اتصال بالإنترنت لمراجعة الصلاحيات التي تطلبها إضافات المتصفحات المبنية على نمط Chromium من خلال ملف `manifest.json`. تحوّل الأداة الصلاحيات الخام إلى ملخص مخاطر قابل للفهم، من دون تثبيت الإضافة أو تشغيل كودها أو إرسال بياناتها إلى أي جهة.

> الصلاحية تعبّر عن **قدرة** الإضافة ولا تثبت نيتها. الدرجة المرتفعة تعني أن الإضافة تحتاج مراجعة أدق، ولا تعني تلقائيًا أنها خبيثة.

## لماذا هذا المشروع؟
يمكن للإضافات طلب الوصول إلى التبويبات والسجل والكوكيز والتنزيلات والمواقع وواجهات تصحيح الأخطاء وغيرها. قراءة ملف manifest يدويًا قد تجعل بعض الصلاحيات تمر دون ملاحظة، لذلك يوفر المشروع مراجعة أولية ثابتة ومناسبة للاستخدام المحلي وCI.

## الميزات
- قراءة ملف `manifest.json` مباشرة أو مجلد إضافة مفكوكة.
- دعم الترتيبات الشائعة لصلاحيات Manifest V2 وV3.
- فصل صلاحيات API عن صلاحيات المواقع، مع فهم أن V2 قد يضع أنماط المواقع داخل `permissions`.
- تنبيه عند الوصول الواسع مثل `<all_urls>` وعند APIs قوية مثل `debugger` و`nativeMessaging` و`proxy` والكوكيز والسجل.
- تنبيه عند Manifest V2 القديم ووجود `unsafe-eval` في CSP النصي.
- درجة مراجعة من 0 إلى 100 وتصنيف: منخفض، متوسط، مرتفع، أو حرج.
- مخرجات بشرية أو JSON، وخيار `--fail-on` للـCI.
- Python API قابلة لإعادة الاستخدام.
- عمل محلي بالكامل بلا telemetry أو شبكة أو تنفيذ لكود الإضافة.

## المتطلبات والتثبيت
يتطلب Python 3.10 أو أحدث ولا توجد اعتماديات تشغيل خارجية.
```bash
git clone https://github.com/rad03i2/browser-permission-audit.git
cd browser-permission-audit
python -m pip install -e .
```
للتطوير والاختبارات:
```bash
python -m pip install -e . pytest
```

## الاستخدام
```bash
browser-permission-audit path/to/manifest.json
browser-permission-audit path/to/unpacked-extension
browser-permission-audit extension/ --json
browser-permission-audit extension/ --fail-on high
```
رموز الخروج: `0` للتدقيق الناجح تحت الحد، `1` لمدخل غير صالح أو غير مقروء، و`2` عند بلوغ حد المخاطر المطلوب.

### Python API
```python
from browser_permission_audit import audit_path
report = audit_path("extension")
print(report.risk, report.score)
```

## الإعداد وآلية التقييم
لا يحتاج المشروع ملف إعداد أو متغيرات بيئة. القواعد ثابتة وموجودة في المصدر: تُمنح الصلاحيات أوزان مراجعة مختلفة، ويحصل الوصول الواسع للمواقع على وزن مرتفع، بينما يحصل الوصول المحدد على وزن متوسط. الدرجة القصوى 100، والصلاحيات غير المعروفة لا تُتجاهل بل تحصل على وزن مراجعة صغير. الصلاحيات الاختيارية تدخل في التدقيق لأنها قد تُطلب لاحقًا.

## بنية المشروع
الكود داخل `src/browser_permission_audit`، والاختبارات داخل `tests`، والمثال الآمن داخل `examples`، وCI داخل `.github/workflows`.

## الاختبار
```bash
python -m compileall -q src tests
pytest -q
```
يشغّل CI الاختبارات على Ubuntu وWindows وmacOS باستخدام Python 3.10 و3.12 و3.13، إضافة إلى اختبار CLI على المثال المرفق.

## المعاينة
المشروع أداة طرفية ولا يحتوي واجهة رسومية. يمكن استخدام مثال المخرجات في القسم الإنجليزي كمرجع، أو التقاط صورة للشاشة بعد تشغيل الأمر على ملف manifest تجريبي.

## الأمان والخصوصية
تقرأ الأداة ملف manifest المحدد فقط. لا تقرأ ملف المتصفح الشخصي أو سجل التصفح أو الكوكيز أو كلمات المرور، ولا تتصل بالإنترنت، ولا تنفذ JavaScript الخاص بالإضافة. راجع [SECURITY.md](SECURITY.md).

## القيود
هذا تدقيق ثابت للصلاحيات وليس كاشف برمجيات خبيثة أو تدقيقًا أمنيًا كاملًا. قد تحتاج إضافة سليمة إلى صلاحيات قوية، وقد يحتوي مشروع قليل الصلاحيات على كود غير آمن. لا يتم تحليل JavaScript أو الخدمات البعيدة أو سلسلة التوريد أو سمعة متجر الإضافات، كما أن دلالات صلاحيات المتصفحات قد تتغير مع الوقت.

## تطوير اختياري مستقبلًا
يمكن مستقبلًا إضافة دلالات خاصة بـFirefox وسياسات مؤسسات قابلة للتخصيص وتحليل أعمق لتعريفات content scripts. هذه أفكار مستقبلية وليست ميزات حالية.

## المساهمة
راجع [CONTRIBUTING.md](CONTRIBUTING.md). يجب إضافة اختبارات للتغييرات والحفاظ على التحليل المحلي القابل للتفسير.

## الترخيص
MIT — راجع [LICENSE](LICENSE).

## المؤلف
**Radwan Abdulhadi Ahmed**  
**رضوان عبدالهادي أحمد**  
GitHub: [@rad03i2](https://github.com/rad03i2)
