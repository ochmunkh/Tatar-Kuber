# TATAR-Kuber

> Kubernetes Security Posture Assessment Framework  
> Engineering Document #3  
> Scanner Adapter Interface  
> Scanner-agnostic orchestration контракт  
> Version 1.2  ·  кодтой тулгасан (2026-09-07)  
> Enkhbat.O — Security Analyst  
> 2026-07-24

<!-- Generated from 03_Scanner-Adapter-Interface.docx by scripts/docx-to-md.py -- do not edit by hand. -->
*Generated from `03_Scanner-Adapter-Interface.docx`. The Word document is canonical; regenerate with `python3 scripts/docx-to-md.py docs/03_Scanner-Adapter-Interface.docx`.*

## 1. Зорилго

TATAR-Kuber өөрөө scanner биш — orchestrator юм. Scanner бүр нэг ижил Go interface (ScannerAdapter) хэрэгжүүлдэг. Ингэснээр цөм (core) нь тодорхой scanner-ийг мэдэхгүйгээр ажиллаж, шинэ scanner нэмэх нь зөвхөн шинэ adapter бичихэд хүрдэг. Энэ баримт нь тухайн контрактыг тодорхойлно.

## 2. ScannerAdapter interface

```go
package scanner

type Mode string
const ( ModeLocal Mode = "local"; ModeRemote Mode = "remote" )

type Target struct {
    Mode        Mode      // local | remote
    Path        string    // -f ./k8s/ (local)
    Kubeconfig  string    // remote
    Context     string    // --context production
    Namespaces  []string  // хязгаарлах (сонголт)
    Timeout     time.Duration
}

type RawResult struct {
    Scanner   string    // "trivy"
    Version   string    // "0.53.0"
    Format    string    // "json" | "sarif"
    Data      []byte    // raw гаралт (~/.tatar-kuber/raw/-д хадгалагдана)
    ExitCode  int
    Duration  time.Duration
}

type ScannerAdapter interface {
    Name() string                                   // "trivy"
    Available() (bool, error)                       // binary олдох, ажиллах уу
    Version(ctx context.Context) (string, error)    // audit-д бичигдэнэ
    Supports(mode Mode) bool                        // ЗӨВХӨН бодитоор дэмждэгээ буцаана
    Scan(ctx context.Context, t Target) (RawResult, error)
    Normalize(raw RawResult) ([]schema.Finding, error)
}
```

## 3. Adapter-ийн амьдралын мөчлөг

Orchestrator adapter бүрийг дараах дарааллаар дуудна:

| **Алхам** | **Метод** | **Тайлбар** |
|---|---|---|
| 1. Илрүүлэх | Available() | Binary байгаа, PATH/tools/-д олдох, ажиллах эсэхийг шалгана. Байхгүй бол scanner-ыг алгасаж, лог/тайланд тэмдэглэнэ. |
| 2. Хувилбар | Version(ctx) | Scanner хувилбарыг авч metadata.scanner_versions-д бичнэ (аудитын давтагдах чадвар). |
| 3. Горим шалгах | Supports(mode) | Тухайн scanner горимыг БОДИТООР дэмжих эсэх. Scan нь татгалзах горимд Supports нь true буцааж БОЛОХГҮЙ — эс бөгөөс scanner_runs-д хиймэл "error" бүртгэгдэнэ. v1: Popeye ба Trivy remote-only, Checkov local-only, Kubescape хоёулаа. |
| 4. Ажиллуулах | Scan(ctx, t) | Scanner-ыг дэд процессоор ажиллуулж raw цуглуулна. Pipeline.Collect нь adapter бүрийг ЗЭРЭГ, тус бүрийг өөрийн context.WithTimeout-оор ажиллуулж, төлөв/хугацаа/алдааг ScannerRun болгон бүртгэнэ. |
| 5. Хадгалах | — | RawResult.Data-г \<out\>/raw/\<scanner\>.json болгон хадгална (нотолгоо; --raw-dir хүлээж авдаг яг тэр бүтэц, дахин боловсруулж болно). --no-raw-аар болино. |
| 6. Normalize | Normalize(raw) | Raw-г \[\]Finding болгож хөрвүүлж, canonical_control-оор баяжуулна. |

## 4. Гүйцэтгэлийн загвар

Adapter-ууд бие даасан тул зэрэгцээ (parallel) ажиллана. Orchestrator worker pool ашиглаж, scanner бүрт timeout тавина. Нэг scanner унавал бусад нь үргэлжилнэ (partial success).

```text
results := runParallel(adapters, target)   // errgroup + timeout
allFindings := []schema.Finding{}
for _, r := range results {
    if r.Err != nil {
        log.Warn("scanner failed", r.Scanner, r.Err)  // үргэлжилнэ
        report.MarkDegraded(r.Scanner)
        continue
    }
    f, _ := adapter[r.Scanner].Normalize(r.Raw)
    allFindings = append(allFindings, f...)
}
deduped := dedup.Deduplicate(allFindings)
```

## 5. Scanner тус бүрийн adapter тэмдэглэл

| **Scanner** | **Ажиллах команд (жишээ)** | **Формат** | **Горим** | **Version** |
|---|---|---|---|---|
| Trivy | trivy k8s --report all --format json \<CONTEXT\> | JSON | remote (v1). Local \`trivy config\` — v2 (доорх тэмдэглэлийг үз) | trivy --version |
| Kubescape | kubescape scan --format json --output \<dir\>/scan.json --kube-contexts \<ctx\> | JSON | local + remote | kubescape version |
| Checkov | checkov -d ./ -o json | JSON | local | checkov --version |
| Popeye | popeye -o json --kubeconfig \<path\> --context \<ctx\> | JSON | remote | popeye version |

**Тэмдэглэл:** Kubescape нь олон framework (NSA, MITRE, CIS-workload)-ийг нэг ажиллуулалтаар өгдөг тул primary posture engine. Trivy нь image CVE + config + secret-ийг барина. Checkov нь local IaC (YAML/Helm/Terraform)-д гүн. Popeye нь remote cluster-ийн ажиллагааны цэвэршилт (dead service, broken ref)-д онцгой. kube-bench нь node-level тул MVP-д БАГТААГҮЙ (Enterprise Agent).

## 6. Алдаа ба timeout

- Adapter бүр context.Context-ийг хүндэтгэж, cancel/timeout үед дэд процессоо цэвэр зогсооно.
- Scanner exit code != 0 бүр алдаа биш — олон scanner finding олдвол non-zero буцаадаг. Adapter энэ ялгааг мэдэж, зөвхөн жинхэнэ гүйцэтгэлийн алдааг error болгоно.
- Нэг scanner унах нь бүх scan-ыг унагаахгүй (graceful degradation). Тайланд degraded scanner-ыг тодорхой заана.
- Raw гаралтыг parse хийхээс өмнө хадгална — parse алдаа гарсан ч нотолгоо үлдэнэ.

## 7. Шинэ adapter нэмэх

Шинэ scanner (ж: нэмэлт RBAC хэрэгсэл) нэмэхэд: (1) internal/scanner/\<name\>/ дор ScannerAdapter-ийг хэрэгжүүлэх; (2) canonical-controls.yaml-д тухайн scanner-ийн rule mappings нэмэх; (3) adapter-ыг registry-д бүртгэх; (4) normalize unit test бичих (raw fixture → expected findings); (5) tools.lock.yaml-д binary хувилбар/checksum нэмэх. Цөмийн код өөрчлөгдөхгүй.

## Хувилбарын тэмдэглэл — v1.1 / v1.2 (2026-09-07)

- Supports() нь ГЭРЭЭ: Scan нь татгалзах горимд true буцааж болохгүй. Trivy нь Supports(local)=true буцаагаад Scan нь local-д үргэлж алдаа буцаадаг байсан тул Mode A-д хиймэл "error" бүртгэгдэж байв — одоо remote-only гэж шударгаар тайлагдана.
- Trivy-г Mode A-д дэмжих нь v2: \`trivy config \<dir\>\` ажилладаг ч гаралт нь K8s объектын нэрийг ТОДОРХОЙ талбараар өгдөггүй — зөвхөн файл:мөр ба хүний унших Message (бодит гаралтад 5 өөр хэлбэртэй). Файлын хэмжээнд тайлагнавал нэг файл дахь хэд хэдэн ижил зөрчил НЭГ finding болж нийлж дутуу тайлагнана. Зөв шийдэл нь манифестыг өөрөө уншиж объектыг тодорхойлох.
- Pipeline нь Collect (зэрэгцээ scan + ScannerRun бүртгэл) ба Process (normalize -\> dedup -\> blind-shot -\> score) хоёр болж хуваагдсан. Run() нь хоёуланг дуудна. Adapter-ийн алдаа бүр ScannerRun-д (status, duration_ms, error, unmapped_rules) бүртгэгдэж тайлангийн "Scanner coverage" хүснэгтэд гарна — graceful degradation нь ЧИМЭЭГҮЙ БАЙХ ЁСГҮЙ.
- Scanner-ийн CLI флагууд хувилбар хооронд өөрчлөгддөг тул зөрүү нь scanner_runs-д "error"/"unavailable" болж ил гарна. Илэрсэн бодит зөрүүнүүд: trivy k8s-ийн default нь --report summary (дэлгэрэнгүй JSON ирдэггүй) ба context нь positional; kubescape-ийн флаг нь --kube-contexts (олон тоо) ба fleet mode-д гаралтын файлаа scan.\<context\>.json болгож өөрөө нэрлэдэг.

(v1.2) blind_shot_rules-ийг registry ачаалахад ХАТУУ шалгана: сонгуургүй дүрэм (namespace ба resource_match хоёул хоосон) нь тухайн control-ийн бүх finding-ийг хаа сайгүй бууруулна; downgrade_to нь хүчинтэй severity байх ёстой (танигдахгүй утга нь хүчингүй severity үүсгэж эрэмбэ ба тоог эвдэнэ); reason ЗААВАЛ (аудитын мөр). Гурвуулан Load-ыг унагана.
