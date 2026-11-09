package audit

// labels — аудитын тайлангийн бүх бичвэр. Нэг газар, хоёр хэлээр: if/else-ээр
// тараавал хоёр хэл чимээгүй зөрнө (HTML dashboard дээр аль хэдийн тохиолдсон).
type labels struct {
	DocTitle, Subtitle, Confidential                      string
	Cluster, Generated, Mode, Tool, Hash, Lang            string
	SecScope, SecCoverage, SecScore, SecAttest, SecFind   string
	SecAppendix, SecMethod                                string
	ScopeBody, MethodBody                                 string
	NotScanner                                            string
	Scanner, Status, Version, Normalized, Unmapped, Dur   string
	CoverageBody, CoverageNone                            string
	ScoreBody, Formula, Penalty, Band, Score, Contributor string
	Share, AttestBody, AttestNone                         string
	Control, Decision, Rationale, By, On, Until, Evidence string
	Expired, Active, ScopeCol                             string
	FindBody, Resource, Severity, FoundBy, Confidence     string
	Why, Fix, Refs, Downgraded, Attack, NoFindings        string
	Total, Inventory, Rollup, Page, Of                    string
	Decisions                                             map[string]string
	Statuses                                              map[string]string
	Reasons                                               map[string]string
}

var labelsEN = labels{
	DocTitle:     "Kubernetes Security Posture — Audit Report",
	Subtitle:     "Consolidated findings from four independent scanners, reconciled to one canonical control set",
	Confidential: "Contains the security weaknesses of a live cluster. Handle accordingly.",
	Cluster:      "Cluster",
	Generated:    "Generated",
	Mode:         "Scan mode",
	Tool:         "Tool version",
	Hash:         "Result hash",
	Lang:         "Language",
	SecScope:     "1. Scope",
	SecMethod:    "2. Method",
	SecCoverage:  "3. What ran — and what did not",
	SecScore:     "4. Risk score, and how it was derived",
	SecAttest:    "5. Manually attested controls",
	SecFind:      "6. Findings",
	SecAppendix:  "Appendix",
	ScopeBody:    "This assessment covers Kubernetes configuration and posture: workload and pod security, RBAC, network policy, image vulnerabilities, and infrastructure-as-code. It does NOT cover runtime threat detection, network traffic analysis, application-layer testing, or any control outside the cluster. Nothing in this report is evidence that an attack occurred; every item is a weakness that could be used.",
	MethodBody:   "Four independent open-source scanners were run or ingested. Each scanner's rule IDs were mapped to a single canonical control set, so one misconfiguration reported by three tools appears once, with all three recorded as evidence. Severity is taken from the curated control registry, not from whichever tool shouted loudest. Pod-level findings were rolled up to their owning controller so one misconfiguration is counted once.",
	NotScanner:   "TATAR-Kuber does not scan. It orchestrates scanners and reconciles their output into one accountable result.",
	Scanner:      "Scanner",
	Status:       "Status",
	Version:      "Version",
	Normalized:   "Findings",
	Unmapped:     "Unmapped rules",
	Dur:          "Duration",
	CoverageBody: "A scanner that failed to install, crashed or was skipped must never produce output that reads as a clean result. The table below is the honest record of what actually ran. Where a scanner contributed nothing, that is stated rather than absorbed into the totals.",
	CoverageNone: "No per-scanner record was written for this scan.",
	ScoreBody:    "The score is a published formula over the findings, not a verdict. It can be recomputed from this report.",
	Formula:      "Formula",
	Penalty:      "Total penalty",
	Band:         "Band",
	Score:        "Score",
	Contributor:  "Largest contributors",
	Share:        "Share",
	AttestBody:   "Controls that no scanner can check are answered by a named person, with a reason and an expiry. An expired attestation counts as unchecked again — it is listed here as expired rather than quietly dropped.",
	AttestNone:   "No manual attestation was recorded for this scan.",
	Control:      "Control",
	Decision:     "Decision",
	Rationale:    "Rationale",
	By:           "Attested by",
	On:           "Attested on",
	Until:        "Expires",
	Evidence:     "Evidence",
	Expired:      "EXPIRED — counts as unchecked",
	Active:       "active",
	ScopeCol:     "Scope",
	FindBody:     "Findings are grouped by canonical control. Each carries the scanners that reported it, a confidence grade with the reason for that grade, and the remediation from the control registry.",
	Resource:     "Resource",
	Severity:     "Severity",
	FoundBy:      "Found by",
	Confidence:   "Confidence",
	Why:          "Why it matters",
	Fix:          "Remediation",
	Refs:         "References",
	Downgraded:   "Context-downgraded",
	Attack:       "May enable",
	NoFindings:   "No findings.",
	Total:        "Total findings",
	Inventory:    "Cluster inventory",
	Rollup:       "Pod rollup",
	Page:         "Page",
	Of:           "of",
	Decisions:    map[string]string{"compliant": "Compliant", "non-compliant": "NON-COMPLIANT", "not-applicable": "Not applicable"},
	Statuses:     map[string]string{"ok": "ran", "ingested": "ingested from raw output", "unavailable": "NOT INSTALLED — contributed nothing", "unsupported": "unsupported in this mode", "error": "FAILED", "timeout": "TIMED OUT", "parse_error": "OUTPUT UNREADABLE"},
	Reasons:      map[string]string{"corroborated": "two or more scanners agreed", "single-scanner": "one scanner, deterministic check", "single-scanner-heuristic": "one scanner, heuristic — context dependent", "unattributed": "no scanner attributed"},
}

var labelsMN = labels{
	DocTitle:     "Kubernetes-ийн аюулгүй байдлын төлөв — аудитын тайлан",
	Subtitle:     "Дөрвөн бие даасан хэрэгслийн олдворыг нэг canonical хяналтын багцад нэгтгэв",
	Confidential: "Амьд кластерын сул талуудыг агуулна. Зохих ёсоор нь хадгална уу.",
	Cluster:      "Кластер",
	Generated:    "Үүсгэсэн",
	Mode:         "Шалгалтын горим",
	Tool:         "Хэрэгслийн хувилбар",
	Hash:         "Үр дүнгийн hash",
	Lang:         "Хэл",
	SecScope:     "1. Хамрах хүрээ",
	SecMethod:    "2. Арга зүй",
	SecCoverage:  "3. Юу ажилласан — юу ажиллаагүй",
	SecScore:     "4. Эрсдэлийн оноо ба түүний гарал",
	SecAttest:    "5. Гараар баталсан хяналтууд",
	SecFind:      "6. Олдворууд",
	SecAppendix:  "Хавсралт",
	ScopeBody:    "Энэхүү үнэлгээ нь Kubernetes-ийн тохиргоо, аюулгүй байдлын төлвийг хамарна: ажлын ачаалал ба pod-ын аюулгүй байдал, RBAC, сүлжээний бодлого, image-ийн эмзэг байдал, infrastructure-as-code. Ажиллах үеийн халдлага илрүүлэлт, сүлжээний урсгалын шинжилгээ, аппликейшн түвшний тест, мөн кластераас гадуурх ямар ч хяналтыг хамрахгүй. Энэ тайланд буй зүйлсийн аль нь ч халдлага болсны нотолгоо БИШ — бүгд нь ашиглагдаж болзошгүй сул тал юм.",
	MethodBody:   "Дөрвөн бие даасан нээлттэй эхийн хэрэгслийг ажиллуулсан эсвэл тэдний гаралтыг уншсан. Хэрэгсэл бүрийн rule ID-г нэг canonical хяналтын багцад буулгасан тул гурван хэрэгслийн мэдээлсэн нэг зөрчил НЭГ удаа гарч, гурвуулаа нотолгоо болон бүртгэгдэнэ. Severity нь хамгийн чанга дуугарсан хэрэгслээс биш, сонгон бүрдүүлсэн хяналтын бүртгэлээс авагдана. Pod түвшний олдворыг эзэмшигч controller руу зөөсөн тул нэг зөрчил нэг удаа тоологдоно.",
	NotScanner:   "TATAR-Kuber нь өөрөө scan хийдэггүй. Scanner-уудыг зохицуулж, тэдний гаралтыг нэг хариуцлагатай үр дүн болгон эвлүүлдэг.",
	Scanner:      "Хэрэгсэл",
	Status:       "Төлөв",
	Version:      "Хувилбар",
	Normalized:   "Олдвор",
	Unmapped:     "Зураглалгүй rule",
	Dur:          "Хугацаа",
	CoverageBody: "Суулгаж чадаагүй, унасан, эсвэл алгассан scanner нь цэвэр үр дүн мэт уншигдах гаралт ХЭЗЭЭ Ч өгч болохгүй. Доорх хүснэгт бол юу бодитоор ажилласны шударга бүртгэл. Хэрэгсэл юу ч оруулаагүй бол тэр нь нийт тоонд уусахгүй, ил бичигдэнэ.",
	CoverageNone: "Энэ шалгалтад scanner тус бүрийн бүртгэл үлдээгүй.",
	ScoreBody:    "Оноо бол дээрээс буусан шийдвэр биш, олдворууд дээрх нийтлэгдсэн томьёо. Энэ тайлангаас дахин тооцож болно.",
	Formula:      "Томьёо",
	Penalty:      "Нийт penalty",
	Band:         "Зэрэглэл",
	Score:        "Оноо",
	Contributor:  "Хамгийн их хувь нэмэр оруулсан",
	Share:        "Эзлэх хувь",
	AttestBody:   "Ямар ч scanner шалгаж чадахгүй хяналтуудад нэр бүхий хүн үндэслэл, хугацаатайгаар хариулсан. Хугацаа дууссан баталгаа нь дахин шалгагдаагүйд тооцогдоно — чимээгүй хаягдахгүй, энд дууссан гэж бичигдэнэ.",
	AttestNone:   "Энэ шалгалтад гараар баталсан бүртгэл алга.",
	Control:      "Хяналт",
	Decision:     "Шийдвэр",
	Rationale:    "Үндэслэл",
	By:           "Баталсан",
	On:           "Огноо",
	Until:        "Хүчинтэй хугацаа",
	Evidence:     "Нотолгоо",
	Expired:      "ХУГАЦАА ДУУССАН — шалгагдаагүйд тооцогдоно",
	Active:       "хүчинтэй",
	ScopeCol:     "Хамрах хүрээ",
	FindBody:     "Олдворуудыг canonical хяналтаар бүлэглэв. Тус бүр нь аль scanner мэдээлсэн, итгэлцлийн зэрэг ба ТҮҮНИЙ ШАЛТГААН, мөн хяналтын бүртгэл дэх засах арга хэмжээг агуулна.",
	Resource:     "Объект",
	Severity:     "Ноцтой байдал",
	FoundBy:      "Илрүүлсэн",
	Confidence:   "Итгэлцэл",
	Why:          "Яагаад чухал вэ",
	Fix:          "Засах арга хэмжээ",
	Refs:         "Эх сурвалж",
	Downgraded:   "Контекстээр бууруулсан",
	Attack:       "Боломжтой болгож болзошгүй",
	NoFindings:   "Олдвор алга.",
	Total:        "Нийт олдвор",
	Inventory:    "Кластерын бүрэлдэхүүн",
	Rollup:       "Pod зөөлт",
	Page:         "Хуудас",
	Of:           "/",
	Decisions:    map[string]string{"compliant": "Хангасан", "non-compliant": "ХАНГААГҮЙ", "not-applicable": "Хамаарахгүй"},
	Statuses:     map[string]string{"ok": "ажилласан", "ingested": "түүхий гаралтаас уншсан", "unavailable": "СУУГААГҮЙ — юу ч оруулаагүй", "unsupported": "энэ горимд дэмжигдэхгүй", "error": "УНАСАН", "timeout": "ХУГАЦАА ХЭТЭРСЭН", "parse_error": "ГАРАЛТ УНШИГДАХГҮЙ"},
	Reasons:      map[string]string{"corroborated": "хоёр ба түүнээс олон scanner санал нийлсэн", "single-scanner": "нэг scanner, шууд шалгалт", "single-scanner-heuristic": "нэг scanner, эвристик — контекстээс хамаарна", "unattributed": "scanner холбогдоогүй"},
}

func pick(lang string) labels {
	if lang == "mn" {
		return labelsMN
	}
	return labelsEN
}
