# Schema versioning and compatibility

`tatar-schema-v1.json` is the published contract for `scan-result.json`:
adopters commit one as a baseline, CI gates read it, and downstream tooling
parses it. This file says what consumers may rely on, and what a change to the
schema obliges us to do.

Монголоор: доод хэсгийг үзнэ үү.

## What `schema_version` covers

**One version for the whole document.** `schema_version` at the root covers
every part of it — `metadata`, `summary` and `findings` alike. There is no
separate version for the findings array.

This was a deliberate decision, not an omission. A second version number
(`findings_schema_version`) was considered for SIEM/SOAR consumers that read
only the findings. It is not worth it:

- A finding does not travel alone. It carries `canonical_control`, which only
  means something against the registry named in `metadata`, and a severity
  whose weighting is explained by `summary`. Versioning the array apart from
  its context lets the two drift while both claim to be current.
- Two numbers have to be kept in step by a human. One of them will be wrong
  eventually, and a version field that lies is worse than no version field —
  that is the same failure this project keeps finding in itself.
- A consumer that reads only findings can still check one number. It gains
  nothing from a second one.

If a consumer ever genuinely needs to accept new `metadata` while refusing new
finding shapes, that is the evidence to revisit this. Until someone asks, one
number stays.

## What counts as a breaking change

Breaking, and requires `tatar-schema-v2.json` plus a bump of `schema_version`:

- **Removing a property**, or renaming one.
- **Adding to any `required` list.** A document that was valid yesterday must
  stay valid today. This is the one that is easy to do by accident, so
  `compat_test.go` freezes every `required` list and fails when one grows.
- **Narrowing a type or an enum** — dropping a value, tightening a pattern.
- **Changing the meaning of a field** while keeping its name and type. A
  consumer cannot detect this, which makes it the most damaging kind.

Not breaking, and allowed inside v1:

- **Adding an optional property.** `confidence_reason` was added this way: a
  reader that does not know it ignores it, and `omitempty` keeps it out of
  documents that have nothing to say.
- **Adding a value to an enum**, when consumers are expected to tolerate
  unknown values (severity is not such an enum; `confidence_reason` is).
- **Documentation, descriptions, examples.**

## What a v2 would have to do

Writing v2 is not just copying the file:

1. `pkg/schema/tatar-schema-v2.json` is added. **v1 stays, unedited** —
   documents already in someone's git history still have to validate.
2. `schema_version` in the output becomes `2`.
3. The reader accepts both for at least one minor release, and
   `scan-result.json` files at v1 keep working with `diff`, `gate` and
   `report`. A baseline a team committed six months ago is exactly the case
   `gate --baseline` exists to serve.
4. `docs/01_Unified-Schema-JSON-v1.docx` gains the v2 section, and the pair
   check (`scripts/docs.sh --check`) keeps the `.md` in step.
5. The release notes say what moved and what a consumer has to change.

No v2 exists today, and none is planned: everything added since v1.0.0 has
been an optional property.

---

# Монгол хэл дээр

`tatar-schema-v1.json` нь `scan-result.json`-ы **нийтлэгдсэн гэрээ**.

**Нэг хувилбар бүх баримтыг хамарна.** Үндэс дэх `schema_version` нь
`metadata`, `summary`, `findings` гурвуулыг хамарна. Findings-д тусдаа
хувилбар **байхгүй**, бас зориуд байхгүй:

- Finding дангаараа явдаггүй: `canonical_control` нь `metadata`-д нэрлэгдсэн
  registry-тэй тулгаж байж утгатай, severity-гийн жин нь `summary`-д
  тайлбарлагдана. Тусад нь хувилбарлавал хоёулаа "хамгийн сүүлийнх" гэж
  зарласаар зөрнө.
- Хоёр тоог хүн гараар зэрэгцүүлнэ. Аль нэг нь эрт орой хожуу буруу болно,
  **худал хэлдэг хувилбарын талбар** нь огт байхгүйгээс дор.

**Эвддэг өөрчлөлт** (v2 шаардана): талбар хасах/нэр солих; `required`-д
нэмэх; төрөл/enum нарийсгах; нэр нь хэвээр атлаа утга нь өөрчлөгдөх.

**Эвддэггүй** (v1 дотор зөвшөөрнө): нэмэлт сонголттой талбар
(`confidence_reason` ингэж орсон); enum-д утга нэмэх (хэрэглэгч танихгүй
утгыг тэвчихээр бол); баримт, тайлбар, жишээ.

`required`-д санамсаргүй нэмэх нь хамгийн амархан алдаа тул `compat_test.go`
бүх `required` жагсаалтыг царцааж, нэмэгдвэл тест унана.