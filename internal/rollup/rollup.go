// Package rollup — Pod хэмжээнд тайлагдсан finding-ийг түүнийг эзэмшдэг
// controller (Deployment/StatefulSet/DaemonSet/Job/CronJob/ReplicaSet) руу зөөнө.
//
// ЯАГААД ХЭРЭГТЭЙ. Scanner-ууд нэг л асуудлыг өөр өөр объектын хэмжээнд
// тайлагнадаг:
//   - Trivy k8s ба Kubescape нь WORKLOAD-ыг (deployment/api) шалгана.
//   - Popeye нь `deployments` ба `pods` linter-ээ ТУС ТУСАД ажиллуулдаг тул
//     нэг асуудлыг хоёр удаа гаргана; мөн зарим шалгалт (network policy,
//     default ServiceAccount) нь зөвхөн pod хэмжээнд гарна.
//
// Ингэснээр pod template-ийн НЭГ зөрчил хоёр finding болж, finding-ийн тоо ба
// эрсдэлийн оноог хөөрөгддөг. Мөн 5 replica-тай deployment-ийн pod-ууд ижил
// асуудлыг 5 удаа тайлагнана.
//
// ЯАГААД ТААМАГЛАЛ БИШ. Бид cluster-т холбогддоггүй тул ownerReferences-ыг
// уншиж чадахгүй (kubescape-ийн raw ч түүнийг агуулдаггүй). Тиймээс зөвхөн
// дараах ХАТУУ нөхцөл бүрэн хангагдсан үед зөөнө:
//
//  1. Тухайн canonical control-д ЯГ ТЭР scan дотор controller хэмжээний finding
//     аль хэдийн байгаа (объектыг зохиохгүй — байгааг л ашиглана).
//  2. Controller нь pod-той ИЖИЛ namespace-д байна.
//  3. Pod-ийн нэр нь controller-ийн нэрээр эхэлж, үлдэх хэсэг нь Kubernetes-ийн
//     ҮҮСГЭСЭН дагавартай таарна (`-<hash>`, `-<rs-hash>-<pod-hash>`, `-<ordinal>`).
//     Тиймээс "api" нь "api-gateway-7d9f8-abcde"-ийг эзэмшихгүй: үлдэх
//     "-gateway-7d9f8-abcde" нь дагаварын хэв маягт таарахгүй.
//  4. Хэд хэдэн controller тохирвол нэр нь ХАМГИЙН УРТ нь сонгогдоно.
//
// Юу ч АЛДАГДАХГҮЙ: зөөгдсөн pod бүр evidence-д `pod/<нэр>` болж бичигдэнэ, мөн
// зөөлтийн тоо metadata.rollup-д гарч тайланд шалгагдах боломжтой болно.
package rollup

import (
	"regexp"
	"sort"
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// controllerKinds — pod эзэмшиж болох workload төрлүүд (жижиг үсгээр,
// resource нь "kind/name" хэлбэртэй).
var controllerKinds = map[string]bool{
	"deployment": true, "statefulset": true, "daemonset": true,
	"job": true, "cronjob": true, "replicaset": true, "replicationcontroller": true,
}

// generatedSuffix — Kubernetes-ийн pod-д өгдөг дагавар:
//
//	ReplicaSet-ээс:  -<rs-hash>-<pod-suffix>   ж: -598c4dc6b8-ldjqq
//	DaemonSet/Job:   -<hash>                   ж: -7d9f8
//	StatefulSet:     -<ordinal>                ж: -0, -12
//
// ГОЛ ШАЛГУУР: K8s-ийн үүсгэсэн санамсаргүй дагавар нь `rand.SafeEncodeString`-ийн
// ЭГШИГГҮЙ алфавитыг (bcdfghjklmnpqrstvwxz2456789) хэрэглэдэг — санамсаргүй үг
// үүсэхээс сэргийлэхийн тулд a/e/i/o/u/y ба 0/1/3 байхгүй. Тиймээс "api-canary"
// нь "api"-ийн pod БИШ ("canary"-д a, y бий), харин "api-598c4dc6b8-ldjqq" бол
// pod юм. Энэ нь "хэш шиг харагдах" гэсэн таамгийн оронд бодит шалгуур болно.
//
// Хатуу байлгасан шалтгаан: зөөлт алдвал зөвхөн тоо давхардана (харагдана,
// хор хөнөөлгүй); БУРУУ зөөвөл finding өөр объектод хамааруулагдана (аудитын
// алдаа). Тиймээс эргэлзвэл зөөхгүй.
const safeSeg = `[bcdfghjklmnpqrstvwxz2456789]`

var generatedSuffix = regexp.MustCompile(`^-(?:\d+|` + safeSeg + `{5,10})(?:-` + safeSeg + `{5})?$`)

// Result — зөөлтийн хураангуй (аудитад ил гаргана).
type Result struct {
	// Moved — controller руу зөөгдсөн pod-scoped finding-ийн тоо.
	Moved int `json:"moved"`
	// Pods — зөөгдсөн өвөрмөц pod-ууд (эрэмбэлсэн).
	Pods []string `json:"pods,omitempty"`
}

func splitResource(r string) (kind, name string) {
	if i := strings.Index(r, "/"); i >= 0 {
		return r[:i], r[i+1:]
	}
	return "", r
}

// Apply — Pod хэмжээний finding-үүдийг боломжтой бол controller руу зөөнө.
// dedup-аас ӨМНӨ дуудагдана: зөөсний дараа dedup нь ижил түлхүүртэй болсон
// finding-үүдийг (found_by, evidence-ийг нэгтгэн) нэг болгоно.
func Apply(fs []finding.Finding) ([]finding.Finding, Result) {
	// 1) canonical control + namespace тус бүрээр controller-ийн нэрсийг цуглуулна.
	type key struct{ ctrl, ns string }
	ctrlNames := map[key][]string{} // (control, ns) -> controller resource-ууд
	for _, f := range fs {
		kind, _ := splitResource(f.Resource)
		if controllerKinds[kind] {
			k := key{f.CanonicalControl, f.Namespace}
			ctrlNames[k] = append(ctrlNames[k], f.Resource)
		}
	}
	if len(ctrlNames) == 0 {
		return fs, Result{}
	}
	// Урт нэр эхэлж таарахын тулд эрэмбэлнэ (api-gateway нь api-аас өмнө).
	for k := range ctrlNames {
		names := ctrlNames[k]
		sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	}

	out := make([]finding.Finding, len(fs))
	copy(out, fs)
	res := Result{}
	seenPods := map[string]bool{}

	for i := range out {
		f := &out[i]
		kind, podName := splitResource(f.Resource)
		if kind != "pod" {
			continue
		}
		owner := findOwner(ctrlNames[key{f.CanonicalControl, f.Namespace}], podName)
		if owner == "" {
			continue
		}
		// Pod-ийн онцлогийг нотолгоонд хадгална — юу ч нуугдахгүй.
		f.Evidence = append(f.Evidence, finding.Evidence{
			Scanner: firstScanner(f.FoundBy),
			Path:    f.Resource,
			Detail:  "rolled up to " + owner,
		})
		f.Resource = owner
		f.ID = finding.StableID(f.CanonicalControl, f.Resource, f.Namespace)
		res.Moved++
		if !seenPods[podName] {
			seenPods[podName] = true
			res.Pods = append(res.Pods, podName)
		}
	}
	sort.Strings(res.Pods)
	return out, res
}

// findOwner — pod нэрийг эзэмших controller resource-ыг (kind/name) буцаана.
// Тохирохгүй бол "" (зөөхгүй).
func findOwner(candidates []string, podName string) string {
	for _, c := range candidates {
		_, cname := splitResource(c)
		if cname == "" || !strings.HasPrefix(podName, cname) {
			continue
		}
		rest := podName[len(cname):]
		if rest == "" {
			continue // pod ба controller ижил нэртэй — эзэмшил гэж үзэхгүй
		}
		if generatedSuffix.MatchString(rest) {
			return c
		}
	}
	return ""
}

func firstScanner(fb []string) string {
	if len(fb) > 0 {
		return fb[0]
	}
	return ""
}
