package k8s

// storagechain.go resolves a pod's storage path: volumes → PVC → PV →
// StorageClass, via live targeted GETs. A missing PV or StorageClass is
// recorded as a signal (unbound claim, deleted class), not an error.

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// StorageLink is one resolved pod→PVC→PV→StorageClass chain.
type StorageLink struct {
	PVCName       string
	PVCPhase      string
	Capacity      string
	AccessModes   []string
	PVName        string // "" when unbound
	PVPhase       string
	ReclaimPolicy string
	SCName        string // "" when no storageClassName
	Provisioner   string
	BindingMode   string
	SCMissing     bool // storageClassName set but the class doesn't exist
}

// storageChainForPod walks each PVC volume on the live pod through its PV and
// StorageClass.
func storageChainForPod(ctx context.Context, cs kubernetes.Interface, ns, podName string) ([]StorageLink, error) {
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", ns, podName, err)
	}
	var out []StorageLink
	for _, v := range pod.Spec.Volumes {
		if v.PersistentVolumeClaim == nil {
			continue
		}
		link := StorageLink{PVCName: v.PersistentVolumeClaim.ClaimName}
		pvc, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, link.PVCName, metav1.GetOptions{})
		if err != nil {
			link.PVCPhase = "NotFound"
			out = append(out, link)
			continue
		}
		link.PVCPhase = string(pvc.Status.Phase)
		if cap, ok := pvc.Status.Capacity["storage"]; ok {
			link.Capacity = cap.String()
		}
		for _, m := range pvc.Status.AccessModes {
			link.AccessModes = append(link.AccessModes, string(m))
		}
		if pvc.Spec.StorageClassName != nil {
			link.SCName = *pvc.Spec.StorageClassName
		}
		if pvc.Spec.VolumeName != "" {
			link.PVName = pvc.Spec.VolumeName
			if pv, err := cs.CoreV1().PersistentVolumes().Get(ctx, link.PVName, metav1.GetOptions{}); err == nil {
				link.PVPhase = string(pv.Status.Phase)
				link.ReclaimPolicy = string(pv.Spec.PersistentVolumeReclaimPolicy)
				if link.SCName == "" {
					link.SCName = pv.Spec.StorageClassName
				}
			}
		}
		if link.SCName != "" {
			if sc, err := cs.StorageV1().StorageClasses().Get(ctx, link.SCName, metav1.GetOptions{}); err == nil {
				link.Provisioner = sc.Provisioner
				if sc.VolumeBindingMode != nil {
					link.BindingMode = string(*sc.VolumeBindingMode)
				}
			} else {
				link.SCMissing = true
			}
		}
		out = append(out, link)
	}
	return out, nil
}

// gatherStorageChain is the planner-facing wrapper for the pod's storage path.
func gatherStorageChain(ctx context.Context, cs kubernetes.Interface, ns, name string) ([]plugin.InvestigationStep, []plugin.EvidenceItem) {
	if cs == nil || name == "" {
		return []plugin.InvestigationStep{step("Storage chain inspected", "unavailable", "no live cluster connection", "")}, nil
	}
	links, err := storageChainForPod(ctx, cs, ns, name)
	if err != nil {
		return []plugin.InvestigationStep{step("Storage chain inspected", "unavailable", "pod fetch failed", "")}, nil
	}
	if len(links) == 0 {
		return []plugin.InvestigationStep{step("Storage chain inspected", "done", "pod mounts no PersistentVolumeClaims", "")}, nil
	}
	var evid []plugin.EvidenceItem
	for _, l := range links {
		txt := fmt.Sprintf("pvc/%s phase=%s capacity=%s", l.PVCName, l.PVCPhase, l.Capacity)
		if l.PVName != "" {
			txt += fmt.Sprintf(" → pv/%s phase=%s reclaim=%s", l.PVName, l.PVPhase, l.ReclaimPolicy)
		} else {
			txt += " → UNBOUND (no PersistentVolume)"
		}
		if l.SCName != "" {
			if l.SCMissing {
				txt += fmt.Sprintf(" → storageclass/%s MISSING", l.SCName)
			} else {
				txt += fmt.Sprintf(" → storageclass/%s provisioner=%s binding=%s", l.SCName, l.Provisioner, l.BindingMode)
			}
		}
		evid = append(evid, plugin.EvidenceItem{
			Kind: "topology", Source: "pvc/" + l.PVCName, Edge: "pod→pvc→pv→storageclass",
			Excerpt: txt,
			Anchor:  "kubectl describe pvc " + l.PVCName + " -n " + ns,
		})
	}
	return []plugin.InvestigationStep{step("Storage chain inspected", "done", fmt.Sprintf("%d PVC(s) mounted", len(links)), "")}, evid
}
