package chaos

import "fmt"

// GenerateLitmusYAML returns a minimal, ready-to-apply Litmus ChaosEngine
// YAML string for the given experiment type, namespace, and service name.
//
// The YAML targets a Deployment whose pod label is "app=<service>".
// Users apply it with: kubectl apply -f - <<< '<yaml>'
func GenerateLitmusYAML(experiment, namespace, service string) string {
	switch experiment {
	case "pod-kill":
		return podKillYAML(namespace, service)
	case "network-partition":
		return networkPartitionYAML(namespace, service)
	case "cpu-stress":
		return cpuStressYAML(namespace, service)
	case "memory-pressure":
		return memoryPressureYAML(namespace, service)
	default:
		return podKillYAML(namespace, service)
	}
}

func podKillYAML(namespace, service string) string {
	return fmt.Sprintf(`apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: %s-pod-kill
  namespace: %s
spec:
  appinfo:
    appns: %s
    applabel: app=%s
    appkind: deployment
  chaosServiceAccount: litmus-admin
  experiments:
    - name: pod-delete
      spec:
        components:
          env:
            - name: TOTAL_CHAOS_DURATION
              value: "30"
            - name: CHAOS_INTERVAL
              value: "10"
            - name: FORCE
              value: "false"
`, service, namespace, namespace, service)
}

func networkPartitionYAML(namespace, service string) string {
	return fmt.Sprintf(`apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: %s-network-partition
  namespace: %s
spec:
  appinfo:
    appns: %s
    applabel: app=%s
    appkind: deployment
  chaosServiceAccount: litmus-admin
  experiments:
    - name: pod-network-loss
      spec:
        components:
          env:
            - name: TOTAL_CHAOS_DURATION
              value: "60"
            - name: NETWORK_PACKET_LOSS_PERCENTAGE
              value: "100"
            - name: CONTAINER_RUNTIME
              value: "containerd"
            - name: SOCKET_PATH
              value: "/run/containerd/containerd.sock"
`, service, namespace, namespace, service)
}

func cpuStressYAML(namespace, service string) string {
	return fmt.Sprintf(`apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: %s-cpu-stress
  namespace: %s
spec:
  appinfo:
    appns: %s
    applabel: app=%s
    appkind: deployment
  chaosServiceAccount: litmus-admin
  experiments:
    - name: pod-cpu-hog
      spec:
        components:
          env:
            - name: TOTAL_CHAOS_DURATION
              value: "60"
            - name: CPU_CORES
              value: "1"
            - name: CPU_LOAD
              value: "100"
`, service, namespace, namespace, service)
}

func memoryPressureYAML(namespace, service string) string {
	return fmt.Sprintf(`apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: %s-memory-pressure
  namespace: %s
spec:
  appinfo:
    appns: %s
    applabel: app=%s
    appkind: deployment
  chaosServiceAccount: litmus-admin
  experiments:
    - name: pod-memory-hog
      spec:
        components:
          env:
            - name: TOTAL_CHAOS_DURATION
              value: "60"
            - name: MEMORY_CONSUMPTION
              value: "500"
`, service, namespace, namespace, service)
}
