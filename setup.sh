#!/usr/bin/env bash
# One-command Path 2 setup. Creates the cluster, installs Calico, builds and
# loads images, applies all seven namespaces, and verifies isolation.
# No manual mkdir, no missing files. Run from the pcm-mcp/ directory.
set -euo pipefail
CL=pcm-mcp

echo "==> 1/6 create kind cluster (Calico CNI for NetworkPolicy)"
kind create cluster --name $CL --config k8s/kind-config.yaml
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml
kubectl -n kube-system wait --for=condition=Ready pod -l k8s-app=calico-node --timeout=300s

echo "==> 2/6 build images"
docker build -t pcm-mcp/engine:dev  -f docker/Dockerfile.engine  .
docker build -t pcm-mcp/servers:dev -f docker/Dockerfile.servers .

echo "==> 3/6 load images into cluster"
kind load docker-image pcm-mcp/engine:dev  --name $CL
kind load docker-image pcm-mcp/servers:dev --name $CL

echo "==> 4/6 apply manifests (7 namespaces)"
kubectl apply -f k8s/00-namespaces.yaml
kubectl apply -f k8s/10-rbac.yaml
kubectl apply -f k8s/20-config.yaml
kubectl apply -f k8s/30-deployments.yaml
kubectl apply -f k8s/40-networkpolicies.yaml

echo "==> 5/6 wait for pods"
kubectl wait --for=condition=Available deploy --all -A --timeout=300s

echo "==> 6/6 verify isolation"
bash k8s/verify-isolation.sh

echo
echo "Ready. Run the three attacks (each prints a per-introspection-point trace):"
echo "  bash k8s/run-workload-job.sh A A2     # \$500 substitution  -> IP-5"
echo "  bash k8s/run-workload-job.sh B B1     # quiet injection    -> IP-5"
echo "  bash k8s/run-workload-job.sh C C1     # economic DoS       -> IP-4"
echo "  bash k8s/run-workload-job.sh A null   # benign, completes"
