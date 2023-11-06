Deploying the container measurement tool in a kube cluster
===

What is this?
---

This is a small utility that deploys the IMA container measurement tool in a kube cluster.

* A `Dockerfile` is provided to build a container image with the source
  code and a proper Fedora environment for building the image.

* The `Dockerfile` also contains a `run` script that attempts to fix
  up the Fedora environment to match the host kernel running the
  container, compile the measurement tool kprobe and ebpf probes, and
  starts them.

* A Kubernetes daemon set definition is provided to load the docker
  image on every worker node in a kube cluster.

* A `Makefile` is provided to drive the building, publishing and
  deployment of the container measurement tool.


Prerequisites
---

Instructions below refer to building and deploying the container meter
image on a kubernetes cluster.  First, you need to make sure that your
kube cluster is capable of deploying this container.

* Only tested on kube clusters where hosts (hypervisors) are running
  the Fedora 38 OS with a 6.2 kernel.

* Since we are extending IMA, the hosts no the kubernetes cluster have
  to be provided with functional TPM devices. To test this, check for
  TPM devices on the kernel log: `dmesg | grep -i tpm`.

* Please make sure that the hosts in question are *not* secure
  booted. We don't yet have any mechanisms that allow this technology
  to deploy on hardened kernels.

Howto
---

* To build the `containermeter` docker image, type

```
make build REPO=<address of your fork> BRANCH=<your branch>
```

The default value for `REPO` is
`https://github.com/avery-blanchard/container-integrity-measurement`.
The default value for `BRANCH` is `ebpf`.

* To publish the docker image, type

```
make publish REGISTRY=<docker registry address> TAG=<preferred image tag>
```

There are no reasonable defaults for the registry and tag at this
point. Use a local registry to build and deploy. There are no
published images yet.

* To deploy the docker image on a kubernetes cluster, first make sure
  that you can talk to the cluster with `kubectl`. Then type

```
make deploy REGISTRY=... TAG=...
```

This deploys a simple no-frills daemon set. The containers in the
daemon set are all privileged, since they need to insert kernel
modules.

What to look for post-deployment
---

* The daemon set deploys in the default namespace on the kubernetes worker nodes

* On any host where the `containermeter` container deploys
  successfully the kprobe is inserted into the kernel and the ebpf
  probe is started.

```
galmasi@css-hermes1:~/BLA/container-integrity-measurement/deploy$ oc logs containermeter-46rnh
Installing kernel dev pack to match host kernel
Compiling container-ima
Inserting container-ima kernel module
Launching the ebpf probe
libbpf: loading object 'probe_bpf' from buffer
...
...
...
```

* As additional containers are started on any of the hosts running the
  container meter, new entries should materialize on the hosts's IMA
  log file, attached to PCR 11.

```
10 1a0266c695d43778842e210acbe4da4deea539c8 ima-ng sha256:8034745e66ae478010d5ca22ecb1f3bd6872111378c09ee68a6041a6645504bd boot_aggregate
11 a80ff40e1301ecb2d7d220b59cb519b6a8a28b75 ima-ng sha256:2db1f4805655f31f48ef33ec0081c4e4cfef8724f3c9cd5fb20c5a7bb7d95f04 4026532676
```

TODOs
---

* The most appalling limitation of this system is that it only runs on
  kube clusters based on Fedora. To some extent this is because of
  limited testing (only Fedora 38 has been tested, really). But there
  are other reasons for it, e.g. a basic incompatibility with Ubuntu
  built kernels explained [here](https://github.com/avery-blanchard/container-integrity-measurement#ubuntu).

* We cannot deploy this technology on secure booted kernels, which
  (for now) makes it no more than a curiosity for security
  purposes. We are working on this aspect.

* The daemon set does not deploy the container image on control plane
  nodes. This is a mistake that needs to be corrected -- for the tool
  to be useful it needs to collect information on *every* node in the
  cluster.