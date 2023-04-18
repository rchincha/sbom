# stacker-bom: a SBOM workflow tool/library for container image builds

Originally intended as a [stacker](https://stackerbuild.io) companion tool to
help with container image builds but anyone should be able to use it.

It uses
[https://github.com/kubernetes-sigs/bom](https://github.com/kubernetes-sigs/bom)
and [https://github.com/anchore/syft](https://github.com/anchore/syft) as its core BOM
libraries.

## Rationale

* Every component of a container image must be accounted for
* Source/build time tooling since most context is available at this time
* Easily integrate with [`stacker`](https://github.com/project-stacker/stacker)
