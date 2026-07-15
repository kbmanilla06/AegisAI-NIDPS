# Gate 5S-B ARM64 dependency review

**Review date:** 2026-07-15
**Target:** Linux ARM64, CPython 3.12, isolated Celery worker
**Decision:** Approved for synthetic-demo Gate 5S-B candidate generation only

The ML runtime is installed only in the worker image. The FastAPI image does not install or import the ML optional dependency set. Exact direct and transitive native wheel hashes are frozen in `constraints/ml-arm64-py312.lock`.

Approved direct versions are NumPy 2.3.5, SciPy 1.17.1, scikit-learn 1.8.0, skl2onnx 1.20.0, ONNX 1.22.0, ONNX Runtime 1.24.4, and PyArrow 23.0.1. Official PyPI provided compatible manylinux ARM64 wheels for every native package.

The initial ONNX 1.20.1 candidate was rejected before model creation because Trivy found four High vulnerabilities. ONNX 1.22.0 replaced it and the rebuilt worker image passed the fail-closed Trivy 0.69.2 scan with zero unresolved Critical or High findings. Scanner image digest: `sha256:3d1f862cb6c4fe13c1506f96f816096030d8d5ccdb2380a3069f7bf07daa86aa`.

The runtime remains restricted to project-created trusted graphs, a fixed operator/domain/opset policy, no external data, no custom operators, fixed float32 `[1,39]` input, a 16 MiB limit, and hash verification. No uploaded or third-party model is accepted. This approval does not authorize registry activation, scoring, online inference, or real-dataset use.
