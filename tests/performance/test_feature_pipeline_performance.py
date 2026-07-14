import hashlib
import resource
import time
from datetime import UTC, datetime, timedelta

from aegis_services.features import FeatureInput, FeaturePipeline
from aegis_services.ingestion import CanonicalFlowV1


def test_ten_thousand_flow_pipeline_is_bounded() -> None:
    started_memory_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    base_time = datetime(2026, 7, 14, tzinfo=UTC)
    inputs = tuple(
        FeatureInput(
            event_key=hashlib.sha256(f"performance-{index}".encode()).hexdigest(),
            sensor_id="performance-sensor",
            flow=CanonicalFlowV1(
                source_type="normalized",
                source_event_id=f"performance-{index}",
                event_time=base_time + timedelta(milliseconds=index * 50),
                src_address=f"192.0.2.{(index % 200) + 1}",
                dst_address=f"198.51.100.{(index % 200) + 1}",
                src_port=49152 + (index % 1000),
                dst_port=(22, 53, 80, 443)[index % 4],
                protocol="tcp" if index % 4 != 1 else "udp",
                duration_ms=index % 5000,
                packet_count=(index % 100) + 1,
                byte_count=((index % 100) + 1) * 128,
                state="SF",
            ),
        )
        for index in range(10_000)
    )
    started = time.perf_counter()
    vectors = FeaturePipeline().transform_batch(inputs)
    elapsed_seconds = time.perf_counter() - started
    finished_memory_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assert len(vectors) == 10_000
    assert elapsed_seconds < 30
    assert finished_memory_kib - started_memory_kib < 256 * 1024
