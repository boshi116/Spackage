"""Preserve final RTSP media when data and EOF become readable together."""

import http.client
import os
import re
import signal
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from helpers import MockRTSPServer, R2HProcess, find_free_port

pytestmark = pytest.mark.rtsp


@pytest.mark.parametrize("stage", ["play_response", "playing"])
@pytest.mark.parametrize("final_packets", [3, 50])
def test_interleaved_media_before_eof(r2h_binary, stage, final_packets):
    ready = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class GatedRTSPServer(MockRTSPServer):
        def _before_play(self):
            if stage == "play_response":
                ready.set()
                assert release.wait(5), "Test did not release PLAY response"

        def _after_play(self, conn, addr):
            if stage == "playing":
                self._num_packets = 64
                super()._after_play(conn, addr)
                ready.set()
                assert release.wait(5), "Test did not release final media"
            self._num_packets = final_packets
            super()._after_play(conn, addr)
            # Queue FIN before waking the test; the worker is still stopped.
            conn.shutdown(socket.SHUT_WR)
            finished.set()

    upstream = GatedRTSPServer(encapsulate_rtp=False)
    r2h = R2HProcess(r2h_binary, find_free_port(), extra_args=["-v", "4"])
    client = None
    worker_pid = None
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        upstream.start()
        r2h.start()
        match = re.search(r"Spawned worker 0 with pid (\d+)", r2h.read_log())
        assert match, r2h.read_log()
        worker_pid = int(match[1])
        client = http.client.HTTPConnection("127.0.0.1", r2h.port, timeout=10)
        client.request("GET", f"/rtsp/127.0.0.1:{upstream.port}/stream")
        response_future = executor.submit(client.getresponse)
        initial = b""
        if stage == "playing":
            response = response_future.result(timeout=10)
            initial = response.read(1316)
            assert len(initial) == 1316
        assert ready.wait(5), r2h.read_log()
        # Freeze only this test's worker so PLAY/media/FIN accumulate in the
        # kernel regardless of VM scheduling, then deliver them in one wakeup.
        os.kill(worker_pid, signal.SIGSTOP)
        release.set()
        assert finished.wait(5), "Mock did not finish sending media and FIN"
        os.kill(worker_pid, signal.SIGCONT)
        response = response_future.result(timeout=10)
        body = initial + response.read()
        assert response.status == 200, r2h.read_log()
        packet_count = final_packets + (64 if stage == "playing" else 0)
        assert len(body) == packet_count * 1316, r2h.read_log()
        assert all(body[index] == 0x47 for index in range(0, len(body), 188))
    finally:
        release.set()
        if worker_pid is not None:
            try:
                os.kill(worker_pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        if client is not None:
            client.close()
        r2h.stop()
        upstream.stop()
        executor.shutdown(wait=True)
