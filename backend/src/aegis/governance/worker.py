"""Background review sweep. A failure here is logged and retried, and never touches enforcement."""

import logging
import threading
from collections.abc import Callable
from datetime import datetime

from aegis.db.session import Database
from aegis.governance.reviews import process_due_reviews

logger = logging.getLogger("aegis.governance.reviews")


class GovernanceReviewWorker:
    def __init__(
        self, db: Database, clock: Callable[[], datetime], poll_seconds: float
    ) -> None:
        self._db = db
        self._clock = clock
        self._poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="aegis-governance-reviews",
                                        daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)

    def _run(self) -> None:
        while not self._stop.wait(self._poll_seconds):
            try:
                process_due_reviews(self._db, clock=self._clock)
            except Exception as error:
                logger.error("governance review pass failed: %s", type(error).__name__)
