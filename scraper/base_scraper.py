"""
Eye of Horus — Abstract Base Scraper
All source-specific scrapers must inherit from this class.
"""

import abc
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Iterator

from loguru import logger


class BaseScraper(abc.ABC):
    """
    Abstract base class for all OSINT scrapers.

    Subclasses must implement:
        - source_name (property)
        - fetch() -> Iterator[dict]

    Subclasses inherit:
        - clean_text()
        - build_record()
        - run()
    """

    # ── Abstract interface ────────────────────────────────────────────────────

    @property
    @abc.abstractmethod
    def source_name(self) -> str:
        """A stable identifier string, e.g. 'reddit', 'forum_hackforums'."""
        ...

    @abc.abstractmethod
    def fetch(self) -> Iterator[dict[str, Any]]:
        """
        Yield raw records from the data source.
        Each record must be a plain dict with at minimum: text, author, url, published_at.
        """
        ...

    # ── Shared helpers ────────────────────────────────────────────────────────

    @staticmethod
    def clean_text(raw: str) -> str:
        """
        Normalize and strip noise from raw text.

        Steps:
        1. Normalize unicode (NFKC)
        2. Remove HTML/Markdown links
        3. Collapse whitespace
        4. Strip leading/trailing whitespace
        """
        if not raw:
            return ""
        # Unicode normalization
        text = unicodedata.normalize("NFKC", raw)
        # Remove markdown links [text](url) → text
        text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
        # Remove bare URLs
        text = re.sub(r"https?://\S+", "", text)
        # Remove HTML tags
        text = re.sub(r"<[^>]+>", "", text)
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def build_record(
        self,
        *,
        post_id: str,
        title: str,
        text: str,
        author: str,
        url: str,
        published_at: datetime,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build a standardized OSINT record that all downstream consumers expect.

        Schema:
            post_id        : unique identifier from the source
            source         : scraper source name
            title          : post/thread title (cleaned)
            text           : post body (cleaned)
            author         : username / handle
            url            : canonical URL to the post
            published_at   : UTC ISO-8601 timestamp
            collected_at   : UTC ISO-8601 timestamp of this collection run
            extra          : source-specific metadata (upvotes, subreddit, etc.)
        """
        return {
            "post_id": post_id,
            "source": self.source_name,
            "title": self.clean_text(title),
            "text": self.clean_text(text),
            "author": author,
            "url": url,
            "published_at": published_at.isoformat() if published_at else None,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "extra": extra or {},
        }

    def run(self, callback) -> int:
        """
        Iterate over fetch() results, build records, and call callback(record).

        Args:
            callback: A callable that accepts a single record dict.
                      Typically the Kafka producer's send() method.

        Returns:
            Number of records successfully processed.
        """
        count = 0
        logger.info(f"[{self.source_name}] Starting scrape run...")

        for raw in self.fetch():
            try:
                record = self._transform(raw)
                callback(record)
                count += 1
            except Exception as exc:
                logger.warning(f"[{self.source_name}] Skipping item — {exc}")

        logger.info(f"[{self.source_name}] Scrape complete. Records collected: {count}")
        return count

    @abc.abstractmethod
    def _transform(self, raw: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a raw fetch() result into a standardized record via build_record().
        Each subclass implements this mapping.
        """
        ...
