"""
Eye of Horus — Reddit OSINT Scraper
Scrapes posts from cyber-threat-related subreddits via the PRAW library
and streams them into the Kafka raw-osint topic.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import praw
from loguru import logger

# ── Project root on path ──────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import reddit as reddit_cfg, kafka as kafka_cfg
from scraper.base_scraper import BaseScraper


class RedditScraper(BaseScraper):
    """
    Scrapes new and hot posts from a configurable list of subreddits
    using Reddit's official API (PRAW) in read-only mode.

    Targets: r/cybersecurity, r/hacking, r/netsec, r/DataBreaches, etc.
    """

    # ── Source identifier ─────────────────────────────────────────────────────
    @property
    def source_name(self) -> str:
        return "reddit"

    # ── Constructor ───────────────────────────────────────────────────────────
    def __init__(self, subreddits: list[str] | None = None) -> None:
        self._subreddits = subreddits or reddit_cfg.SUBREDDITS
        self._post_limit = reddit_cfg.POST_LIMIT
        self._reddit = self._authenticate()
        logger.info(
            f"[reddit] Authenticated. Monitoring: {', '.join(self._subreddits)}"
        )

    def _authenticate(self) -> praw.Reddit:
        """
        Authenticate with Reddit using PRAW read-only mode.
        Requires REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET in .env
        """
        if not reddit_cfg.CLIENT_ID or reddit_cfg.CLIENT_ID == "your_client_id_here":
            logger.warning(
                "[reddit] No Reddit API credentials found. "
                "Falling back to anonymous read-only mode (rate-limited)."
            )
            return praw.Reddit(
                client_id="placeholder",
                client_secret="placeholder",
                user_agent=reddit_cfg.USER_AGENT,
            )

        return praw.Reddit(
            client_id=reddit_cfg.CLIENT_ID,
            client_secret=reddit_cfg.CLIENT_SECRET,
            user_agent=reddit_cfg.USER_AGENT,
        )

    # ── Fetch ─────────────────────────────────────────────────────────────────
    def fetch(self) -> Iterator[dict[str, Any]]:
        """
        Yield raw submissions from each configured subreddit.
        Fetches both 'new' (real-time) and 'hot' (trending) posts.
        """
        for sub_name in self._subreddits:
            try:
                subreddit = self._reddit.subreddit(sub_name)
                logger.info(f"[reddit] Fetching r/{sub_name} ...")

                # Fetch NEW posts (most recent activity)
                for submission in subreddit.new(limit=self._post_limit):
                    yield self._submission_to_raw(submission, feed="new")

                # Fetch HOT posts (trending in the last 24h)
                for submission in subreddit.hot(limit=max(10, self._post_limit // 5)):
                    yield self._submission_to_raw(submission, feed="hot")

            except Exception as exc:
                logger.error(f"[reddit] Error accessing r/{sub_name}: {exc}")
                continue

    def _submission_to_raw(self, submission, feed: str) -> dict[str, Any]:
        """Convert a PRAW Submission object into a plain dict."""
        return {
            "id": submission.id,
            "title": submission.title or "",
            "selftext": submission.selftext or "",
            "author": str(submission.author) if submission.author else "[deleted]",
            "url": f"https://www.reddit.com{submission.permalink}",
            "created_utc": submission.created_utc,
            "subreddit": submission.subreddit.display_name,
            "score": submission.score,
            "num_comments": submission.num_comments,
            "upvote_ratio": submission.upvote_ratio,
            "is_self": submission.is_self,
            "flair": submission.link_flair_text,
            "feed": feed,
        }

    # ── Transform ─────────────────────────────────────────────────────────────
    def _transform(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map a Reddit submission dict to the standard OSINT record schema."""
        published_at = datetime.fromtimestamp(
            raw["created_utc"], tz=timezone.utc
        )

        # Combine title + body for NLP processing downstream
        full_text = f"{raw['title']} {raw['selftext']}".strip()

        return self.build_record(
            post_id=f"reddit_{raw['id']}",
            title=raw["title"],
            text=full_text,
            author=raw["author"],
            url=raw["url"],
            published_at=published_at,
            extra={
                "subreddit": raw["subreddit"],
                "score": raw["score"],
                "num_comments": raw["num_comments"],
                "upvote_ratio": raw["upvote_ratio"],
                "flair": raw["flair"],
                "feed_type": raw["feed"],
            },
        )


# ── Standalone entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    import time
    import schedule

    from kafka.producer import OsintProducer

    logger.add("logs/scraper_reddit.log", rotation="10 MB", retention="7 days")

    scraper = RedditScraper()

    with OsintProducer() as producer:

        def scrape_and_push():
            logger.info("━" * 60)
            logger.info("🔍 Starting Reddit scrape cycle...")
            count = scraper.run(
                callback=lambda record: producer.send(
                    data=record,
                    topic=kafka_cfg.TOPIC_RAW,
                    key=record["source"],
                )
            )
            logger.info(f"✅ Cycle complete — {count} records pushed to Kafka.")

        # Run immediately, then on schedule
        scrape_and_push()

        schedule.every(60).seconds.do(scrape_and_push)
        logger.info("⏱  Scheduler active. Press Ctrl+C to stop.")

        while True:
            schedule.run_pending()
            time.sleep(1)
