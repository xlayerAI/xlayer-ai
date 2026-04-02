import asyncio
import aiohttp
import os
import json
import re
from dotenv import load_dotenv
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# Load credentials securely
dotenv_path = os.path.join(os.getcwd(), '.env')
print(f"DEBUG: Loading .env from {dotenv_path}")
load_dotenv(dotenv_path)

# Setup Logging
logger.add("logs/h1_scraper_{time}.log", rotation="500 MB", level="INFO")

logger.info(f"Loading .env from {dotenv_path}")
logger.info(f"H1_USERNAME present: {bool(os.getenv('H1_USERNAME'))}")
logger.info(f"H1_API_TOKEN present: {bool(os.getenv('H1_API_TOKEN'))}")

CONFIG = {
    "USERNAME": os.getenv("H1_USERNAME"),
    "API_TOKEN": os.getenv("H1_API_TOKEN"),
    "BASE_URL": "https://api.hackerone.com/v1/reports",
    "OUTPUT_DIR": "data/enterprise_dataset",
    "CHECKPOINT_FILE": "data/checkpoint.json",
    "CONCURRENCY_LIMIT": 5, 
    "PAGE_SIZE": 100
}

# Ensure directories exist
os.makedirs(CONFIG["OUTPUT_DIR"], exist_ok=True)
os.makedirs("logs", exist_ok=True)

class HackerOneScraper:
    def __init__(self):
        if not CONFIG["USERNAME"] or not CONFIG["API_TOKEN"]:
            logger.error("CRITICAL: Credentials missing in .env file.")
            raise ValueError("Missing Credentials")
            
        self.auth = aiohttp.BasicAuth(CONFIG["USERNAME"], CONFIG["API_TOKEN"])
        self.semaphore = asyncio.Semaphore(CONFIG["CONCURRENCY_LIMIT"])
        self.checkpoint = self._load_checkpoint()

    def _load_checkpoint(self):
        if os.path.exists(CONFIG["CHECKPOINT_FILE"]):
            try:
                with open(CONFIG["CHECKPOINT_FILE"], 'r') as f:
                    data = json.load(f)
                    return data.get('next_page', 1)
            except Exception:
                return 1
        return 1

    def _save_checkpoint(self, page_num):
        with open(CONFIG["CHECKPOINT_FILE"], 'w') as f:
            json.dump({"next_page": page_num}, f)

    def clean_text(self, text):
        if not text: return ""
        # Remove greetings but keep structural newlines
        text = re.sub(r"(?i)^(hi|hello|hey)\s+(team|there|security).*?(\n|$)", "", text)
        text = re.sub(r"<.*?>", "", text)
        text = re.sub(r"\n\s*\n", "\n", text)
        return text.strip()

    def is_valid_chain(self, text):
        """Filter for Exploit Chain logic only."""
        if not text: return False
        keywords = [
            r"(?i)step\s*\d+", r"(?m)^\s*\d+\.", 
            r"(?i)chain", r"(?i)first", r"(?i)then",
            r"(?i)repro"
        ]
        return any(re.search(p, text) for p in keywords)

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
    )
    async def fetch_page(self, session, page_num):
        params = {
            "page[number]": page_num,
            "page[size]": CONFIG["PAGE_SIZE"],
            "filter[state]": "publicly-disclosed"
        }
        
        async with self.semaphore:
            async with session.get(CONFIG["BASE_URL"], params=params) as resp:
                if resp.status == 429:
                    logger.warning(f"Rate limit hit on page {page_num}. Pausing...")
                    await asyncio.sleep(5)
                    raise aiohttp.ClientError("Rate Limited")
                
                resp.raise_for_status()
                return await resp.json()

    async def process_data(self):
        current_page = self.checkpoint
        
        async with aiohttp.ClientSession(auth=self.auth) as session:
            while True:
                logger.info(f"Fetching Page {current_page}...")
                
                try:
                    data = await self.fetch_page(session, current_page)
                    reports = data.get("data", [])
                    
                    if not reports:
                        logger.success("Scraping Complete! No more pages.")
                        break

                    processed_count = 0
                    output_file = os.path.join(CONFIG["OUTPUT_DIR"], f"h1_data_page_{current_page}.jsonl")
                    
                    with open(output_file, "w", encoding="utf-8") as f:
                        for item in reports:
                            attr = item["attributes"]
                            vinfo = self.clean_text(attr.get("vulnerability_information", ""))
                            
                            if not self.is_valid_chain(vinfo):
                                continue

                            entry = {
                                "id": item["id"],
                                "title": attr.get("title"),
                                "severity": attr.get("severity", {}).get("rating"),
                                "cwe": attr.get("weakness", {}).get("name"),
                                "instruction": "Analyze the exploit chain in this report.",
                                "input": vinfo,
                                "output": "To be generated during training"
                            }
                            f.write(json.dumps(entry) + "\n")
                            processed_count += 1
                    
                    logger.info(f"Page {current_page}: Saved {processed_count} valid chain reports.")
                    
                    current_page += 1
                    self._save_checkpoint(current_page)
                    await asyncio.sleep(0.5) 
                    
                    # For verification purposes, let's stop after 1 page if we found data, or maybe 2 pages.
                    # The user asked to summarize which pages were fetched.
                    # I'll let it run for a bit, but maybe I should add a limit for this verification run?
                    # The user didn't explicitly ask for a limit, but "Run the collector script" implies running it.
                    # I'll leave it as is.

                except Exception as e:
                    logger.exception(f"Stopping due to error on page {current_page}: {e}")
                    break

if __name__ == "__main__":
    try:
        scraper = HackerOneScraper()
        asyncio.run(scraper.process_data())
    except KeyboardInterrupt:
        logger.info("Scraper stopped by user.")
    except Exception as e:
        logger.error(f"Initialization Failed: {e}")