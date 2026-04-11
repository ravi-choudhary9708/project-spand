
import os
import sys
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add the backend path to sys.path
sys.path.append(r"c:\Users\Admin\Desktop\spand\project-spand\backend")

# Mocking parts of the app to avoid DB dependencies during the profiling test
from app.tasks.scan_tasks import (
    _get_root_domain, 
    _build_ct_cache, 
    get_ips_from_spf, 
    get_historical_ips_viewdns,
    _is_known_cdn_ip,
    _gather_target_profile
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def verify_github_parallel_flow():
    root_domain = "github.com"
    # We'll test with a few real subdomains to see the concurrency in action
    all_domains = ["github.com", "api.github.com", "gist.github.com", "pages.github.com", "raw.github.com"]
    
    logger.info(f"=== VERIFYING PARALLEL SCAN FLOW FOR {root_domain} ===")
    
    # --- STAGE 1: Root Intel Gathering ---
    logger.info("STEP 1: Gathering Root Intel (Parallel)...")
    ct_cache_map = {}
    root_info_map = {}
    
    def _get_root_intel(root):
        logger.info(f"  [root] Fetching intel for {root}...")
        # 3a. CT Log metadata
        ct_data = _build_ct_cache(root)
        # 3b. SPF Mining
        spf_ips = get_ips_from_spf(root)
        origin_targets = [{"type": "ip", "value": ip, "cert_domain": root, "source": "spf"} for ip in spf_ips]
        # 3c. Historical IPs
        hist_ips = get_historical_ips_viewdns(root)
        for ip in hist_ips:
            if not _is_known_cdn_ip(ip):
                origin_targets.append({"type": "ip", "value": ip, "cert_domain": root, "source": "passive_dns"})
        return root, ct_data, origin_targets

    # Run root intel (typically for one root domain in this test)
    with ThreadPoolExecutor(max_workers=5) as root_executor:
        future = root_executor.submit(_get_root_intel, root_domain)
        try:
            r, ct, ot = future.result()
            ct_cache_map.update(ct)
            root_info_map[r] = {"origin_targets": ot}
            logger.info(f"DONE: Cached {len(ct_cache_map)} CT entries and {len(ot)} origin targets for {root_domain}")
        except Exception as e:
            logger.error(f"Root Intel failed: {e}")
            return

    # --- STAGE 2: Parallel Subdomain Profiling ---
    logger.info(f"STEP 2: Profiling {len(all_domains)} subdomains (Parallel)...")
    target_profiles = {}
    
    with ThreadPoolExecutor(max_workers=10) as gather_executor:
        gather_futures = {
            gather_executor.submit(_gather_target_profile, domain, root_domain, ct_cache_map, root_info_map): domain
            for domain in all_domains
        }
        for future in as_completed(gather_futures):
            domain = gather_futures[future]
            try:
                target_profiles[domain] = future.result()
                logger.info(f"  [profile] Success for {domain}: Found {len(target_profiles[domain]['origin_targets'])} bypass candidates")
            except Exception as e:
                logger.error(f"  [profile] Failed for {domain}: {e}")

    logger.info(f"=== VERIFICATION COMPLETE ===")
    logger.info(f"Total profiles built: {len(target_profiles)}")
    
    sample_domain = "api.github.com"
    sample = target_profiles.get(sample_domain, {})
    if sample:
        logger.info(f"Sample Profile: {sample_domain}")
        logger.info(f"  - CT Metadata: {'Found' if sample.get('ct_entry') else 'Not Found'}")
        logger.info(f"  - Bypass Candidates: {len(sample.get('origin_targets', []))}")
        for t in sample.get('origin_targets', [])[:3]:
            logger.info(f"    * {t.get('type')}: {t.get('value')} ({t.get('source')})")

if __name__ == "__main__":
    verify_github_parallel_flow()
