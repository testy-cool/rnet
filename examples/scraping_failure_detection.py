"""
Scraping Failure Detection for rnet

This example demonstrates how to detect scraping failures even when
receiving a 200 HTTP status code. Common scenarios include:
- CAPTCHA challenges
- Bot detection pages
- JavaScript requirement pages
- Rate limiting soft-blocks
"""

import re
import rnet
from typing import Optional, Tuple


class ScrapingFailureDetector:
    """Detects scraping failures beyond HTTP status codes"""

    # Common anti-bot page indicators
    BOT_INDICATORS = [
        "captcha",
        "recaptcha",
        "hcaptcha",
        "cloudflare",
        "cf-browser-verification",
        "challenge-platform",
        "access denied",
        "blocked",
        "security check",
        "ray id:",
        "enable javascript",
        "datadome",
        "imperva",
        "perimeter x",
        "distil networks",
        "akamai",
        "incapsula",
        "please verify you are human",
        "are you a robot",
        "automated access",
        "unusual traffic",
        "__cf_chl_jschl_tk__",  # Cloudflare JS challenge
        "cf_clearance",
        "bot detection",
    ]

    # Suspicious headers that may indicate blocking
    SUSPICIOUS_HEADERS = {
        "cf-ray": "Cloudflare protection",
        "cf-mitigated": "Cloudflare mitigation",
        "x-datadome-cid": "DataDome protection",
        "x-distil-cs": "Distil Networks",
        "server": ["akamai", "cloudflare", "imperva"],
    }

    def __init__(
        self,
        min_content_length: int = 500,
        max_content_length: Optional[int] = None,
        expected_content_type: str = "text/html",
        required_markers: Optional[list[str]] = None,
        check_js_rendering: bool = False,
        min_text_ratio: float = 0.05,
    ):
        """
        Initialize the detector

        Args:
            min_content_length: Minimum expected response size in bytes
            max_content_length: Maximum expected response size in bytes
            expected_content_type: Expected Content-Type header value
            required_markers: List of strings that must be present in response
            check_js_rendering: Enable JS-rendered content detection
            min_text_ratio: Minimum ratio of text to HTML (for JS detection)
        """
        self.min_content_length = min_content_length
        self.max_content_length = max_content_length
        self.expected_content_type = expected_content_type
        self.required_markers = required_markers or []
        self.check_js_rendering = check_js_rendering
        self.min_text_ratio = min_text_ratio

    async def check_response(
        self,
        response: rnet.Response
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if scraping likely failed

        Returns:
            (is_valid, error_message): Tuple where is_valid=True means scraping succeeded
        """
        # First check HTTP status
        if not response.status.is_success():
            return False, f"HTTP error: {response.status.as_int()}"

        # Check suspicious status codes that are often used for soft-blocks
        status_code = response.status.as_int()
        if status_code in [203, 204]:  # Non-Authoritative, No Content
            return False, f"Suspicious status code: {status_code}"

        # Check headers for protection systems
        is_valid, error = self._check_headers(response)
        if not is_valid:
            return is_valid, error

        # Check content-type
        is_valid, error = self._check_content_type(response)
        if not is_valid:
            return is_valid, error

        # Check redirects
        is_valid, error = self._check_redirects(response)
        if not is_valid:
            return is_valid, error

        # Get response body for content checks
        try:
            html = await response.text()
        except Exception as e:
            return False, f"Failed to decode response: {e}"

        # Check content length
        is_valid, error = self._check_content_length(html)
        if not is_valid:
            return is_valid, error

        # Check for bot detection indicators
        is_valid, error = self._check_bot_indicators(html)
        if not is_valid:
            return is_valid, error

        # Check for required content markers
        is_valid, error = self._check_required_markers(html)
        if not is_valid:
            return is_valid, error

        # Check for JS-rendered content issues
        if self.check_js_rendering:
            is_valid, error = self._check_js_placeholders(html)
            if not is_valid:
                return is_valid, error

            is_valid, error = self._check_content_density(html)
            if not is_valid:
                return is_valid, error

            is_valid, error = self._check_embedded_data(html)
            if not is_valid:
                return is_valid, error

        return True, None

    def _check_headers(self, response: rnet.Response) -> Tuple[bool, Optional[str]]:
        """Check headers for anti-bot indicators"""
        for header_name, indicator in self.SUSPICIOUS_HEADERS.items():
            header_value = response.headers.get(header_name)
            if header_value:
                if isinstance(indicator, list):
                    for pattern in indicator:
                        if pattern.lower() in header_value.lower():
                            return False, f"Protection detected via header {header_name}: {pattern}"
                else:
                    return False, f"Protection detected: {indicator}"

        return True, None

    def _check_content_type(self, response: rnet.Response) -> Tuple[bool, Optional[str]]:
        """Validate content-type header"""
        content_type = response.headers.get("content-type", "")

        if self.expected_content_type and self.expected_content_type not in content_type:
            return False, f"Wrong content-type: expected '{self.expected_content_type}', got '{content_type}'"

        return True, None

    def _check_redirects(self, response: rnet.Response) -> Tuple[bool, Optional[str]]:
        """Analyze redirect history"""
        if not response.history:
            return True, None

        # Check for redirect loops
        urls = [h.url for h in response.history]
        if len(urls) != len(set(urls)):
            return False, "Redirect loop detected"

        # Check for suspicious redirect patterns
        for history in response.history:
            url_lower = history.url.lower()
            for pattern in ['captcha', 'challenge', 'verify', 'blocked']:
                if pattern in url_lower:
                    return False, f"Suspicious redirect: {history.url}"

            # Check for suspicious status codes in redirects
            if history.status in [503, 403, 429]:
                return False, f"Blocking status in redirect chain: {history.status}"

        # Check for excessive redirects
        if len(response.history) > 5:
            return False, f"Too many redirects: {len(response.history)}"

        return True, None

    def _check_content_length(self, html: str) -> Tuple[bool, Optional[str]]:
        """Validate response size"""
        content_length = len(html)

        if content_length < self.min_content_length:
            return False, f"Content too small: {content_length} bytes (min: {self.min_content_length})"

        if self.max_content_length and content_length > self.max_content_length:
            return False, f"Content too large: {content_length} bytes (max: {self.max_content_length})"

        # Check for empty body
        if content_length == 0:
            return False, "Empty response body"

        return True, None

    def _check_bot_indicators(self, html: str) -> Tuple[bool, Optional[str]]:
        """Check for anti-bot page indicators"""
        html_lower = html.lower()

        for indicator in self.BOT_INDICATORS:
            if indicator in html_lower:
                # Double-check it's not in a comment or legitimate context
                # This is a simple heuristic - you may want to use proper HTML parsing
                context_start = max(0, html_lower.find(indicator) - 50)
                context_end = min(len(html), html_lower.find(indicator) + len(indicator) + 50)
                context = html[context_start:context_end]

                return False, f"Bot detection indicator found: '{indicator}' (context: ...{context}...)"

        return True, None

    def _check_required_markers(self, html: str) -> Tuple[bool, Optional[str]]:
        """Check for expected content markers"""
        if not self.required_markers:
            return True, None

        missing = []
        for marker in self.required_markers:
            if marker not in html:
                missing.append(marker)

        if missing:
            return False, f"Missing required content markers: {missing}"

        return True, None

    def _check_js_placeholders(self, html: str) -> Tuple[bool, Optional[str]]:
        """Detect common JavaScript placeholder/skeleton patterns"""
        html_lower = html.lower()

        # Patterns indicating JS-rendered content
        js_placeholder_indicators = [
            ('data-reactroot', 'React root'),
            ('id="root"', 'React/Vue root element'),
            ('id="app"', 'Vue/SPA app element'),
            ('data-vue-app', 'Vue app'),
            ('ng-app', 'Angular app'),
            ('ng-version', 'Angular framework'),
            ('<div id="root"></div>', 'Empty React root'),
            ('<div id="app"></div>', 'Empty app container'),
            ('<main></main>', 'Empty main element'),
            ('skeleton-loader', 'Skeleton loading state'),
            ('placeholder-glow', 'Placeholder animation'),
            ('spinner', 'Loading spinner'),
        ]

        detected = []
        for pattern, description in js_placeholder_indicators:
            if pattern.lower() in html_lower:
                detected.append(description)

        # Check for single root div with nothing in it (common SPA pattern)
        # This is a simple heuristic
        single_div_pattern = re.search(r'<body[^>]*>\s*<div[^>]*>\s*</div>\s*<script', html_lower)
        if single_div_pattern:
            detected.append('Single empty div with scripts (SPA pattern)')

        if detected:
            return False, f"JS placeholder detected: {', '.join(detected[:3])}"

        return True, None

    def _check_content_density(self, html: str) -> Tuple[bool, Optional[str]]:
        """Check if page has suspiciously low text content (indicates JS rendering)"""
        total_size = len(html)

        if total_size == 0:
            return False, "Empty HTML"

        # Remove scripts, styles, and tags to get text content
        text_only = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        text_only = re.sub(r'<style[^>]*>.*?</style>', '', text_only, flags=re.DOTALL | re.IGNORECASE)
        text_only = re.sub(r'<[^>]+>', '', text_only)
        text_only = re.sub(r'\s+', ' ', text_only)  # Normalize whitespace
        text_only = text_only.strip()

        text_size = len(text_only)
        text_ratio = text_size / total_size if total_size > 0 else 0

        # Count script tags
        script_count = html.lower().count('<script')

        # If very low text ratio and has scripts, likely JS-rendered
        if text_ratio < self.min_text_ratio and total_size > 1000:
            return False, f"Low content density: {text_ratio:.1%} text, {script_count} scripts (likely JS-rendered)"

        # Warn about heavy JS usage even if text ratio is acceptable
        if script_count > 15 and text_ratio < 0.15:
            return False, f"Heavy JS usage: {script_count} scripts with {text_ratio:.1%} text content"

        return True, None

    def _check_embedded_data(self, html: str) -> Tuple[bool, Optional[str]]:
        """Look for JSON data that JavaScript would render"""
        # Patterns that indicate data is embedded but not rendered
        data_embedding_patterns = [
            ('type="application/json"', 'JSON script tag'),
            ('type="application/ld+json"', 'JSON-LD structured data'),
            ('__initial_state__', 'Initial state data'),
            ('__preloaded_state__', 'Preloaded state'),
            ('window.__data__', 'Window data object'),
            ('id="__next_data__"', 'Next.js data'),
            ('__next_data__', 'Next.js SSR data'),
            ('window.__initial_data__', 'Initial data'),
        ]

        html_lower = html.lower()
        found_patterns = []

        for pattern, description in data_embedding_patterns:
            if pattern.lower() in html_lower:
                found_patterns.append(description)

        if found_patterns:
            # Check if there's also very little visible content
            # This indicates data is there but not rendered
            visible_content = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
            visible_content = re.sub(r'<[^>]+>', '', visible_content).strip()

            if len(visible_content) < 500:  # Very little visible text
                return False, f"Found embedded data requiring JS: {', '.join(found_patterns[:2])}"

        return True, None


async def example_basic_detection():
    """Basic scraping failure detection"""
    print("=" * 60)
    print("Example 1: Basic Detection")
    print("=" * 60)

    client = rnet.Client(
        emulation=rnet.Emulation.Chrome134,
        timeout=30,
    )

    detector = ScrapingFailureDetector(
        min_content_length=1000,
        expected_content_type="text/html",
    )

    # Test with a normal page
    url = "https://httpbin.org/html"

    try:
        response = await client.get(url)
        is_valid, error = await detector.check_response(response)

        if is_valid:
            print(f"✓ Scraping succeeded for {url}")
            html = await response.text()
            print(f"  Content length: {len(html)} bytes")
        else:
            print(f"✗ Scraping failed for {url}")
            print(f"  Reason: {error}")
    except Exception as e:
        print(f"✗ Request failed: {e}")


async def example_with_required_markers():
    """Detection with required content markers"""
    print("\n" + "=" * 60)
    print("Example 2: Detection with Required Markers")
    print("=" * 60)

    client = rnet.Client(
        emulation=rnet.Emulation.Chrome134,
    )

    # Expect specific content on the page
    detector = ScrapingFailureDetector(
        min_content_length=500,
        required_markers=["<html", "</html>"],  # Basic HTML structure
    )

    url = "https://httpbin.org/html"

    try:
        response = await client.get(url)
        is_valid, error = await detector.check_response(response)

        if is_valid:
            print(f"✓ Page contains required markers")
        else:
            print(f"✗ Validation failed: {error}")
    except Exception as e:
        print(f"✗ Request failed: {e}")


async def example_detect_cloudflare():
    """Detect Cloudflare protection (simulated)"""
    print("\n" + "=" * 60)
    print("Example 3: Cloudflare Detection")
    print("=" * 60)

    client = rnet.Client(
        emulation=rnet.Emulation.Chrome134,
    )

    detector = ScrapingFailureDetector(min_content_length=100)

    # This will likely fail if Cloudflare is protecting the site
    url = "https://httpbin.org/headers"

    try:
        response = await client.get(url)

        # Manual Cloudflare header check
        cf_ray = response.headers.get("cf-ray")
        if cf_ray:
            print(f"  Cloudflare detected (CF-Ray: {cf_ray})")

        is_valid, error = await detector.check_response(response)

        if is_valid:
            print(f"✓ No blocking detected")
        else:
            print(f"✗ Blocking detected: {error}")
    except Exception as e:
        print(f"✗ Request failed: {e}")


async def example_custom_validation():
    """Custom validation logic"""
    print("\n" + "=" * 60)
    print("Example 4: Custom Validation Logic")
    print("=" * 60)

    client = rnet.Client(
        emulation=rnet.Emulation.Chrome134,
    )

    async def custom_validator(response: rnet.Response) -> Tuple[bool, Optional[str]]:
        """Custom validation function"""
        # Use the standard detector first
        detector = ScrapingFailureDetector(min_content_length=200)
        is_valid, error = await detector.check_response(response)

        if not is_valid:
            return is_valid, error

        # Add custom checks
        html = await response.text()

        # Check for specific error messages
        if "error" in html.lower() and "404" in html:
            return False, "Page contains error message"

        # Check HTML structure
        if "<html" not in html.lower() or "</html>" not in html.lower():
            return False, "Invalid HTML structure"

        return True, None

    url = "https://httpbin.org/html"

    try:
        response = await client.get(url)
        is_valid, error = await custom_validator(response)

        if is_valid:
            print(f"✓ Custom validation passed")
        else:
            print(f"✗ Custom validation failed: {error}")
    except Exception as e:
        print(f"✗ Request failed: {e}")


async def example_js_rendered_content():
    """Detect JavaScript-rendered content issues"""
    print("\n" + "=" * 60)
    print("Example 5: JavaScript-Rendered Content Detection")
    print("=" * 60)

    client = rnet.Client(
        emulation=rnet.Emulation.Chrome134,
    )

    # Enable JS rendering checks
    detector = ScrapingFailureDetector(
        min_content_length=500,
        check_js_rendering=True,
        min_text_ratio=0.1,  # Expect at least 10% text content
        required_markers=['<html', '</html>'],
    )

    # Test with httpbin (should pass - server-rendered)
    url = "https://httpbin.org/html"

    print("\nTesting server-rendered page (httpbin):")
    try:
        response = await client.get(url)
        is_valid, error = await detector.check_response(response)

        if is_valid:
            print(f"✓ Server-rendered content detected")
            html = await response.text()

            # Show some stats
            text_only = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
            text_only = re.sub(r'<style[^>]*>.*?</style>', '', text_only, flags=re.DOTALL | re.IGNORECASE)
            text_only = re.sub(r'<[^>]+>', '', text_only).strip()

            script_count = html.lower().count('<script')
            text_ratio = len(text_only) / len(html) if html else 0

            print(f"  Content length: {len(html)} bytes")
            print(f"  Text ratio: {text_ratio:.1%}")
            print(f"  Script tags: {script_count}")
        else:
            print(f"✗ Detection failed: {error}")
    except Exception as e:
        print(f"✗ Request failed: {e}")

    # Simulate a JS-heavy page check
    print("\nChecking for common JS framework patterns:")
    js_patterns = [
        'React (id="root")',
        'Vue (id="app")',
        'Angular (ng-app)',
        'Next.js (__NEXT_DATA__)',
    ]
    print(f"  Detectable patterns: {', '.join(js_patterns)}")
    print("  If these are found with low text content, scraping likely failed")


async def example_real_world_scenario():
    """Real-world e-commerce scraping scenario"""
    print("\n" + "=" * 60)
    print("Example 6: Real-World E-commerce Scraping")
    print("=" * 60)

    client = rnet.Client(
        emulation=rnet.Emulation.Chrome134,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    )

    # Create detector expecting product page content
    detector = ScrapingFailureDetector(
        min_content_length=2000,
        check_js_rendering=True,
        required_markers=[
            'price',      # Product price
            'cart',       # Shopping cart
            'product',    # Product identifier
        ],
    )

    print("\nScenario: Scraping a product page")
    print("Expected markers: price, cart, product")
    print("\nNote: This example demonstrates the detection logic.")
    print("In production, you would:")
    print("  1. Request the actual product page")
    print("  2. Check if it contains expected elements")
    print("  3. Handle failures (retry, use different IP, etc.)")
    print("\nCommon failure patterns:")
    print("  ✗ Bot challenge page (200 status)")
    print("  ✗ JS-rendered content not loaded")
    print("  ✗ Empty price/product fields")
    print("  ✗ Redirect to homepage/error page")


async def main():
    """Run all examples"""
    await example_basic_detection()
    await example_with_required_markers()
    await example_detect_cloudflare()
    await example_custom_validation()
    await example_js_rendered_content()
    await example_real_world_scenario()

    print("\n" + "=" * 60)
    print("Detection Strategies Summary")
    print("=" * 60)
    print("""
    1. Content-based: Check for anti-bot keywords in HTML
    2. Size validation: Ensure response isn't suspiciously small/large
    3. Content-type: Verify you're getting expected content type
    4. Header analysis: Check for protection system headers
    5. Redirect analysis: Detect challenge/captcha redirects
    6. Required markers: Ensure expected content is present
    7. JS rendering detection: Detect missing JS-loaded content
       - Empty root divs (React/Vue/Angular)
       - Low text-to-HTML ratio
       - Skeleton loaders/placeholders
       - Embedded JSON data not rendered
    8. Custom logic: Implement domain-specific validation

    For JS-rendered content detection:
    - Look for empty <div id="root"></div> or similar
    - Check text-to-HTML ratio (should be >5-10%)
    - Count script tags (>15 scripts = likely SPA)
    - Look for embedded JSON that wasn't rendered
    - Check for framework-specific patterns

    Combine multiple strategies for robust failure detection!
    """)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
