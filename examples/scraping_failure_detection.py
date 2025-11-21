"""
Scraping Failure Detection for rnet

This example demonstrates how to detect scraping failures even when
receiving a 200 HTTP status code. Common scenarios include:
- CAPTCHA challenges
- Bot detection pages
- JavaScript requirement pages
- Rate limiting soft-blocks
"""

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
    ):
        """
        Initialize the detector

        Args:
            min_content_length: Minimum expected response size in bytes
            max_content_length: Maximum expected response size in bytes
            expected_content_type: Expected Content-Type header value
            required_markers: List of strings that must be present in response
        """
        self.min_content_length = min_content_length
        self.max_content_length = max_content_length
        self.expected_content_type = expected_content_type
        self.required_markers = required_markers or []

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


async def main():
    """Run all examples"""
    await example_basic_detection()
    await example_with_required_markers()
    await example_detect_cloudflare()
    await example_custom_validation()

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
    7. Custom logic: Implement domain-specific validation

    Combine multiple strategies for robust failure detection!
    """)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
