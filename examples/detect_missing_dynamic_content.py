"""
Detecting Missing Dynamic Content in "Complete-Looking" Pages

This example demonstrates advanced detection techniques for when you receive
a seemingly complete page (good size, has content) but are actually missing
dynamic/JS-loaded content. This is the trickiest scraping failure scenario.

Common cases:
- Product listings with only first page loaded
- Prices/ratings loaded dynamically
- Infinite scroll content not loaded
- Reviews/comments loaded via AJAX
- Lazy-loaded images still showing placeholders
"""

import json
import re
import rnet
from typing import Optional, Tuple, Dict, Any


class DynamicContentDetector:
    """Detects missing dynamic content in seemingly complete pages"""

    def __init__(
        self,
        min_item_count: Optional[int] = None,
        expected_patterns: Optional[Dict[str, Dict[str, Any]]] = None,
        check_lazy_loading: bool = True,
        check_pagination: bool = True,
    ):
        """
        Initialize detector for dynamic content

        Args:
            min_item_count: Minimum expected number of items (products, posts, etc.)
            expected_patterns: Dict of patterns to validate with min counts
            check_lazy_loading: Check for unloaded lazy-load content
            check_pagination: Check if pagination/infinite scroll loaded
        """
        self.min_item_count = min_item_count
        self.expected_patterns = expected_patterns or {}
        self.check_lazy_loading = check_lazy_loading
        self.check_pagination = check_pagination

    async def check_response(
        self,
        response: rnet.Response
    ) -> Tuple[bool, Optional[str]]:
        """Check if dynamic content is missing"""

        html = await response.text()

        # Check for lazy-loaded content that didn't load
        if self.check_lazy_loading:
            is_valid, error = self._check_lazy_loading(html)
            if not is_valid:
                return is_valid, error

        # Check pagination/infinite scroll
        if self.check_pagination:
            is_valid, error = self._check_pagination(html)
            if not is_valid:
                return is_valid, error

        # Check minimum item count
        if self.min_item_count:
            is_valid, error = self._check_item_count(html, self.min_item_count)
            if not is_valid:
                return is_valid, error

        # Validate expected patterns
        if self.expected_patterns:
            is_valid, error = self._validate_patterns(html)
            if not is_valid:
                return is_valid, error

        # Check for noscript fallback content
        is_valid, error = self._check_noscript(html)
        if not is_valid:
            return is_valid, error

        # Check structured data completeness
        is_valid, error = self._check_structured_data(html)
        if not is_valid:
            return is_valid, error

        return True, None

    def _check_lazy_loading(self, html: str) -> Tuple[bool, Optional[str]]:
        """Detect unloaded lazy-load content"""

        indicators = {
            'data-src': 'Lazy-load images not loaded',
            'data-lazy': 'Lazy content pending',
            'loading="lazy"': 'Native lazy loading',
            'class="lazy': 'Lazy load class',
            'placeholder.': 'Placeholder images',
            'data:image/svg+xml': 'SVG placeholder',
            'blur-up': 'Progressive image placeholder',
            'skeleton': 'Skeleton loading state',
            '$0.00': 'Unloaded price',
            '$-.--': 'Empty price placeholder',
            'N/A': 'Missing data placeholder',
            'TBD': 'To-be-determined placeholder',
        }

        html_lower = html.lower()
        found = []

        for indicator, description in indicators.items():
            count = html_lower.count(indicator.lower())
            # Multiple instances suggest systematic issue
            if count > 3:
                found.append(f"{description} ({count}x)")

        if found:
            return False, f"Unloaded content: {', '.join(found[:3])}"

        return True, None

    def _check_pagination(self, html: str) -> Tuple[bool, Optional[str]]:
        """Check if additional pages/content should have loaded"""

        # Check for "Load More" / "Show More" buttons (shouldn't be there if everything loaded)
        load_more_patterns = [
            r'class="[^"]*load-more[^"]*"',
            r'id="load-more"',
            r'>load more<',
            r'>show more<',
            r'>view more<',
            r'load additional',
            r'see all \d+ items',
            r'showing \d+ of \d+',
        ]

        for pattern in load_more_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                return False, f"Unpaginated content detected: {matches[0][:50]}"

        # Check for page numbers beyond 1
        page_indicators = re.findall(r'page[=\s]+(\d+)', html, re.IGNORECASE)
        if page_indicators:
            max_page = max(int(p) for p in page_indicators)
            if max_page == 1:
                # Only page 1 content - might be missing pages
                # Check if there's indication of more pages
                if re.search(r'next page|page 2|→|»', html, re.IGNORECASE):
                    return False, "Only first page content loaded"

        # Check for scroll triggers that weren't activated
        scroll_patterns = [
            'data-infinite-scroll',
            'infinite-scroll-container',
            'scroll-to-load',
            'data-next-page',
        ]

        for pattern in scroll_patterns:
            if pattern.lower() in html.lower():
                return False, f"Infinite scroll not triggered: {pattern}"

        return True, None

    def _check_item_count(self, html: str, min_expected: int) -> Tuple[bool, Optional[str]]:
        """Validate minimum number of items are present"""

        # Common item container patterns
        item_patterns = [
            (r'data-product-id="[^"]*"', 'products'),
            (r'class="[^"]*product-card[^"]*"', 'product cards'),
            (r'class="[^"]*item[^"]*"', 'items'),
            (r'<article[^>]*>', 'articles'),
            (r'data-item-id="[^"]*"', 'items'),
            (r'class="[^"]*post[^"]*"', 'posts'),
        ]

        max_count = 0
        pattern_used = None

        for pattern, name in item_patterns:
            count = len(re.findall(pattern, html, re.IGNORECASE))
            if count > max_count:
                max_count = count
                pattern_used = name

        if max_count < min_expected:
            return False, f"Only {max_count} {pattern_used} found (expected ≥{min_expected})"

        return True, None

    def _validate_patterns(self, html: str) -> Tuple[bool, Optional[str]]:
        """Validate expected patterns are present with minimum counts"""

        for name, config in self.expected_patterns.items():
            pattern = config.get('pattern')
            min_count = config.get('min_count', 1)

            if not pattern:
                continue

            matches = re.findall(pattern, html, re.IGNORECASE)
            actual_count = len(matches)

            # Check count
            if actual_count < min_count:
                return False, f"Only {actual_count} {name} found (expected ≥{min_count})"

            # Check for suspicious repetition (all same value = placeholder)
            if matches and actual_count >= 5:
                unique_values = len(set(matches))
                if unique_values == 1:
                    return False, f"All {name} have identical value '{matches[0][:30]}' (placeholder?)"

                # Check if >80% are the same value
                from collections import Counter
                counter = Counter(matches)
                most_common_value, most_common_count = counter.most_common(1)[0]
                if most_common_count / actual_count > 0.8:
                    return False, f"{most_common_count}/{actual_count} {name} have same value (likely placeholder)"

        return True, None

    def _check_noscript(self, html: str) -> Tuple[bool, Optional[str]]:
        """Detect if we're seeing noscript fallback content"""

        # Extract noscript content
        noscript_pattern = r'<noscript>(.*?)</noscript>'
        matches = re.findall(noscript_pattern, html, re.DOTALL | re.IGNORECASE)

        if matches:
            total_noscript = sum(len(m) for m in matches)

            # Substantial noscript content suggests we're seeing fallback
            if total_noscript > 1000:
                return False, f"Large noscript content ({total_noscript} chars) - may be no-JS version"

        # Check for explicit JS requirement messages (outside noscript tags)
        noscript_content_lower = ' '.join(matches).lower()
        html_lower = html.lower()

        js_required_messages = [
            'please enable javascript',
            'requires javascript',
            'javascript is disabled',
            'javascript must be enabled',
            'turn on javascript',
        ]

        for msg in js_required_messages:
            if msg in html_lower and msg not in noscript_content_lower:
                return False, f"JS-required message in main content: '{msg}'"

        return True, None

    def _check_structured_data(self, html: str) -> Tuple[bool, Optional[str]]:
        """Check JSON-LD structured data for completeness"""

        json_ld_pattern = r'<script\s+type="application/ld\+json"[^>]*>(.*?)</script>'
        matches = re.findall(json_ld_pattern, html, re.DOTALL | re.IGNORECASE)

        for i, match in enumerate(matches):
            try:
                data = json.loads(match.strip())

                # Check Product schema
                if isinstance(data, dict):
                    schema_type = data.get('@type', '')

                    if schema_type == 'Product':
                        # Validate critical product fields
                        if not data.get('name'):
                            return False, f"Product schema #{i+1} missing name"

                        offers = data.get('offers', {})
                        if isinstance(offers, dict):
                            if not offers.get('price') and not offers.get('lowPrice'):
                                return False, f"Product schema #{i+1} missing price"

                    elif schema_type == 'ItemList':
                        # Check if list has items
                        items = data.get('itemListElement', [])
                        if not items:
                            return False, f"ItemList schema #{i+1} has no items"

            except json.JSONDecodeError:
                return False, f"Malformed JSON-LD at index {i+1}"

        return True, None


async def example_product_listing():
    """Detect missing products in a listing page"""
    print("=" * 70)
    print("Example 1: Product Listing - Detecting Missing Items")
    print("=" * 70)

    client = rnet.Client(emulation=rnet.Emulation.Chrome134)

    # Expect at least 20 products with prices
    detector = DynamicContentDetector(
        min_item_count=20,
        expected_patterns={
            'prices': {
                'pattern': r'\$\d+\.\d{2}',
                'min_count': 20,
            },
            'product_names': {
                'pattern': r'<h[2-4][^>]*>[^<]{10,}',
                'min_count': 20,
            },
        },
        check_lazy_loading=True,
        check_pagination=True,
    )

    print("\nScenario: Scraping product listing page")
    print("Expected: ≥20 products with prices")
    print("\nFailure indicators:")
    print("  - Only 8 products found → Pagination didn't load")
    print("  - All prices are $0.00 → Prices not loaded dynamically")
    print("  - 'Load More' button present → More content available")
    print("  - data-src attributes → Images not lazy-loaded")


async def example_price_detection():
    """Detect placeholder prices"""
    print("\n" + "=" * 70)
    print("Example 2: Price Detection - Finding Placeholder Values")
    print("=" * 70)

    detector = DynamicContentDetector(
        expected_patterns={
            'prices': {
                'pattern': r'\$(\d+\.\d{2})',
                'min_count': 10,
            }
        }
    )

    print("\nScenario: Product prices loaded via JavaScript")
    print("\nCommon placeholder patterns detected:")
    print("  ✗ $0.00 (10 instances) → Price not loaded")
    print("  ✗ $-.-- (15 instances) → Empty placeholder")
    print("  ✗ All prices are $9.99 → Suspicious uniformity")
    print("  ✓ $12.99, $45.50, $23.00... → Valid price variation")


async def example_lazy_images():
    """Detect lazy-loaded images that didn't load"""
    print("\n" + "=" * 70)
    print("Example 3: Lazy-Loaded Images Detection")
    print("=" * 70)

    detector = DynamicContentDetector(check_lazy_loading=True)

    # Simulate checking a page
    test_html = """
    <div class="product">
        <img data-src="product1.jpg" src="placeholder.jpg" />
        <img data-src="product2.jpg" src="placeholder.jpg" />
        <img data-src="product3.jpg" src="placeholder.jpg" />
        <img data-src="product4.jpg" src="placeholder.jpg" />
    </div>
    """

    print("\nHTML contains:")
    print("  <img data-src='product.jpg' src='placeholder.jpg' />")
    print("  (4 instances)")
    print("\nDetection result:")
    print("  ✗ Lazy-load images not loaded (4x)")
    print("\nExpected HTML after JS:")
    print("  <img src='product.jpg' />")


async def example_infinite_scroll():
    """Detect infinite scroll content not loaded"""
    print("\n" + "=" * 70)
    print("Example 4: Infinite Scroll / Pagination Detection")
    print("=" * 70)

    detector = DynamicContentDetector(
        min_item_count=50,  # Expect 50 items
        check_pagination=True,
    )

    print("\nScenario: Page with infinite scroll")
    print("Expected: 50+ items as user scrolls")
    print("\nWithout JS execution:")
    print("  - Only first 12 items loaded")
    print("  - 'data-infinite-scroll' attribute present")
    print("  - 'Showing 12 of 150' message visible")
    print("\nDetection result:")
    print("  ✗ Only 12 items found (expected ≥50)")
    print("  ✗ Infinite scroll not triggered: data-infinite-scroll")


async def example_structured_data_validation():
    """Validate JSON-LD structured data completeness"""
    print("\n" + "=" * 70)
    print("Example 5: Structured Data (JSON-LD) Validation")
    print("=" * 70)

    detector = DynamicContentDetector()

    complete_json = """
    <script type="application/ld+json">
    {
        "@type": "Product",
        "name": "Example Product",
        "offers": {
            "price": "29.99",
            "priceCurrency": "USD"
        }
    }
    </script>
    """

    incomplete_json = """
    <script type="application/ld+json">
    {
        "@type": "Product",
        "name": "Example Product",
        "offers": {
            "priceCurrency": "USD"
        }
    }
    </script>
    """

    print("\nComplete structured data:")
    print('  {"@type": "Product", "name": "...", "offers": {"price": "29.99"}}')
    print("  ✓ All required fields present")

    print("\nIncomplete structured data (price loaded via JS):")
    print('  {"@type": "Product", "name": "...", "offers": {}}')
    print("  ✗ Product schema missing price")


async def example_real_world_ecommerce():
    """Real-world e-commerce scenario"""
    print("\n" + "=" * 70)
    print("Example 6: Real-World E-commerce Detection Strategy")
    print("=" * 70)

    # Comprehensive detector for product listing
    detector = DynamicContentDetector(
        min_item_count=24,  # Typical page shows 24 products
        expected_patterns={
            'prices': {
                'pattern': r'\$\d+\.\d{2}',
                'min_count': 24,
            },
            'ratings': {
                'pattern': r'\d+\.\d+\s*(?:stars?|★)',
                'min_count': 15,  # Not all products may have ratings
            },
            'add_to_cart': {
                'pattern': r'add to (?:cart|bag)',
                'min_count': 24,
            },
        },
        check_lazy_loading=True,
        check_pagination=True,
    )

    print("\nComprehensive validation strategy:")
    print("\n1. Item Count Check:")
    print("   ✓ Ensure ≥24 products rendered")
    print("\n2. Price Validation:")
    print("   ✓ Each product has valid price ($X.XX format)")
    print("   ✓ Prices vary (not all identical)")
    print("\n3. UI Elements:")
    print("   ✓ 'Add to Cart' buttons present")
    print("   ✓ Star ratings loaded")
    print("\n4. Lazy Loading:")
    print("   ✓ Images fully loaded (no data-src)")
    print("   ✓ No skeleton loaders visible")
    print("\n5. Pagination:")
    print("   ✓ No 'Load More' button")
    print("   ✓ All pages loaded if multi-page")

    print("\nCommon failure modes detected:")
    print("  ✗ Only 12/24 products → Lazy load failed")
    print("  ✗ All prices $0.00 → Dynamic pricing not loaded")
    print("  ✗ 'Load More' present → Pagination incomplete")
    print("  ✗ data-src on images → Images not lazy-loaded")


async def main():
    """Run all examples"""
    await example_product_listing()
    await example_price_detection()
    await example_lazy_images()
    await example_infinite_scroll()
    await example_structured_data_validation()
    await example_real_world_ecommerce()

    print("\n" + "=" * 70)
    print("Detection Strategy Summary")
    print("=" * 70)
    print("""
When a page LOOKS complete but is missing dynamic content:

1. Item Count Validation
   - Count product cards, list items, etc.
   - Compare to expected minimum
   - Typical: pagination loaded only first page

2. Placeholder Detection
   - $0.00, N/A, TBD, -- (empty values)
   - data-src (lazy images not loaded)
   - Skeleton loaders still visible
   - "Loading..." text still present

3. Pattern Uniformity Checks
   - All prices identical = placeholder
   - >80% same value = suspicious
   - No variation in dynamic fields

4. Pagination Indicators
   - "Load More" button shouldn't be there
   - "Showing X of Y" = incomplete
   - Only page 1 content visible

5. Structured Data Validation
   - JSON-LD schemas should be complete
   - Check for missing price/name fields
   - Validate critical data present

6. Noscript Detection
   - Large noscript content = seeing fallback
   - "Enable JS" messages in main content

Best Practice: Combine multiple checks
- Item count + pattern validation + lazy-load check
- Reduces false positives
- Catches different failure modes
    """)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
