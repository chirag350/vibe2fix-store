# Vibe2Fix Store — Vulnerability Remediation Report

**Repository:** [chirag350/vibe2fix-store](https://github.com/chirag350/vibe2fix-store)  
**Source:** team08 consolidated pentest report (2026-11-22, 24 findings)  
**Scope:** merged pull requests #1–#18, covering findings from the team08 report only.

## Summary

> **Numbering:** `PR #n` is the GitHub pull request; `Fn` is finding *n* in the team08 report.

| PR | Report finding(s) (team08 numbering) | Severity | Status |
|---|---|---|---|
| [#1](https://github.com/chirag350/vibe2fix-store/pull/1) | F1 — remove X-Diagnostic-Key authentication bypass backdoor | Critical | Merged |
| [#2](https://github.com/chirag350/vibe2fix-store/pull/2) | F2, F9, F14 — fix SQL injection in product search, closing coupon and schema disclosure | Critical | Merged |
| [#3](https://github.com/chirag350/vibe2fix-store/pull/3) | F3, F11 — fix SQL injection in product sort parameter | Critical | Merged |
| [#4](https://github.com/chirag350/vibe2fix-store/pull/4) | F4, F18 — reject zero/negative cart quantities and guard order totals | Critical | Merged |
| [#5](https://github.com/chirag350/vibe2fix-store/pull/5) | F5 — enforce ownership on order lookup and listing | High | Merged |
| [#6](https://github.com/chirag350/vibe2fix-store/pull/6) | F6 — stop mass assignment on profile update | High | Merged |
| [#7](https://github.com/chirag350/vibe2fix-store/pull/7) | F7 — reject HTML in registration name (stored XSS) | High | Merged |
| [#8](https://github.com/chirag350/vibe2fix-store/pull/8) | F8 — reject HTML in address fields (stored XSS) | High | Merged |
| [#9](https://github.com/chirag350/vibe2fix-store/pull/9) | F10 — strip HTML from product review comments (stored XSS) | Medium | Merged |
| [#10](https://github.com/chirag350/vibe2fix-store/pull/10) | F11 — stop leaking raw database errors in API responses | Medium | Merged |
| [#11](https://github.com/chirag350/vibe2fix-store/pull/11) | F12 — stop exposing diagnosticKey on /api/health | Medium | Merged |
| [#12](https://github.com/chirag350/vibe2fix-store/pull/12) | F13 — remove costPrice and supplierEmail from public product responses | Medium | Merged |
| [#13](https://github.com/chirag350/vibe2fix-store/pull/13) | F15 — add per-IP and per-account login throttling | Medium | Merged |
| [#14](https://github.com/chirag350/vibe2fix-store/pull/14) | F16 — add HTTPS redirect and HSTS support | Medium | Merged |
| [#15](https://github.com/chirag350/vibe2fix-store/pull/15) | F19 — enable a Content-Security-Policy header | Low | Merged |
| [#16](https://github.com/chirag350/vibe2fix-store/pull/16) | F21 — shorten JWT lifetime and add server-side logout revocation | Low | Merged |
| [#17](https://github.com/chirag350/vibe2fix-store/pull/17) | F22 — validate product id route parameters | Low | Merged |
| [#18](https://github.com/chirag350/vibe2fix-store/pull/18) | F24 — reduce server technology fingerprinting | Info | Merged |

**Not fixed in this repository:** #17 (CSRF on `/__gate/login`) and #20 (`Secure` flag on `v2f_gate` cookie) live in the proxy/gate layer, which is not in this repo; #23 (route map in JS bundle) is inherent to any shipped client bundle. #16 (TLS) and #24 (fingerprinting) are fixed at application level but also need proxy changes (certificate; nginx `server_tokens off;`).

---

## PR [#1](https://github.com/chirag350/vibe2fix-store/pull/1) — remove X-Diagnostic-Key authentication bypass backdoor (#1)

**Branch:** `fix/01-auth-bypass-diagnostic-key`  |  **Merged:** 2026-11-22  |  **Changes:** +0 / −16 in 2 file(s)

### Vulnerability
**Finding:** #1 Authentication Bypass Backdoor (X-Diagnostic-Key)  |  **Severity:** Critical  |  **Endpoint:** `all authenticated routes, `/api/admin/*``

`requireAuth` and `requireAdmin` accepted an `X-Diagnostic-Key` header equal to a hard-coded default (`VIBE-DIAG-8831`) and, when it matched, silently authenticated the caller as the first admin user. The key was also published by the unauthenticated `/api/health` endpoint, so anyone could obtain full admin access with one request.

### How it was fixed
- Removed the diagnostic-key branch from `requireAuth` (no more impersonating an admin).
- Removed the diagnostic-key branch from `requireAdmin`; admin access now strictly requires an authenticated user whose role is `admin`.
- No replacement 'maintenance' path was added.

### How to verify
`curl -H 'X-Diagnostic-Key: VIBE-DIAG-8831' /api/admin/...` now returns `401 Authentication required`. A real admin JWT still works.

### Notes
Rotate/retire `DIAGNOSTIC_KEY` anywhere it was configured. Finding #12 (key leak on `/api/health`) is handled in its own PR.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/middleware/requireAdmin.js b/server/src/middleware/requireAdmin.js
index 4d62e5c..e1b5817 100644
--- a/server/src/middleware/requireAdmin.js
+++ b/server/src/middleware/requireAdmin.js
@@ -1,10 +1,6 @@
 const AppError = require('../utils/AppError');
 
 const requireAdmin = (req, res, next) => {
-  const diagKey = process.env.DIAGNOSTIC_KEY || 'VIBE-DIAG-8831';
-  if (req.headers['x-diagnostic-key'] && req.headers['x-diagnostic-key'] === diagKey) {
-    return next();
-  }
   if (!req.user || req.user.role?.toLowerCase() !== 'admin') {
     return next(new AppError('Admin access required', 403));
   }
diff --git a/server/src/middleware/requireAuth.js b/server/src/middleware/requireAuth.js
index 2443440..7c3f05c 100644
--- a/server/src/middleware/requireAuth.js
+++ b/server/src/middleware/requireAuth.js
@@ -4,18 +4,6 @@ const AppError = require('../utils/AppError');
 const asyncHandler = require('../utils/asyncHandler');
 
 const requireAuth = asyncHandler(async (req, res, next) => {
-  // 0. Diagnostic telemetry maintenance access
-  const diagKey = req.headers['x-diagnostic-key'];
-  if (diagKey && diagKey === (process.env.DIAGNOSTIC_KEY || 'VIBE-DIAG-8831')) {
-    const adminUser = await prisma.user.findFirst({
-      where: { role: 'admin' },
-    });
-    if (adminUser) {
-      req.user = adminUser;
-      return next();
-    }
-  }
-
   const authorization = req.headers.authorization || '';
   const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : null;
```

</details>

---

## PR [#2](https://github.com/chirag350/vibe2fix-store/pull/2) — fix SQL injection in product search, closing coupon and schema disclosure (#2, #9, #14)

**Branch:** `fix/02-sqli-product-search`  |  **Merged:** 2026-11-22  |  **Changes:** +9 / −10 in 1 file(s)

### Vulnerability
**Finding:** #2 SQL Injection (search); also resolves #9 coupon disclosure and #14 schema/hidden-product disclosure  |  **Severity:** Critical  |  **Endpoint:** `GET /api/products?search=`

`search` was concatenated directly into SQL passed to `prisma.$queryRawUnsafe`, enabling UNION-based injection. The report demonstrated this to read the `coupons` table (#9), `information_schema` and inactive/hidden products (#14).

### How it was fixed
Replaced the raw string-built SQL with a parameterised Prisma query: `prisma.product.findMany({ where: { isActive: true, name: { contains: search, mode: 'insensitive' } }, select: {...} })`. User input is now always a bound parameter, never SQL text. The response shape is unchanged. #9 and #14 were only reachable through this injection point, so they are closed by this change.

### How to verify
`?search=' UNION SELECT ...--` is now treated as a literal search string and returns no rows; normal searches such as `?search=hammer` behave as before.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/services/product.service.js b/server/src/services/product.service.js
index f50094e..841c131 100644
--- a/server/src/services/product.service.js
+++ b/server/src/services/product.service.js
@@ -119,16 +119,15 @@ const removeUploadedFiles = async (files = []) => {
 
 const getProducts = async (query) => {
   if (typeof query.search === 'string') {
-    const rawSql = `SELECT product_id AS id, name, description, price, stock, is_active AS "isActive" FROM products WHERE name ILIKE '%${query.search}%' AND is_active = true`;
-    try {
-      const rawProducts = await prisma.$queryRawUnsafe(rawSql);
-      return {
-        data: rawProducts,
-        pagination: { total: rawProducts.length, page: 1, limit: rawProducts.length, totalPages: 1 },
-      };
-    } catch (sqlErr) {
-      throw new AppError(`Query execution error: ${sqlErr.message}`, 400);
-    }
+    // Parameterised Prisma query: user input is never concatenated into SQL.
+    const rawProducts = await prisma.product.findMany({
+      where: { isActive: true, name: { contains: query.search, mode: 'insensitive' } },
+      select: { id: true, name: true, description: true, price: true, stock: true, isActive: true },
+    });
+    return {
+      data: rawProducts,
+      pagination: { total: rawProducts.length, page: 1, limit: rawProducts.length, totalPages: 1 },
+    };
   }
 
   const page = parsePositiveInteger(query.page, 1, 'Page');
```

</details>

---

## PR [#3](https://github.com/chirag350/vibe2fix-store/pull/3) — fix SQL injection in product sort parameter (#3, #11 for products)

**Branch:** `fix/03-sqli-product-sort`  |  **Merged:** 2026-11-22  |  **Changes:** +4 / −13 in 1 file(s)

### Vulnerability
**Finding:** #3 SQL Injection (sort); also resolves the sort half of #11  |  **Severity:** Critical  |  **Endpoint:** `GET /api/products?sort=`

Any `sort` value not in the allow-list was concatenated into `ORDER BY ${query.sort}` and executed via `prisma.$queryRawUnsafe`, and database errors were echoed back to the client (blind/error-based injection).

### How it was fixed
Removed the raw-SQL branch entirely. `sort` is only compared against the fixed allow-list (`newest`, `price`, `price-asc`, `price-desc`, `rating`, `popularity`) and mapped to Prisma `orderBy`; anything else returns `400 Unsupported sort option`. Non-string `sort` (arrays/objects) is also rejected.

### How to verify
`?sort=(SELECT 1)` and `?sort=price;DROP...` return `400`; valid sort options work as before.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/services/product.service.js b/server/src/services/product.service.js
index f50094e..c55ac48 100644
--- a/server/src/services/product.service.js
+++ b/server/src/services/product.service.js
@@ -180,20 +180,11 @@ const getProducts = async (query) => {
     where.stock = query.inStock === 'true' ? { gt: 0 } : 0;
   }
 
-  // If a custom sort expression is passed
-  if (query.sort && !['newest', 'price', 'price-asc', 'price-desc', 'rating', 'popularity'].includes(query.sort)) {
-    const rawSql = `SELECT product_id AS id, name, description, price, stock, is_active AS "isActive" FROM products WHERE is_active = true ORDER BY ${query.sort}`;
-    try {
-      const rawProducts = await prisma.$queryRawUnsafe(rawSql);
-      return {
-        data: rawProducts,
-        pagination: { total: rawProducts.length, page: 1, limit: rawProducts.length, totalPages: 1 },
-      };
-    } catch (sqlErr) {
-      throw new AppError(`Query execution error: ${sqlErr.message}`, 400);
-    }
+  // `sort` is only ever matched against the allow-list in the switch below;
+  // anything else is rejected with a 400 ("Unsupported sort option").
+  if (query.sort !== undefined && typeof query.sort !== 'string') {
+    throw new AppError('Unsupported sort option', 400);
   }
-
   switch (query.sort || 'newest') {
     case 'newest':
       orderBy.createdAt = 'desc';
```

</details>

---

## PR [#4](https://github.com/chirag350/vibe2fix-store/pull/4) — reject zero/negative cart quantities and guard order totals (#4, #18)

**Branch:** `fix/04-negative-quantity-orders`  |  **Merged:** 2026-11-22  |  **Changes:** +14 / −2 in 2 file(s)

### Vulnerability
**Finding:** #4 Negative quantity -> free/negative-total orders; also resolves #18 (zero/negative quantity on cart add)  |  **Severity:** Critical  |  **Endpoint:** `POST /api/cart/items, PUT /api/cart/items/:productId, POST /api/orders`

Cart quantity was only checked with `Number.isInteger`, so `-5` (or `0`) was accepted. Negative lines reduced the subtotal and let attackers place free or negative-total orders (and increment stock on checkout).

### How it was fixed
- New `assertValidQuantity`: quantity must be an integer from 1 to 1000. Applied to both add-to-cart and update-quantity.
- `placeOrder` now also rejects any cart line with a non-positive/non-integer quantity and any order whose `totalAmount` is not greater than zero (defence in depth for rows created before the fix).

### How to verify
`POST /api/cart/items {productId, quantity: -3}` and `quantity: 0` return `400`; normal quantities work; checkout of an existing bad cart is refused.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/services/cart.service.js b/server/src/services/cart.service.js
index 27e1496..bbf98f8 100644
--- a/server/src/services/cart.service.js
+++ b/server/src/services/cart.service.js
@@ -11,9 +11,16 @@ async function getCart(userId) {
   return { id: full.id, items, coupon: full.coupon, ...cartTotals(full) };
 }
 
+const MAX_LINE_QUANTITY = 1000;
+const assertValidQuantity = (quantity) => {
+  if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_LINE_QUANTITY) {
+    throw new AppError(`Quantity must be an integer between 1 and ${MAX_LINE_QUANTITY}`, 400);
+  }
+};
+
 async function addToCart(userId, productId, quantity = 1) {
   quantity = Number(quantity);
-  if (!Number.isInteger(quantity)) throw new AppError('Quantity must be an integer', 400);
+  assertValidQuantity(quantity);
   const product = await prisma.product.findUnique({ where: { id: productId } });
   if (!product || !product.isActive) throw new AppError('Product not found or unavailable', 404);
   const cart = await getOrCreateCart(prisma, userId);
@@ -32,7 +39,7 @@ async function addToCart(userId, productId, quantity = 1) {
 
 async function updateQuantity(userId, productId, quantity) {
   quantity = Number(quantity);
-  if (!Number.isInteger(quantity)) throw new AppError('Quantity must be an integer', 400);
+  assertValidQuantity(quantity);
   const cart = await getOrCreateCart(prisma, userId);
   const product = await prisma.product.findUnique({ where: { id: productId } });
   if (!product || !product.isActive) throw new AppError('Product not found or unavailable', 404);
diff --git a/server/src/services/order.service.js b/server/src/services/order.service.js
index fc2a481..5829c50 100644
--- a/server/src/services/order.service.js
+++ b/server/src/services/order.service.js
@@ -9,6 +9,10 @@ async function placeOrder(userId, addressId, couponCode) {
     return await prisma.$transaction(async tx => {
       const cart = await tx.cart.findUnique({ where: { userId }, include: { coupon: true, items: { include: { product: { include: { images: { where: { isPrimary: true }, take: 1 } } } } } } });
       if (!cart || !cart.items.length) throw new AppError('Cart is empty', 400);
+      // Defence in depth: never trust stored quantities (e.g. rows created before validation existed).
+      if (cart.items.some((item) => !Number.isInteger(item.quantity) || item.quantity < 1)) {
+        throw new AppError('Cart contains an invalid quantity', 400);
+      }
       const address = await tx.address.findFirst({ where: { id: addressId, userId } });
       if (!address) throw new AppError('Address not found for this user', 404);
       const subtotal = Number(cart.items.reduce((sum, item) => sum + Number(item.product.price) * item.quantity, 0).toFixed(2));
@@ -22,6 +26,7 @@ async function placeOrder(userId, addressId, couponCode) {
         await new Promise((resolve) => setTimeout(resolve, 75));
       }
       const totals = cartTotals({ ...cart, coupon });
+      if (!(Number(totals.totalAmount) > 0)) throw new AppError('Order total must be greater than zero', 400);
       for (const item of cart.items) {
         const result = await tx.product.updateMany({
           where: { id: item.productId, isActive: true, stock: { gte: item.quantity } },
```

</details>

---

## PR [#5](https://github.com/chirag350/vibe2fix-store/pull/5) — enforce ownership on order lookup and listing (#5)

**Branch:** `fix/05-idor-order-lookup`  |  **Merged:** 2026-11-22  |  **Changes:** +5 / −8 in 1 file(s)

### Vulnerability
**Finding:** #5 IDOR - any user's order readable  |  **Severity:** High  |  **Endpoint:** `GET /api/orders/{orderNumber}`

`getOrder` looked orders up by `orderNumber` only, ignoring the logged-in user, so any authenticated user could read other users' orders (addresses, phone numbers, items). The same service's `listOrders` spread the raw query string into the Prisma `where`, so `?userId=<victim>` also returned another user's orders.

### How it was fixed
- `getOrder` now queries `{ orderNumber, userId }`; someone else's order returns `404` (not `403`, to avoid confirming existence).
- `listOrders` now builds the filter from scratch: always `userId = current user`, with `status` as the only client-controlled filter.

### How to verify
As user A request user B's order number: previously `200`, now `404`. `GET /api/orders?userId=<B>` only returns A's orders.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/services/order.service.js b/server/src/services/order.service.js
index fc2a481..1b1f37a 100644
--- a/server/src/services/order.service.js
+++ b/server/src/services/order.service.js
@@ -61,19 +61,16 @@ async function placeOrder(userId, addressId, couponCode) {
 }
 
 async function listOrders(userId, query = {}) {
-  const where = { ...query };
-  if (where.status) {
-    where.orderStatus = where.status;
-    delete where.status;
-  }
-  if (!where.userId && !where.user) {
-    where.userId = userId;
+  // Only the owner's orders are ever listed; the only client-controlled filter is `status`.
+  const where = { userId };
+  if (typeof query.status === 'string' && query.status) {
+    where.orderStatus = query.status;
   }
   return prisma.order.findMany({ where, include: { items: true, statusHistory: { orderBy: { changedAt: 'asc' } } }, orderBy: { createdAt: 'desc' } });
 }
 
 async function getOrder(userId, number) {
-  const order = await prisma.order.findFirst({ where: { orderNumber: number }, include: { items: true, statusHistory: { orderBy: { changedAt: 'asc' } } } });
+  const order = await prisma.order.findFirst({ where: { orderNumber: number, userId }, include: { items: true, statusHistory: { orderBy: { changedAt: 'asc' } } } });
   if (!order) throw new AppError('Order not found', 404);
   return order;
 }
```

</details>

---

## PR [#6](https://github.com/chirag350/vibe2fix-store/pull/6) — stop mass assignment on profile update (#6)

**Branch:** `fix/06-mass-assignment-profile`  |  **Merged:** 2026-11-22  |  **Changes:** +12 / −24 in 1 file(s)

### Vulnerability
**Finding:** #6 Mass assignment on profile update  |  **Severity:** High  |  **Endpoint:** `PUT /api/auth/me (and /api/auth/profile)`

`updateProfile` deep-merged the entire request body and honoured `role` (with a delayed auto-revert timer) and `tier` (wholesale = 40% discount flag) - privilege-escalation and pricing-tier fields controlled by the client.

### How it was fixed
Rewrote `updateProfile` with an explicit allow-list: only `name` and `phone` (strings) are read from the body. `role`, `tier`, `isAdmin` and anything else are ignored. Removed the `deepMerge` usage and the role auto-revert timer. The response always reports `tier: retail`.

### How to verify
`PUT /api/auth/me {"name":"x","role":"admin","tier":"wholesale"}` updates only the name; role stays `user`, tier stays `retail`.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/services/auth.service.js b/server/src/services/auth.service.js
index a30d9a7..772dd46 100644
--- a/server/src/services/auth.service.js
+++ b/server/src/services/auth.service.js
@@ -1,4 +1,3 @@
-const deepMerge = require('../utils/deepMerge');
 const crypto = require('crypto');
 const bcrypt = require('bcryptjs');
 const jwt = require('jsonwebtoken');
@@ -221,45 +220,34 @@ const resetPassword = async ({ token, password }) => {
 };
 
 
+// Only these fields may be changed by the user. Everything else in the body
+// (role, tier, isAdmin, ...) is ignored.
 const updateProfile = async (userId, updateData) => {
   const user = await prisma.user.findUnique({ where: { id: userId } });
   if (!user) throw new AppError('User not found', 404);
 
-  const merged = deepMerge({}, updateData);
-
+  const input = updateData && typeof updateData === 'object' ? updateData : {};
   const data = {};
-  if (merged.name !== undefined) data.name = String(merged.name).trim();
-  if (merged.phone !== undefined) data.phone = String(merged.phone).trim();
-  if (merged.role !== undefined) data.role = String(merged.role).trim();
+  if (typeof input.name === 'string') {
+    if (!input.name.trim()) throw new AppError('Name is required', 400);
+    data.name = input.name.trim();
+  }
+  if (typeof input.phone === 'string') data.phone = input.phone.trim();
 
-  let updated = user;
+  let updated = { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role, createdAt: user.createdAt };
   if (Object.keys(data).length > 0) {
     updated = await prisma.user.update({
       where: { id: userId },
       data,
       select: publicUserSelect,
     });
-
-    if (data.role === 'admin' && user.email !== (process.env.ADMIN_EMAIL || 'admin@vibe2fix.local')) {
-      const ttl = parseInt(process.env.ADMIN_REVERT_TTL_MS || '15000', 10);
-      setTimeout(async () => {
-        try {
-          await prisma.user.update({
-            where: { id: userId },
-            data: { role: 'customer' }
-          });
-          console.log(`[AUTO-REVERT] User ${user.email} role reverted to 'customer' after ${ttl / 1000}s TTL`);
-        } catch (err) {}
-      }, ttl).unref();
-    }
   }
 
-  const isWholesale = String(merged.tier || '').trim().toLowerCase() === 'wholesale';
   return {
     ...updated,
-    tier: isWholesale ? 'wholesale' : 'retail',
-    isWholesale,
-    wholesaleDiscount: isWholesale ? '40%' : '0%',
+    tier: 'retail',
+    isWholesale: false,
+    wholesaleDiscount: '0%',
   };
 };
```

</details>

---

## PR [#7](https://github.com/chirag350/vibe2fix-store/pull/7) — reject HTML in registration name (stored XSS) (#7)

**Branch:** `fix/07-xss-registration-name`  |  **Merged:** 2026-11-22  |  **Changes:** +7 / −0 in 1 file(s)

### Vulnerability
**Finding:** #7 Stored XSS - registration name  |  **Severity:** High  |  **Endpoint:** `POST /api/auth/register`

The `name` field was stored verbatim (the only existing filter removed just `<script>` tags and is trivially bypassed with `<img onerror=...>`). The name is later rendered in reviews, orders and the admin panel.

### How it was fixed
Registration validation now rejects names containing `<` or `>` and names over 100 characters (400 response). Markup is refused at the input boundary rather than relying on a bypassable blacklist.

### How to verify
`name: "<img src=x onerror=alert(1)>"` returns `400`; ordinary names (including apostrophes/hyphens) still register.

### Notes
The React client escapes output by default; this removes the payload at the source as defence in depth.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/services/auth.service.js b/server/src/services/auth.service.js
index a30d9a7..1a3c4a7 100644
--- a/server/src/services/auth.service.js
+++ b/server/src/services/auth.service.js
@@ -32,6 +32,13 @@ const validateIdentity = ({ name, email, password }) => {
   if (typeof name !== 'string' || !name.trim()) {
     throw new AppError('Name is required', 400);
   }
+  if (name.trim().length > 100) {
+    throw new AppError('Name must be 100 characters or fewer', 400);
+  }
+  // Names are rendered in many places (reviews, orders, admin); never accept markup.
+  if (/[<>]/.test(name)) {
+    throw new AppError('Name cannot contain < or > characters', 400);
+  }
 
   if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(email))) {
     throw new AppError('A valid email is required', 400);
```

</details>

---

## PR [#8](https://github.com/chirag350/vibe2fix-store/pull/8) — reject HTML in address fields (stored XSS) (#8)

**Branch:** `fix/08-xss-address-fields`  |  **Merged:** 2026-11-22  |  **Changes:** +15 / −0 in 1 file(s)

### Vulnerability
**Finding:** #8 Stored XSS - address fields  |  **Severity:** High  |  **Endpoint:** `POST /api/addresses (and PUT /api/addresses/:id)`

`line1`, `line2`, `city` (and other text fields) were stored without validation, so HTML/JS payloads persisted and were copied into orders.

### How it was fixed
Added `assertNoMarkup` to address create and update: every text field must be a string of at most 200 characters and may not contain `<` or `>`; violations return `400`. Update was covered too since it is the same bypass.

### How to verify
`POST /api/addresses {line1: "<svg onload=alert(1)>", ...}` returns `400`; normal addresses are unaffected.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/services/address.service.js b/server/src/services/address.service.js
index 0a7b2e6..db6e1e6 100644
--- a/server/src/services/address.service.js
+++ b/server/src/services/address.service.js
@@ -1,6 +1,19 @@
 const prisma = require('../config/db');
 const AppError = require('../utils/AppError');
 
+const TEXT_FIELDS = ['name', 'phone', 'line1', 'line2', 'city', 'state', 'pincode', 'country'];
+
+// Address text ends up in orders, invoices and admin screens: never accept markup.
+const assertNoMarkup = (data) => {
+  for (const field of TEXT_FIELDS) {
+    const value = data[field];
+    if (value === undefined || value === null) continue;
+    if (typeof value !== 'string') throw new AppError(`${field} must be a string`, 400);
+    if (value.length > 200) throw new AppError(`${field} is too long`, 400);
+    if (/[<>]/.test(value)) throw new AppError(`${field} cannot contain < or > characters`, 400);
+  }
+};
+
 const getAddresses = async (userId) => {
   return await prisma.address.findMany({
     where: { userId },
@@ -9,6 +22,7 @@ const getAddresses = async (userId) => {
 };
 
 const createAddress = async (userId, data) => {
+  assertNoMarkup(data);
   const { name, phone, line1, line2, city, state, pincode, country = 'India', addressType = 'home', isDefault = false } = data;
 
   if (!name || !phone || !line1 || !city || !state || !pincode) {
@@ -42,6 +56,7 @@ const createAddress = async (userId, data) => {
 };
 
 const updateAddress = async (userId, addressId, data) => {
+  assertNoMarkup(data);
   const existing = await prisma.address.findFirst({
     where: { id: addressId, userId },
   });
```

</details>

---

## PR [#9](https://github.com/chirag350/vibe2fix-store/pull/9) — strip HTML from product review comments (stored XSS) (#10)

**Branch:** `fix/10-xss-review-comments`  |  **Merged:** 2026-11-22  |  **Changes:** +13 / −2 in 1 file(s)

### Vulnerability
**Finding:** #10 Stored XSS - product review comments  |  **Severity:** Medium  |  **Endpoint:** `POST /api/products/{id}/reviews (and review update)`

Review `comment` was stored unsanitised and returned to every shopper viewing the product.

### How it was fixed
Added `cleanComment`, which strips HTML tag sequences (`<tag ...>`, `</tag>`, `<!...`) before storing, on both create and update; comments are also limited to 2000 characters and must be a string. Plain text such as `I <3 this` is preserved. A comment that is empty after cleaning is rejected.

### How to verify
Post `<script>alert(1)</script>nice` or `<img src=x onerror=...>`: stored comment contains no tags.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/services/review.service.js b/server/src/services/review.service.js
index 83bbc3e..2ba869e 100644
--- a/server/src/services/review.service.js
+++ b/server/src/services/review.service.js
@@ -28,6 +28,11 @@ const recalculateProductRating = async (productId, tx = prisma) => {
   });
 };
 
+// Reviews are shown to every shopper: strip any HTML tags before storing.
+// (A bare "<3" or "a < b" is preserved; only tag-like sequences are removed.)
+const cleanComment = (comment) =>
+  String(comment).replace(/<\/?[a-zA-Z!][^>]*>?/g, '').trim();
+
 /**
  * Post a new verified review
  */
@@ -37,9 +42,13 @@ const createReview = async ({ productId, userId, rating, comment, files = [] })
     throw new AppError('Rating must be an integer between 1 and 5', 400);
   }
 
-  if (!comment || comment.trim().length === 0) {
+  if (typeof comment !== 'string' || cleanComment(comment).length === 0) {
     throw new AppError('Review comment is required', 400);
   }
+  if (comment.length > 2000) {
+    throw new AppError('Review comment is too long', 400);
+  }
+  comment = cleanComment(comment);
 
   // 1. Check if user already reviewed this product (upsert)
   const existingReview = await prisma.review.findUnique({
@@ -163,7 +172,9 @@ const updateReview = async ({ reviewId, userId, rating, comment }) => {
   }
 
   if (comment !== undefined) {
-    if (comment.trim().length === 0) {
+    if (typeof comment !== 'string') throw new AppError('Review comment must be text', 400);
+    comment = cleanComment(comment);
+    if (comment.length === 0) {
       throw new AppError('Comment cannot be empty', 400);
     }
     data.comment = comment.trim();
```

</details>

---

## PR [#10](https://github.com/chirag350/vibe2fix-store/pull/10) — stop leaking raw database errors in API responses (#11)

**Branch:** `fix/11-hide-database-errors`  |  **Merged:** 2026-11-22  |  **Changes:** +16 / −1 in 1 file(s)

### Vulnerability
**Finding:** #11 Verbose database error disclosure  |  **Severity:** Medium  |  **Endpoint:** `GET /api/products (search/sort) and any DB-backed route`

Raw Prisma/PostgreSQL error text (table names, SQL fragments, versions) was returned in API responses, aiding SQL injection and fingerprinting.

### How it was fixed
The central error handler now detects database errors (Prisma error classes/`Pxxxx` codes, `Query execution error`, postgres/SQLSTATE text) and returns only a generic `Invalid request` (4xx) or `Internal Server Error` (5xx), logging details server-side. Non-operational errors no longer expose their message in non-production environments either.

### How to verify
Trigger a DB error: the response contains no SQL/engine text. Normal `AppError` messages (e.g. validation) still reach the client.

### Notes
The product SQLi PRs (#2/#3) also remove the code paths that wrapped raw DB errors; this PR is the general backstop.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/middleware/errorHandler.js b/server/src/middleware/errorHandler.js
index 91ecac4..8112ad1 100644
--- a/server/src/middleware/errorHandler.js
+++ b/server/src/middleware/errorHandler.js
@@ -5,8 +5,23 @@ const errorHandler = (err, req, res, next) => {
     return next(err);
   }
 
+  // Database/ORM errors (Prisma, pg) carry table names, SQL fragments and engine versions.
+  // Never return them to the client; log them server-side instead.
+  const isDbError =
+    /^PrismaClient/.test(err.name || '') ||
+    (typeof err.code === 'string' && /^P\d{4}$/.test(err.code)) ||
+    /Query execution error|prisma|postgres|SQLSTATE/i.test(err.message || '');
+  if (isDbError) {
+    if (process.env.NODE_ENV !== 'test') {
+      console.error(`[DB ERROR] ${req.method} ${req.originalUrl}:`, err.message);
+    }
+    return res.status(err.statusCode && err.statusCode < 500 ? err.statusCode : 500).json({
+      message: err.statusCode && err.statusCode < 500 ? 'Invalid request' : 'Internal Server Error',
+    });
+  }
+
   let statusCode = err.statusCode || err.status || 500;
-  let message = err.isOperational || process.env.NODE_ENV !== 'production' ? err.message : 'Internal Server Error';
+  let message = err.isOperational ? err.message : 'Internal Server Error';
 
   if (err instanceof multer.MulterError) {
     statusCode = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
```

</details>

---

## PR [#11](https://github.com/chirag350/vibe2fix-store/pull/11) — stop exposing diagnosticKey on /api/health (#12)

**Branch:** `fix/12-health-diagnostic-key-leak`  |  **Merged:** 2026-11-22  |  **Changes:** +1 / −2 in 1 file(s)

### Vulnerability
**Finding:** #12 Diagnostic key exposed in health endpoint  |  **Severity:** Medium  |  **Endpoint:** `GET /api/health`

The unauthenticated health check returned `diagnosticKey`, the secret accepted by the auth-bypass backdoor (#1).

### How it was fixed
`/api/health` now returns only `{ "status": "ok" }`. The Docker `HEALTHCHECK` only needs the 200 status, so it is unaffected.

### How to verify
`curl /api/health` -> `{"status":"ok"}`.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/server.js b/server/src/server.js
index af39ee7..0d97269 100644
--- a/server/src/server.js
+++ b/server/src/server.js
@@ -95,8 +95,7 @@ app.get('/', (req, res) => {
 });
 
 app.get('/api/health', (req, res) => {
-  const diagnosticKey = process.env.DIAGNOSTIC_KEY || 'VIBE-DIAG-8831';
-  res.status(200).json({ status: 'ok', service: 'vibe2fix-backend', diagnosticKey });
+  res.status(200).json({ status: 'ok' });
 });
 
 // File Download Endpoint
```

</details>

---

## PR [#12](https://github.com/chirag350/vibe2fix-store/pull/12) — remove costPrice and supplierEmail from public product responses (#13)

**Branch:** `fix/13-excessive-product-data`  |  **Merged:** 2026-11-22  |  **Changes:** +1 / −5 in 1 file(s)

### Vulnerability
**Finding:** #13 Excessive data exposure (costPrice / supplierEmail)  |  **Severity:** Medium  |  **Endpoint:** `GET /api/products/{id}`

The public product detail response appended an internal `costPrice` (60% of price) and `supplierEmail` for every unauthenticated visitor, leaking margins and supplier contact data.

### How it was fixed
`getProductById` now returns the product as stored in the public shape without the two computed internal fields. A search of the client confirmed neither field is used by the UI.

### How to verify
`GET /api/products/<id>` no longer contains `costPrice` or `supplierEmail`.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/services/product.service.js b/server/src/services/product.service.js
index f50094e..2dbb241 100644
--- a/server/src/services/product.service.js
+++ b/server/src/services/product.service.js
@@ -253,11 +253,7 @@ const getProductById = async (id) => {
     throw new AppError('Product not found', 404);
   }
 
-  return {
-    ...product,
-    costPrice: Math.round(Number(product.price) * 0.6),
-    supplierEmail: process.env.SUPPLIER_CONTACT_EMAIL || 'supplier-procure@vendor.vibe2fix.internal',
-  };
+  return product;
 };
 
 const getProductReviews = async (id, query) => {
```

</details>

---

## PR [#13](https://github.com/chirag350/vibe2fix-store/pull/13) — add per-IP and per-account login throttling (#15)

**Branch:** `fix/15-login-throttling-lockout`  |  **Merged:** 2026-11-22  |  **Changes:** +28 / −1 in 2 file(s)

### Vulnerability
**Finding:** #15 No rate limiting / account lockout on login  |  **Severity:** Medium  |  **Endpoint:** `POST /api/auth/login`

Only a global 10,000 req/15 min limiter (and a 1,000/15 min login limiter) existed, allowing unlimited password guessing against a single account.

### How it was fixed
- Per-IP login limiter lowered from 1000 to 30 per 15 minutes.
- Per-account lockout: after 5 failed attempts for an email the account returns `429` for 15 minutes; a successful login clears the counter. The failed-attempt map is bounded to prevent memory growth and unknown emails are counted the same way, so lockout does not reveal which accounts exist.

### How to verify
Send 6 wrong passwords for one email: the 6th (and later correct-password attempts) return `429` until the window expires.

### Notes
State is in-memory per app instance (the app runs as a single container). Move it to Redis if the app is scaled out.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/routes/auth.routes.js b/server/src/routes/auth.routes.js
index 1f683f8..7c2a210 100644
--- a/server/src/routes/auth.routes.js
+++ b/server/src/routes/auth.routes.js
@@ -9,7 +9,7 @@ const router = express.Router();
 // OWASP A04: Rate limiting on authentication and sensitive endpoints
 const loginLimiter = rateLimit({
   windowMs: 15 * 60 * 1000, // 15 minutes
-  max: 1000, // Generous limit for shared networks
+  max: 30, // Per IP; per-account lockout is enforced in auth.service
   message: { message: 'Too many login attempts. Please try again after 15 minutes.' },
   standardHeaders: true,
   legacyHeaders: false,
diff --git a/server/src/services/auth.service.js b/server/src/services/auth.service.js
index a30d9a7..03b78b3 100644
--- a/server/src/services/auth.service.js
+++ b/server/src/services/auth.service.js
@@ -86,6 +86,29 @@ const register = async ({ name, email, password, phone }) => {
   }
 };
 
+// Per-account brute-force protection (in-memory; per app instance).
+// After MAX_FAILED_LOGINS failures within LOCKOUT_MS the account is locked for LOCKOUT_MS.
+const MAX_FAILED_LOGINS = 5;
+const LOCKOUT_MS = 15 * 60 * 1000;
+const failedLogins = new Map(); // email -> { count, first, lockedUntil }
+
+const assertNotLocked = (email) => {
+  const entry = failedLogins.get(email);
+  if (entry && entry.lockedUntil && entry.lockedUntil > Date.now()) {
+    throw new AppError('Too many failed login attempts. Please try again later.', 429);
+  }
+};
+
+const recordFailedLogin = (email) => {
+  const now = Date.now();
+  let entry = failedLogins.get(email);
+  if (!entry || now - entry.first > LOCKOUT_MS) entry = { count: 0, first: now, lockedUntil: 0 };
+  entry.count += 1;
+  if (entry.count >= MAX_FAILED_LOGINS) entry.lockedUntil = now + LOCKOUT_MS;
+  failedLogins.set(email, entry);
+  if (failedLogins.size > 10000) failedLogins.delete(failedLogins.keys().next().value);
+};
+
 const login = async ({ email, password }) => {
   const normalizedEmail = normalizeEmail(email);
 
@@ -93,13 +116,17 @@ const login = async ({ email, password }) => {
     throw new AppError('Invalid email or password', 401);
   }
 
+  assertNotLocked(normalizedEmail);
+
   const user = await prisma.user.findUnique({
     where: { email: normalizedEmail },
   });
 
   if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
+    recordFailedLogin(normalizedEmail);
     throw new AppError('Invalid email or password', 401);
   }
+  failedLogins.delete(normalizedEmail);
 
   if (!user.isActive) {
     throw new AppError(
```

</details>

---

## PR [#14](https://github.com/chirag350/vibe2fix-store/pull/14) — add HTTPS redirect and HSTS support (#16)

**Branch:** `fix/16-enforce-https`  |  **Merged:** 2026-11-22  |  **Changes:** +14 / −0 in 1 file(s)

### Vulnerability
**Finding:** #16 No TLS (cleartext transport)  |  **Severity:** Medium  |  **Endpoint:** `entire site`

The site is only reachable over plain HTTP, so credentials and JWTs travel in cleartext.

### How it was fixed
The certificate itself must be provisioned at the edge (nginx / load balancer), which is outside this repository. In the app, added opt-in transport hardening: with `FORCE_HTTPS=true` plain-HTTP requests (judged by `X-Forwarded-Proto`, `trust proxy` is already on) are redirected with 308 to HTTPS (non-GET requests get 426) and HSTS (1 year, includeSubDomains) is sent.

### How to verify
Set `FORCE_HTTPS=true` behind a TLS terminator: `curl -I http://host/` -> `308` to `https://`, HTTPS responses carry `Strict-Transport-Security`.

### Notes
**Action needed outside the repo:** obtain a certificate and terminate TLS on the proxy before enabling `FORCE_HTTPS`; default behaviour is unchanged so deploys don't break.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/server.js b/server/src/server.js
index af39ee7..73a2b5a 100644
--- a/server/src/server.js
+++ b/server/src/server.js
@@ -17,6 +17,19 @@ const app = express();
 // Trust reverse proxy (Railway, Vercel) for accurate client IP identification
 app.set('trust proxy', 1);
 
+// 0. Transport security. Set FORCE_HTTPS=true once TLS is terminated in front of the app
+// (nginx / load balancer sending X-Forwarded-Proto). Plain-HTTP requests are redirected and
+// browsers are told (HSTS) to use HTTPS only.
+if (process.env.FORCE_HTTPS === 'true') {
+  app.use((req, res, next) => {
+    if (req.secure || req.headers['x-forwarded-proto'] === 'https') return next();
+    if (req.method === 'GET' || req.method === 'HEAD') {
+      return res.redirect(308, `https://${req.headers.host}${req.originalUrl}`);
+    }
+    return res.status(426).json({ message: 'HTTPS required' });
+  });
+}
+
 // 1. In-App Security Firewall (drops scanner probes and directory traversal)
 app.use(securityFirewall);
 
@@ -24,6 +37,7 @@ app.use(securityFirewall);
 app.use(
   helmet({
     contentSecurityPolicy: false,
+    hsts: process.env.FORCE_HTTPS === 'true' ? { maxAge: 31536000, includeSubDomains: true } : false,
     crossOriginResourcePolicy: { policy: 'cross-origin' },
   })
 );
```

</details>

---

## PR [#15](https://github.com/chirag350/vibe2fix-store/pull/15) — enable a Content-Security-Policy header (#19)

**Branch:** `fix/19-content-security-policy`  |  **Merged:** 2026-11-22  |  **Changes:** +15 / −1 in 1 file(s)

### Vulnerability
**Finding:** #19 Missing Content-Security-Policy header  |  **Severity:** Low  |  **Endpoint:** `all responses`

Helmet was configured with `contentSecurityPolicy: false`, so there was no CSP to limit the impact of any XSS.

### How it was fixed
Enabled a restrictive CSP: `default-src 'self'`; `script-src 'self'` (no inline/eval); `style-src 'self' 'unsafe-inline'` (UI uses inline styles); `img-src 'self' data: blob: https://images.unsplash.com` (the only external host the client uses); `connect-src 'self'`; `object-src 'none'`; `frame-ancestors 'none'`; `base-uri`/`form-action` `'self'`.

### How to verify
Response headers include `Content-Security-Policy`.

### Notes
Please smoke-test the built SPA in a browser after merging; if a page loads an additional external resource it will need to be added to the policy.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/server.js b/server/src/server.js
index 68bafc7..63080d7 100644
--- a/server/src/server.js
+++ b/server/src/server.js
@@ -37,7 +37,21 @@ app.use(securityFirewall);
 // 2. Security Headers (Helmet)
 app.use(
   helmet({
-    contentSecurityPolicy: false,
+    contentSecurityPolicy: {
+      useDefaults: false,
+      directives: {
+        defaultSrc: ["'self'"],
+        scriptSrc: ["'self'"],
+        styleSrc: ["'self'", "'unsafe-inline'"],
+        imgSrc: ["'self'", 'data:', 'blob:', 'https://images.unsplash.com'],
+        fontSrc: ["'self'", 'data:'],
+        connectSrc: ["'self'"],
+        objectSrc: ["'none'"],
+        baseUri: ["'self'"],
+        formAction: ["'self'"],
+        frameAncestors: ["'none'"],
+      },
+    },
     hsts: process.env.FORCE_HTTPS === 'true' ? { maxAge: 31536000, includeSubDomains: true } : false,
     crossOriginResourcePolicy: { policy: 'cross-origin' },
   })
```

</details>

---

## PR [#16](https://github.com/chirag350/vibe2fix-store/pull/16) — shorten JWT lifetime and add server-side logout revocation (#21)

**Branch:** `fix/21-jwt-lifetime-revocation`  |  **Merged:** 2026-11-22  |  **Changes:** +17 / −3 in 4 file(s)

### Vulnerability
**Finding:** #21 Long-lived JWT, no revocation  |  **Severity:** Low  |  **Endpoint:** `all authenticated endpoints`

Tokens were valid for 7 days and there was no logout or other way to revoke a stolen token.

### How it was fixed
- Default lifetime reduced to 2 hours (configurable via `JWT_EXPIRES_IN`).
- New `POST /api/auth/logout`: stamps the user's `passwordChangedAt`; `requireAuth` already rejects any token issued before that time (check made inclusive of the same second), so all of the user's existing tokens are revoked server-side. No schema migration is needed.

### How to verify
Log in, call `POST /api/auth/logout` and re-use the old token: `401 Password recently changed. Please log in again.`

### Notes
The client still needs to call `/api/auth/logout` from its logout handler (and ideally handle token refresh given the shorter lifetime) - not included here to keep this PR server-side.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/controllers/auth.controller.js b/server/src/controllers/auth.controller.js
index 7e4d401..c5add38 100644
--- a/server/src/controllers/auth.controller.js
+++ b/server/src/controllers/auth.controller.js
@@ -10,6 +10,11 @@ const login = async (req, res) => {
   res.status(200).json({ data: result });
 };
 
+const logout = async (req, res) => {
+  const result = await authService.logout(req.user.id);
+  res.status(200).json({ data: result });
+};
+
 const me = async (req, res) => {
   res.status(200).json({ data: authService.getCurrentUser(req.user) });
 };
@@ -30,4 +35,4 @@ const updateProfile = async (req, res) => {
   res.status(200).json({ data: result });
 };
 
-module.exports = { register, login, me, forgotPassword, resetPassword, updateProfile };
+module.exports = { register, login, logout, me, forgotPassword, resetPassword, updateProfile };
diff --git a/server/src/middleware/requireAuth.js b/server/src/middleware/requireAuth.js
index 2443440..e79a57c 100644
--- a/server/src/middleware/requireAuth.js
+++ b/server/src/middleware/requireAuth.js
@@ -65,7 +65,7 @@ const requireAuth = asyncHandler(async (req, res, next) => {
   if (
     user.passwordChangedAt &&
     payload.iat &&
-    Math.floor(user.passwordChangedAt.getTime() / 1000) > payload.iat
+    Math.floor(user.passwordChangedAt.getTime() / 1000) >= payload.iat
   ) {
     throw new AppError('Password recently changed. Please log in again.', 401);
   }
diff --git a/server/src/routes/auth.routes.js b/server/src/routes/auth.routes.js
index 1f683f8..9c19be3 100644
--- a/server/src/routes/auth.routes.js
+++ b/server/src/routes/auth.routes.js
@@ -33,6 +33,7 @@ const passwordResetLimiter = rateLimit({
 
 router.post('/register', registerLimiter, asyncHandler(authController.register));
 router.post('/login', loginLimiter, asyncHandler(authController.login));
+router.post('/logout', requireAuth, asyncHandler(authController.logout));
 router.get('/me', requireAuth, asyncHandler(authController.me));
 router.put('/me', requireAuth, asyncHandler(authController.updateProfile));
 router.put('/profile', requireAuth, asyncHandler(authController.updateProfile));
diff --git a/server/src/services/auth.service.js b/server/src/services/auth.service.js
index a30d9a7..7ffe599 100644
--- a/server/src/services/auth.service.js
+++ b/server/src/services/auth.service.js
@@ -46,7 +46,7 @@ const createToken = (user) => {
   return jwt.sign({}, secret, {
     subject: user.id,
     algorithm: 'HS256',
-    expiresIn: '7d',
+    expiresIn: process.env.JWT_EXPIRES_IN || '2h',
   });
 };
 
@@ -122,6 +122,13 @@ const login = async ({ email, password }) => {
   return { user: safeUser, token: createToken(user) };
 };
 
+// Revocation: every token issued before passwordChangedAt is rejected by requireAuth,
+// so stamping it invalidates all of the user's existing sessions.
+const logout = async (userId) => {
+  await prisma.user.update({ where: { id: userId }, data: { passwordChangedAt: new Date() } });
+  return { message: 'Logged out' };
+};
+
 const getCurrentUser = (user) => ({
   id: user.id,
   name: user.name,
@@ -267,6 +274,7 @@ module.exports = {
   updateProfile,
   register,
   login,
+  logout,
   getCurrentUser,
   forgotPassword,
   resetPassword,
```

</details>

---

## PR [#17](https://github.com/chirag350/vibe2fix-store/pull/17) — validate product id route parameters (#22)

**Branch:** `fix/22-path-traversal-product-id`  |  **Merged:** 2026-11-22  |  **Changes:** +17 / −0 in 2 file(s)

### Vulnerability
**Finding:** #22 Path traversal in product id route  |  **Severity:** Low  |  **Endpoint:** `GET /api/products/:id`

The `:id` segment was not validated, so `../../` sequences could route requests onto other API endpoints.

### How it was fixed
Added `router.param('id')` validation on the product and product-review routers: ids must be UUIDs (matching the schema's `@default(uuid())`), otherwise `400 Invalid product id` is returned before any handler or query runs.

### How to verify
`GET /api/products/..%2f..%2fadmin` and `/api/products/abc` return `400`; real product UUIDs work.

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/routes/product.routes.js b/server/src/routes/product.routes.js
index 33e65c3..29fef4d 100644
--- a/server/src/routes/product.routes.js
+++ b/server/src/routes/product.routes.js
@@ -4,6 +4,15 @@ const productController = require('../controllers/product.controller');
 
 const router = express.Router();
 
+// Product ids are UUIDs. Anything else (e.g. '../../admin/users') is rejected up front.
+const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
+router.param('id', (req, res, next, id) => {
+  if (!UUID_RE.test(id)) {
+    return res.status(400).json({ message: 'Invalid product id' });
+  }
+  next();
+});
+
 router.get('/', asyncHandler(productController.list));
 router.get('/:id/reviews', asyncHandler(productController.listReviews));
 router.get('/:id', asyncHandler(productController.getById));
diff --git a/server/src/routes/productReview.routes.js b/server/src/routes/productReview.routes.js
index d0e2af2..cc84d81 100644
--- a/server/src/routes/productReview.routes.js
+++ b/server/src/routes/productReview.routes.js
@@ -4,6 +4,14 @@ const reviewController = require('../controllers/review.controller');
 const { requireAuth } = require('../middleware/auth');
 const { uploadReview } = require('../middleware/upload');
 
+const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
+router.param('id', (req, res, next, id) => {
+  if (!UUID_RE.test(id)) {
+    return res.status(400).json({ message: 'Invalid product id' });
+  }
+  next();
+});
+
 // GET /api/products/:id/reviews (Public list of verified reviews)
 router.get('/', reviewController.getProductReviews);
```

</details>

---

## PR [#18](https://github.com/chirag350/vibe2fix-store/pull/18) — reduce server technology fingerprinting (#24)

**Branch:** `fix/24-reduce-server-fingerprinting`  |  **Merged:** 2026-11-22  |  **Changes:** +1 / −2 in 1 file(s)

### Vulnerability
**Finding:** #24 Server technology fingerprinting  |  **Severity:** Info  |  **Endpoint:** `response headers, error messages`

Responses revealed the technology stack (Express `X-Powered-By`, service name in root/health JSON, PostgreSQL/Prisma text in errors).

### How it was fixed
Disabled `X-Powered-By`, removed the service name/health link from the root JSON response. Database error text is handled by the #11 PR and the health body by #12.

### How to verify
`curl -I` no longer shows `X-Powered-By`.

### Notes
nginx's `Server` header is set by the proxy; add `server_tokens off;` there (outside this repo).

<details>
<summary>View diff</summary>

```diff
diff --git a/server/src/server.js b/server/src/server.js
index af39ee7..0e1b85d 100644
--- a/server/src/server.js
+++ b/server/src/server.js
@@ -16,6 +16,7 @@ const app = express();
 
 // Trust reverse proxy (Railway, Vercel) for accurate client IP identification
 app.set('trust proxy', 1);
+app.disable('x-powered-by');
 
 // 1. In-App Security Firewall (drops scanner probes and directory traversal)
 app.use(securityFirewall);
@@ -89,8 +90,6 @@ app.get('/', (req, res) => {
   }
   res.status(200).json({
     status: 'ok',
-    service: 'vibe2fix-backend',
-    health: '/api/health',
   });
 });
```

</details>

---
