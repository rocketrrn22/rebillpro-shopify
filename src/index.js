require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');
const fetch = require('node-fetch');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ── MIDDLEWARE ──────────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());
app.use('/webhooks', express.raw({ type: 'application/json' })); // raw body needed for HMAC
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'rebillpro-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// ── PERSISTENT STORE ────────────────────────────────────────────
const STORE_FILE = path.join(__dirname, '../store.json');

function loadStore() {
  try {
    if (fs.existsSync(STORE_FILE)) return JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
  } catch (e) { console.error('Failed to load store:', e.message); }
  return { shops: {} };
}

function saveStore() {
  try { fs.writeFileSync(STORE_FILE, JSON.stringify({ shops: store.shops }, null, 2)); }
  catch (e) { console.error('Failed to save store:', e.message); }
}

const persisted = loadStore();
const store = {
  shops: persisted.shops || {},
  webhookEvents: []
};

// Auto-load token from env vars (custom app setup — no OAuth needed)
if (process.env.SHOPIFY_SHOP && process.env.SHOPIFY_ACCESS_TOKEN) {
  const s = process.env.SHOPIFY_SHOP;
  store.shops[s] = { accessToken: process.env.SHOPIFY_ACCESS_TOKEN, shop: s, at: new Date().toISOString() };
  console.log(`✅ Loaded token from env for ${s}`);
}

// ── CONFIG ──────────────────────────────────────────────────────
const SHOPIFY_API_KEY    = process.env.SHOPIFY_API_KEY    || '';
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET || '';
const APP_URL            = process.env.APP_URL            || `http://localhost:${PORT}`;
const SCOPES             = 'read_customers,write_customers,read_orders,write_orders,read_draft_orders,write_draft_orders,read_products,write_products,read_own_subscription_contracts,write_own_subscription_contracts';

// ── HELPERS ─────────────────────────────────────────────────────
async function gql(shop, token, query, variables = {}) {
  const r = await fetch(`https://${shop}/admin/api/2024-10/graphql.json`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Shopify-Access-Token': token },
    body: JSON.stringify({ query, variables })
  });
  const d = await r.json();
  if (d.errors) throw new Error(d.errors[0].message);
  return d.data;
}

async function rest(shop, token, endpoint, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Shopify-Access-Token': token }
  };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(`https://${shop}/admin/api/2024-10/${endpoint}`, opts);
  const text = await r.text();
  if (!text) throw new Error(`HTTP ${r.status} — empty response. App may need reinstalling to get new scopes.`);
  try { return JSON.parse(text); }
  catch (e) { throw new Error(`HTTP ${r.status}: ${text.slice(0, 300)}`); }
}

function verifyHmac(query) {
  const { hmac, ...params } = query;
  if (!hmac) return false;
  const msg = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
  const digest = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(msg).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
}

function verifyWebhookHmac(rawBody, signature) {
  const digest = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(rawBody).digest('base64');
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
}

function requireAuth(req, res, next) {
  const shop = req.query.shop || req.body?.shop || req.session.shop;
  if (!shop || !store.shops[shop]) {
    return res.status(401).json({ error: 'Not authenticated. Please install the app first.' });
  }
  req.shop = shop;
  req.token = store.shops[shop].accessToken;
  next();
}

// ── AUTH ────────────────────────────────────────────────────────
app.get('/auth', (req, res) => {
  const shop = req.query.shop;
  if (!shop) return res.status(400).send('Missing shop');
  const state = crypto.randomBytes(16).toString('hex');
  req.session.state = state;
  req.session.shop  = shop;
  const redirectUri = `${APP_URL}/auth/callback`;
  res.redirect(`https://${shop}/admin/oauth/authorize?client_id=${SHOPIFY_API_KEY}&scope=${SCOPES}&state=${state}&redirect_uri=${redirectUri}`);
});

app.get('/auth/callback', async (req, res) => {
  const { shop, code, state } = req.query;
  if (state !== req.session.state) return res.status(403).send('State mismatch');
  if (!verifyHmac(req.query))      return res.status(403).send('HMAC invalid');
  try {
    const r = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: SHOPIFY_API_KEY, client_secret: SHOPIFY_API_SECRET, code })
    });
    const { access_token } = await r.json();
    store.shops[shop] = { accessToken: access_token, shop, at: new Date().toISOString() };
    saveStore();
    req.session.shop = shop;
    console.log(`✅ Installed: ${shop}`);
    res.redirect(`/dashboard?shop=${shop}`);
  } catch (e) {
    console.error(e);
    res.status(500).send('Auth failed: ' + e.message);
  }
});

// ── PAGES ───────────────────────────────────────────────────────
app.get('/', (req, res) => {
  const shop = req.query.shop;
  if (shop && store.shops[shop]) return res.redirect(`/dashboard?shop=${shop}`);
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

// ── API: STATUS ─────────────────────────────────────────────────
app.get('/api/status', (req, res) => {
  const shop = req.query.shop;
  res.json({ connected: !!(shop && store.shops[shop]), shop, appUrl: APP_URL });
});

// ── API: SHOP INFO ──────────────────────────────────────────────
app.get('/api/shop', requireAuth, async (req, res) => {
  try {
    const d = await rest(req.shop, req.token, 'shop.json');
    res.json({ success: true, shop: d.shop });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── API: CUSTOMERS ──────────────────────────────────────────────
app.get('/api/customers', requireAuth, async (req, res) => {
  try {
    const query = `
      query {
        customers(first: 100) {
          edges {
            node {
              id
              displayName
              email
              phone
              createdAt
               numberOfOrders
              amountSpent { amount currencyCode }
              paymentMethods(first: 3) {
                edges {
                  node {
                    id
                    instrument {
                      ... on CustomerCreditCard {
                        brand
                        lastDigits
                        expiryMonth
                        expiryYear
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;
    const data = await gql(req.shop, req.token, query);
    const customers = data.customers.edges.map(e => ({
      ...e.node,
      ordersCount: e.node.numberOfOrders,
      totalSpentV2: e.node.amountSpent,
      hasCard: e.node.paymentMethods.edges.length > 0,
      card: e.node.paymentMethods.edges[0]?.node?.instrument || null
    }));
    res.json({ success: true, customers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── API: ORDERS ─────────────────────────────────────────────────
app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const d = await rest(req.shop, req.token, 'orders.json?status=any&limit=100');
    res.json({ success: true, orders: d.orders || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── API: SUBSCRIPTIONS ──────────────────────────────────────────
app.get('/api/subscriptions', requireAuth, async (req, res) => {
  try {
    const query = `
      query {
        subscriptionContracts(first: 100) {
          edges {
            node {
              id
              status
              createdAt
              nextBillingDate
              customer { id displayName email }
              billingPolicy { interval intervalCount }
              lines(first: 3) {
                edges {
                  node {
                    title
                    quantity
                    currentPrice { amount currencyCode }
                  }
                }
              }
            }
          }
        }
      }
    `;
    const data = await gql(req.shop, req.token, query);
    const subs = data.subscriptionContracts?.edges?.map(e => e.node) || [];
    res.json({ success: true, subscriptions: subs });
  } catch (e) {
    // Subscription API may not be enabled — return empty
    res.json({ success: true, subscriptions: [], note: e.message });
  }
});

// ── API: CREATE SUBSCRIPTION ────────────────────────────────────
app.post('/api/subscriptions/create', requireAuth, async (req, res) => {
  const { customerId, amount, currency, intervalUnit, intervalCount, description } = req.body;
  try {
    const custQuery = `
      query($id: ID!) {
        customer(id: $id) {
          paymentMethods(first: 1) { edges { node { id } } }
        }
      }
    `;
    const custData = await gql(req.shop, req.token, custQuery, { id: customerId });
    if (!custData.customer.paymentMethods.edges.length) {
      return res.status(400).json({ error: 'Customer has no saved payment method' });
    }
    const paymentMethodId = custData.customer.paymentMethods.edges[0].node.id;
    const nextDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    const mutation = `
      mutation($input: SubscriptionContractCreateInput!) {
        subscriptionContractCreate(input: $input) {
          draft { id status }
          userErrors { field message }
        }
      }
    `;
    const input = {
      customerId,
      nextBillingDate: nextDate,
      contract: {
        status: 'ACTIVE',
        paymentMethodId,
        billingPolicy:  { interval: intervalUnit || 'MONTH', intervalCount: intervalCount || 1, minCycles: 1 },
        deliveryPolicy: { interval: intervalUnit || 'MONTH', intervalCount: intervalCount || 1 },
        note: description || 'RebillPro subscription'
      },
      lineItems: [{
        quantity: 1,
        currentPrice: { amount: (amount / 100).toFixed(2), currencyCode: (currency || 'USD').toUpperCase() },
        title: description || 'Subscription'
      }]
    };
    const result = await gql(req.shop, req.token, mutation, { input });
    if (result.subscriptionContractCreate.userErrors?.length) {
      throw new Error(result.subscriptionContractCreate.userErrors[0].message);
    }
    res.json({ success: true, subscription: result.subscriptionContractCreate.draft });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── API: BILL SUBSCRIPTION ──────────────────────────────────────
app.post('/api/subscriptions/bill', requireAuth, async (req, res) => {
  const { subscriptionContractId } = req.body;
  try {
    const key = crypto.randomBytes(16).toString('hex');
    const mutation = `
      mutation($id: ID!, $key: String!) {
        subscriptionBillingAttemptCreate(
          subscriptionContractId: $id
          subscriptionBillingAttemptInput: { idempotencyKey: $key }
        ) {
          subscriptionBillingAttempt { id ready errorMessage order { id name } }
          userErrors { field message }
        }
      }
    `;
    const r = await gql(req.shop, req.token, mutation, { id: subscriptionContractId, key });
    if (r.subscriptionBillingAttemptCreate.userErrors?.length) {
      throw new Error(r.subscriptionBillingAttemptCreate.userErrors[0].message);
    }
    res.json({ success: true, attempt: r.subscriptionBillingAttemptCreate.subscriptionBillingAttempt });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── API: BILL ALL SUBSCRIPTIONS ─────────────────────────────────
app.post('/api/subscriptions/bill-all', requireAuth, async (req, res) => {
  try {
    const query = `query { subscriptionContracts(first:100, query:"status:ACTIVE") { edges { node { id customer { displayName email } } } } }`;
    const data = await gql(req.shop, req.token, query);
    const contracts = data.subscriptionContracts?.edges?.map(e => e.node) || [];
    let ok = 0, failed = 0;
    for (const c of contracts) {
      try {
        const key = crypto.randomBytes(16).toString('hex');
        const m = `mutation($id:ID!,$key:String!){subscriptionBillingAttemptCreate(subscriptionContractId:$id subscriptionBillingAttemptInput:{idempotencyKey:$key}){subscriptionBillingAttempt{id ready}userErrors{message}}}`;
        const r = await gql(req.shop, req.token, m, { id: c.id, key });
        r.subscriptionBillingAttemptCreate.userErrors?.length ? failed++ : ok++;
        await new Promise(res => setTimeout(res, 300));
      } catch { failed++; }
    }
    res.json({ success: true, charged: ok, failed, total: contracts.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── API: CANCEL SUBSCRIPTION ────────────────────────────────────
app.post('/api/subscriptions/cancel', requireAuth, async (req, res) => {
  const { subscriptionContractId } = req.body;
  try {
    const m = `mutation($id:ID!){subscriptionContractCancel(subscriptionContractId:$id){subscriptionContract{id status}userErrors{message}}}`;
    const r = await gql(req.shop, req.token, m, { id: subscriptionContractId });
    res.json({ success: true, contract: r.subscriptionContractCancel.subscriptionContract });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── API: DRAFT ORDER (manual one-time charge) ───────────────────
app.post('/api/draft-order', requireAuth, async (req, res) => {
  const { customerId, amount, currency, note } = req.body;
  try {
    const rawId = customerId.replace('gid://shopify/Customer/', '');
    const d = await rest(req.shop, req.token, 'draft_orders.json', 'POST', {
      draft_order: {
        customer: { id: rawId },
        line_items: [{
          title: note || 'Manual charge — RebillPro',
          price: (amount / 100).toFixed(2),
          quantity: 1,
          requires_shipping: false
        }],
        send_invoice: true,
        note: 'Created by RebillPro'
      }
    });
    if (d.errors) throw new Error(JSON.stringify(d.errors));
    res.json({ success: true, draftOrder: d.draft_order });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GHOST CHECKOUT: ROBUST HEADLESS ENGINE ──────────────────────
app.post('/api/checkout/create-prefilled', async (req, res) => {
  const { 
    shop = 'jx49ii-v0.myshopify.com', 
    variantId, 
    sellingPlanId, 
    email, 
    firstName, 
    lastName, 
    address1, 
    city, 
    zip, 
    country = 'FR' 
  } = req.body;

  if (!variantId || !email) return res.status(400).json({ error: 'Missing requirements' });

  try {
    const token = await getShopToken(shop);
    
    // 1. Create a Storefront Access Token if needed
    const stData = await rest(shop, token, 'storefront_access_tokens.json', 'POST', {
      storefront_access_token: { title: 'RebillPro Ghost Engine' }
    });
    const st = stData.storefront_access_token.access_token;

    // 2. Prepare Variant/Plan GIDs
    const vId = variantId.split('/').pop();
    const pId = sellingPlanId ? sellingPlanId.split('/').pop() : null;
    const variantGid = `gid://shopify/ProductVariant/${vId}`;
    const planGid = pId ? `gid://shopify/SellingPlan/${pId}` : null;

    // 3. Create Checkout via Storefront API (GraphQL)
    const storeResponse = await fetch(`https://${shop}/api/2024-10/graphql.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Storefront-Access-Token': st },
      body: JSON.stringify({
        query: `mutation checkoutCreate($input: CheckoutCreateInput!) {
          checkoutCreate(input: $input) {
            checkout { webUrl }
            checkoutUserErrors { message }
          }
        }`,
        variables: {
          input: {
            email,
            shippingAddress: { firstName, lastName, address1, city, zip, country },
            lineItems: [{ variantId: variantGid, quantity: 1, ...(planGid ? { sellingPlanId: planGid } : {}) }]
          }
        }
      })
    });

    const sr = await storeResponse.json();
    const result = sr.data?.checkoutCreate;
    
    if (result?.checkoutUserErrors?.length) throw new Error(result.checkoutUserErrors[0].message);
    if (!result?.checkout?.webUrl) throw new Error('Failed to create checkout object');

    res.json({ success: true, url: result.checkout.webUrl });
  } catch (e) {
    console.error('Headless Error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

async function getShopToken(shop) {
  if (store.shops && store.shops[shop]) return store.shops[shop].accessToken;
  return process.env.SHOPIFY_ACCESS_TOKEN;
}

const WEBHOOK_TOPICS = [
  'subscription_contracts/create',
  'subscription_contracts/update',
  'orders/paid'
];

app.get('/api/webhooks', requireAuth, async (req, res) => {
  try {
    const d = await rest(req.shop, req.token, 'webhooks.json');
    res.json({ success: true, webhooks: d.webhooks || [], events: store.webhookEvents.slice(0, 50) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/webhooks/register', requireAuth, async (req, res) => {
  const results = [];
  for (const topic of WEBHOOK_TOPICS) {
    try {
      const r = await rest(req.shop, req.token, 'webhooks.json', 'POST', {
        webhook: { topic, address: `${APP_URL}/webhooks`, format: 'json' }
      });
      results.push({ topic, success: !r.errors, id: r.webhook?.id, error: r.errors });
    } catch (e) {
      results.push({ topic, success: false, error: e.message });
    }
  }
  res.json({ success: true, results });
});

app.post('/webhooks', (req, res) => {
  const signature = req.headers['x-shopify-hmac-sha256'];
  const topic     = req.headers['x-shopify-topic'];
  const shopDomain = req.headers['x-shopify-shop-domain'];
  if (!signature || !verifyWebhookHmac(req.body, signature)) {
    return res.status(401).send('Unauthorized');
  }
  res.status(200).send('OK');
  try {
    const payload = JSON.parse(req.body.toString());
    store.webhookEvents.unshift({ topic, shop: shopDomain, at: new Date().toISOString(), id: payload.id, payload });
    if (store.webhookEvents.length > 200) store.webhookEvents.pop();
    console.log(`📨 Webhook: ${topic} from ${shopDomain}`);
  } catch (e) { console.error('Webhook parse error:', e.message); }
});

// ── SELLING PLANS ────────────────────────────────────────────────
app.get('/api/selling-plans', requireAuth, async (req, res) => {
  try {
    const query = `
      query {
        sellingPlanGroups(first: 50) {
          edges {
            node {
              id
              name
              merchantCode
              productsCount { count }
              products(first: 5) {
                edges {
                  node {
                    id
                    title
                    variants(first: 5) {
                      edges {
                        node {
                          id
                          title
                          sku
                        }
                      }
                    }
                  }
                }
              }
              sellingPlans(first: 10) {
                edges {
                  node {
                    id
                    name
                    billingPolicy {
                      ... on SellingPlanRecurringBillingPolicy {
                        interval
                        intervalCount
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;
    const data = await gql(req.shop, req.token, query);
    const groups = (data.sellingPlanGroups?.edges || []).map(e => ({
      id: e.node.id,
      name: e.node.name,
      merchantCode: e.node.merchantCode,
      productCount: e.node.productsCount?.count || 0,
      products: e.node.products.edges.map(pe => ({
        id: pe.node.id,
        title: pe.node.title,
        variants: pe.node.variants.edges.map(ve => ({
          id: ve.node.id,
          title: ve.node.title,
          sku: ve.node.sku
        }))
      })),
      sellingPlans: e.node.sellingPlans.edges.map(se => ({
        id: se.node.id,
        name: se.node.name
      }))
    }));
    res.json({ success: true, groups });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/selling-plans/create', requireAuth, async (req, res) => {
  const { name, interval, intervalCount, discount } = req.body;
  try {
    const merchantCode = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const count = parseInt(intervalCount) || 1;
    const pct = parseFloat(discount) || 0;
    const planName = `Delivery every ${count} ${interval.toLowerCase()}${count > 1 ? 's' : ''}`;
    const body = {
      selling_plan_group: {
        name,
        merchant_code: merchantCode,
        options: ['Delivery every'],
        selling_plans: [{
          name: planName,
          options: [`${count} ${interval.charAt(0) + interval.slice(1).toLowerCase()}`],
          billing_policy: { interval: interval.toLowerCase(), interval_count: count },
          delivery_policy: { interval: interval.toLowerCase(), interval_count: count },
          ...(pct > 0 && { pricing_policies: [{ adjustment_type: 'percentage', adjustment_value: String(pct) }] })
        }]
      }
    };
    const d = await rest(req.shop, req.token, 'selling_plan_groups.json', 'POST', body);
    if (d.errors) throw new Error(JSON.stringify(d.errors));
    res.json({ success: true, group: d.selling_plan_group });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/selling-plans/assign', requireAuth, async (req, res) => {
  const { sellingPlanGroupId, productIds } = req.body;
  try {
    const mutation = `
      mutation sellingPlanGroupAddProducts($id: ID!, $productIds: [ID!]!) {
        sellingPlanGroupAddProducts(id: $id, productIds: $productIds) {
          sellingPlanGroup { id name merchantCode }
          userErrors { field message }
        }
      }
    `;
    const result = await gql(req.shop, req.token, mutation, { id: sellingPlanGroupId, productIds });
    if (result.sellingPlanGroupAddProducts.userErrors?.length) {
      throw new Error(result.sellingPlanGroupAddProducts.userErrors[0].message);
    }
    res.json({ success: true, group: result.sellingPlanGroupAddProducts.sellingPlanGroup });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/selling-plans/delete', requireAuth, async (req, res) => {
  const { sellingPlanGroupId } = req.body;
  try {
    const mutation = `
      mutation sellingPlanGroupDelete($id: ID!) {
        sellingPlanGroupDelete(id: $id) {
          deletedSellingPlanGroupId
          userErrors { field message }
        }
      }
    `;
    const result = await gql(req.shop, req.token, mutation, { id: sellingPlanGroupId });
    if (!result?.sellingPlanGroupDelete?.deletedSellingPlanGroupId) {
      throw new Error(result?.sellingPlanGroupDelete?.userErrors?.[0]?.message || 'Failed to delete selling plan group');
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ── START ───────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 RebillPro running on port ${PORT}`);
  console.log(`   App URL: ${APP_URL}`);
  console.log(`   Install: ${APP_URL}/auth?shop=YOURSTORE.myshopify.com\n`);
});
