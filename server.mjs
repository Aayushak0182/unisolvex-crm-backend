import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import crypto from 'node:crypto';

const app = express();
const port = Number(process.env.PORT || 3001);
const verifyToken = process.env.WHATSAPP_VERIFY_TOKEN || '';
const appSecret = process.env.META_APP_SECRET || process.env.WHATSAPP_APP_SECRET || '';
const whatsappAccessToken = process.env.WHATSAPP_ACCESS_TOKEN || '';
const whatsappPhoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID || '';

app.use(cors());
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(
    express.json({
        limit: '2mb',
        verify: (req, _res, buf, encoding) => {
            req.rawBody = buf.toString(encoding || 'utf8');
        }
    })
);

const contactsByWaId = new Map();
const messagesByWaId = new Map();
const messageStatusById = new Map();
const sockets = new Set();
const webhookEvents = [];

let loggedMissingAppSecret = false;

function safeTimingCompareHex(expectedHex, actualHex) {
    const expected = Buffer.from(String(expectedHex || ''), 'utf8');
    const actual = Buffer.from(String(actualHex || ''), 'utf8');
    if (expected.length !== actual.length) return false;
    return crypto.timingSafeEqual(expected, actual);
}

function verifyMetaSignature(req) {
    if (!appSecret) {
        if (process.env.NODE_ENV === 'production' && !loggedMissingAppSecret) {
            loggedMissingAppSecret = true;
            console.warn('[webhook] WARNING: META_APP_SECRET/WHATSAPP_APP_SECRET not set; signature verification is disabled.');
        }
        return true;
    }

    const rawBody = String(req.rawBody || '');
    const sig256 = req.get('x-hub-signature-256');
    if (sig256) {
        const match = /^sha256=(.+)$/i.exec(String(sig256));
        if (!match?.[1]) return false;
        const provided = match[1];
        const expected = crypto.createHmac('sha256', appSecret).update(rawBody, 'utf8').digest('hex');
        return safeTimingCompareHex(expected, provided);
    }

    const sig1 = req.get('x-hub-signature');
    if (sig1) {
        const match = /^sha1=(.+)$/i.exec(String(sig1));
        if (!match?.[1]) return false;
        const provided = match[1];
        const expected = crypto.createHmac('sha1', appSecret).update(rawBody, 'utf8').digest('hex');
        return safeTimingCompareHex(expected, provided);
    }

    // If we have a secret but no signature header, treat as invalid.
    return false;
}

function pushWebhookEvent(event) {
    webhookEvents.unshift(event);
    if (webhookEvents.length > 100) webhookEvents.pop();
}

function normalizeWaId(value) {
    return String(value || '').replace(/[^\d]/g, '');
}

function upsertContact(waId, profileName) {
    if (!waId) return null;
    const existing = contactsByWaId.get(waId) || { waId, profileName: waId, updatedAt: new Date().toISOString() };
    if (profileName) existing.profileName = profileName;
    existing.updatedAt = new Date().toISOString();
    contactsByWaId.set(waId, existing);
    return existing;
}

function addMessage(waId, message) {
    if (!waId || !message) return;
    const messageId = String(message.id || '');
    const knownStatus = messageId ? messageStatusById.get(messageId) : null;
    if (knownStatus) {
        message.status = knownStatus.status;
        message.statusTimestamp = knownStatus.statusTimestamp;
    }
    if (messageId && message.status) {
        messageStatusById.set(messageId, {
            status: message.status,
            statusTimestamp: message.statusTimestamp || message.timestamp || new Date().toISOString()
        });
    }
    const existing = messagesByWaId.get(waId) || [];
    existing.push(message);
    if (existing.length > 250) {
        existing.splice(0, existing.length - 250);
    }
    messagesByWaId.set(waId, existing);
}

function updateMessageStatus(waId, messageId, status, statusTimestamp) {
    if (!waId || !messageId || !status) return false;
    messageStatusById.set(messageId, {
        status,
        statusTimestamp: statusTimestamp || new Date().toISOString()
    });
    const thread = messagesByWaId.get(waId) || [];
    if (!thread.length) return false;

    let updated = false;
    for (let i = thread.length - 1; i >= 0; i -= 1) {
        const item = thread[i];
        if (item?.id !== messageId) continue;
        item.status = status;
        if (statusTimestamp) item.statusTimestamp = statusTimestamp;
        updated = true;
        break;
    }
    if (updated) {
        messagesByWaId.set(waId, thread);
    }
    return updated;
}

function broadcast(payload) {
    const packet = JSON.stringify(payload);
    sockets.forEach((ws) => {
        if (ws.readyState === ws.OPEN) {
            ws.send(packet);
        }
    });
}

function normalizeIncomingMessage(valueMessage) {
    if (!valueMessage) return '';
    if (valueMessage.type === 'text') return valueMessage.text?.body || '';
    if (valueMessage.type === 'button') return valueMessage.button?.text || '';
    if (valueMessage.type === 'interactive') {
        return valueMessage.interactive?.button_reply?.title || valueMessage.interactive?.list_reply?.title || '[Interactive message]';
    }
    if (valueMessage.type === 'image') return '[Image]';
    if (valueMessage.type === 'document') return '[Document]';
    if (valueMessage.type === 'audio') return '[Audio]';
    if (valueMessage.type === 'video') return '[Video]';
    return '[Unsupported message type]';
}

app.get('/health', (_req, res) => {
    res.json({ ok: true, service: 'whatsapp-webhook', at: new Date().toISOString() });
});

app.get('/webhook', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];
    if (mode === 'subscribe' && token && token === verifyToken) {
        return res.status(200).send(challenge);
    }
    return res.sendStatus(403);
});

app.post('/webhook', (req, res) => {
    if (!verifyMetaSignature(req)) {
        console.warn('[webhook] invalid signature');
        return res.sendStatus(403);
    }

    const body = req.body;
    const receivedAt = new Date().toISOString();
    pushWebhookEvent({
        receivedAt,
        object: body?.object || '',
        hasEntry: Array.isArray(body?.entry),
        entryCount: Array.isArray(body?.entry) ? body.entry.length : 0
    });
    console.log('[webhook] received', receivedAt, 'object=', body?.object || '(none)');

    if (body?.object !== 'whatsapp_business_account') {
        // Always ack webhook deliveries; non-WA payloads are ignored.
        return res.sendStatus(200);
    }

    const entries = body.entry || [];
    entries.forEach((entry) => {
        const changes = entry.changes || [];
        changes.forEach((change) => {
            const value = change.value || {};
            const contacts = value.contacts || [];
            const messages = value.messages || [];
            const statuses = value.statuses || [];

            messages.forEach((incomingMessage) => {
                const waId = normalizeWaId(incomingMessage.from || '');
                const contactInfo = contacts.find((c) => c.wa_id === waId);
                const profileName = contactInfo?.profile?.name || waId;
                const tsMillis = Number(incomingMessage.timestamp || '0') * 1000;
                const timestamp = tsMillis > 0 ? new Date(tsMillis).toISOString() : new Date().toISOString();
                const text = normalizeIncomingMessage(incomingMessage);

                upsertContact(waId, profileName);
                addMessage(waId, {
                    id: incomingMessage.id || '',
                    direction: 'incoming',
                    text,
                    timestamp
                });
                pushWebhookEvent({
                    receivedAt,
                    object: body?.object || '',
                    waId,
                    profileName,
                    direction: 'incoming',
                    text,
                    timestamp
                });

                broadcast({
                    type: 'whatsapp_message',
                    payload: {
                        waId,
                        profileName,
                        id: incomingMessage.id || '',
                        direction: 'incoming',
                        text,
                        timestamp
                    }
                });
            });

            statuses.forEach((statusEvent) => {
                const waId = normalizeWaId(statusEvent.recipient_id || '');
                const messageId = statusEvent.id || '';
                const status = String(statusEvent.status || '').toLowerCase();
                const tsMillis = Number(statusEvent.timestamp || '0') * 1000;
                const statusTimestamp = tsMillis > 0 ? new Date(tsMillis).toISOString() : new Date().toISOString();
                if (!waId || !messageId || !status) return;

                updateMessageStatus(waId, messageId, status, statusTimestamp);
                pushWebhookEvent({
                    receivedAt,
                    object: body?.object || '',
                    waId,
                    direction: 'outgoing',
                    messageId,
                    status,
                    statusTimestamp
                });
                broadcast({
                    type: 'whatsapp_message_status',
                    payload: {
                        waId,
                        messageId,
                        status,
                        statusTimestamp
                    }
                });
            });
        });
    });

    return res.sendStatus(200);
});

app.get('/api/whatsapp/debug', (_req, res) => {
    res.json({
        ok: true,
        contacts: contactsByWaId.size,
        messageThreads: messagesByWaId.size,
        recentWebhookEvents: webhookEvents.slice(0, 20)
    });
});

app.get('/api/whatsapp/contacts', (_req, res) => {
    const rows = Array.from(contactsByWaId.values())
        .sort((a, b) => {
            const aTs = new Date(a.updatedAt).getTime();
            const bTs = new Date(b.updatedAt).getTime();
            return bTs - aTs;
        })
        .map((contact) => ({
            waId: contact.waId,
            profileName: contact.profileName,
            updatedAt: contact.updatedAt,
            messages: (messagesByWaId.get(contact.waId) || []).map((message) => {
                const knownStatus = messageStatusById.get(message.id || '');
                if (!knownStatus) return message;
                return {
                    ...message,
                    status: knownStatus.status,
                    statusTimestamp: knownStatus.statusTimestamp
                };
            })
        }));
    res.json(rows);
});

app.post('/api/whatsapp/send', async (req, res) => {
    const waId = normalizeWaId(req.body?.waId || '');
    const text = String(req.body?.text || '').trim();

    if (!waId || !text) {
        return res.status(400).json({ ok: false, error: 'waId and text are required' });
    }
    if (!whatsappAccessToken || !whatsappPhoneNumberId) {
        return res.status(500).json({ ok: false, error: 'WHATSAPP_ACCESS_TOKEN or WHATSAPP_PHONE_NUMBER_ID missing' });
    }

    try {
        const graphUrl = `https://graph.facebook.com/v22.0/${whatsappPhoneNumberId}/messages`;
        const response = await fetch(graphUrl, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${whatsappAccessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                messaging_product: 'whatsapp',
                to: waId,
                type: 'text',
                text: { body: text }
            })
        });

        const result = await response.json();
        if (!response.ok) {
            return res.status(502).json({
                ok: false,
                error: result?.error?.message || 'WhatsApp API send failed',
                details: result
            });
        }

        const profileName = contactsByWaId.get(waId)?.profileName || waId;
        const timestamp = new Date().toISOString();
        const messageId = result?.messages?.[0]?.id || '';
        upsertContact(waId, profileName);
        addMessage(waId, {
            id: messageId,
            direction: 'outgoing',
            text,
            timestamp,
            status: 'sent',
            statusTimestamp: timestamp
        });

        broadcast({
            type: 'whatsapp_message',
            payload: {
                waId,
                profileName,
                id: messageId,
                direction: 'outgoing',
                text,
                timestamp,
                status: 'sent',
                statusTimestamp: timestamp
            }
        });

        return res.json({ ok: true, id: messageId });
    } catch (error) {
        return res.status(500).json({ ok: false, error: error?.message || 'Unexpected send error' });
    }
});

const server = app.listen(port, () => {
    console.log(`WhatsApp webhook server running on http://localhost:${port}`);
});

const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws) => {
    sockets.add(ws);
    ws.on('close', () => sockets.delete(ws));
});
