const nconf = require.main.require('nconf');
const winston = require.main.require('winston');
const axios = require('axios');
const crypto = require('crypto');

const PLUGIN_ID = 'nodebb-plugin-flowprompt-bot';

// Env variables (configure in NodeBB environment)
const { FLOWPROMPT_WEBHOOK_URL } = process.env;
const { FLOWPROMPT_WEBHOOK_SECRET } = process.env;
const { SUPPORT_CATEGORY_ID } = process.env;

console.log('FLOWPROMPT_WEBHOOK_URL', FLOWPROMPT_WEBHOOK_URL);
console.log('FLOWPROMPT_WEBHOOK_SECRET', FLOWPROMPT_WEBHOOK_SECRET);
console.log('SUPPORT_CATEGORY_ID', SUPPORT_CATEGORY_ID);

const BOT_UID = parseInt(process.env.BOT_UID || '0', 10);

function signPayload(payload, timestamp) {
  const body = JSON.stringify(payload);
  const base = `${timestamp}.${body}`;
  const hmac = crypto
    .createHmac('sha256', FLOWPROMPT_WEBHOOK_SECRET || '')
    .update(base)
    .digest('hex');

  return `sha256=${hmac}`;
}

async function sendToFlowPrompt(eventType, payload) {
  if (!FLOWPROMPT_WEBHOOK_URL || !FLOWPROMPT_WEBHOOK_SECRET) {
    winston.warn(`[${PLUGIN_ID}] Webhook not configured. Skipping event.`);
    return;
  }

  try {
    const timestamp = Date.now().toString();
    const signature = signPayload(payload, timestamp);

    await axios.post(FLOWPROMPT_WEBHOOK_URL, payload, {
      headers: {
        'Content-Type': 'application/json',
        'x-flowprompt-signature': signature,
        'x-flowprompt-timestamp': timestamp,
        'x-flowprompt-event-type': eventType,
      },
      timeout: 5000,
    });

    winston.info(
      `[${PLUGIN_ID}] Sent event ${eventType} for tid=${payload.tid}, pid=${payload.pid || 'topic'}`,
    );
  } catch (err) {
    winston.error(
      `[${PLUGIN_ID}] Failed to send event ${eventType}: ${err.message}`,
      err,
    );
  }
}

/**
 * Common guard checks:
 * - Only support category
 * - Skip bot user
 * - Skip edits/deleted
 */
function shouldProcess({ cid, uid, isMain, isDeleted }) {
  if (!SUPPORT_CATEGORY_ID || cid !== SUPPORT_CATEGORY_ID) {
    return false;
  }

  // Skip posts authored by the bot
  if (BOT_UID && uid === BOT_UID) {
    return false;
  }

  if (isDeleted) {
    return false;
  }

  // For topic.create we only care about main post (handled by hook)
  // For post.save we can process replies (non-main posts)
  return true;
}

const Plugin = {};

/**
 * Hook: filter:topic.create
 * Called when a new topic is created via NodeBB UI.
 *
 * data: {
 *   topic: { tid, cid, uid, title, mainPid, ... },
 *   post: { pid, content, uid, ... }
 * }
 */
Plugin.onTopicCreate = async function (hookData) {
  try {
    const topic = hookData.topic || {};
    const post = hookData.post || {};

    const { cid } = topic;
    const uid = post.uid || topic.uid;

    if (
      !shouldProcess({
        cid,
        uid,
        isMain: true,
        isDeleted: !!topic.deleted,
      })
    ) {
      return hookData;
    }

    const payload = {
      event: 'topic.create',
      tid: topic.tid,
      pid: post.pid || topic.mainPid,
      cid: topic.cid,
      uid,
      username: post.username || topic.user?.username,
      title: topic.title,
      content: post.content,
      timestamp: Date.now(),
      baseUrl: nconf.get('url'),
    };

    await sendToFlowPrompt('topic.create', payload);

    return hookData;
  } catch (err) {
    winston.error(`[${PLUGIN_ID}] onTopicCreate error: ${err.message}`, err);
    return hookData; // Do not block NodeBB
  }
};

/**
 * Hook: filter:post.save
 * Called when a post is created or edited.
 *
 * data: {
 *   post: { pid, tid, uid, content, isMain, deleted, ... }
 * }
 */
Plugin.onPostSave = async function (hookData) {
  try {
    const post = hookData.post || {};
    const { tid, pid, uid, content, isMain, deleted } = post;

    const cid = post.cid || post.category?.cid || hookData.topic?.cid;

    if (
      !shouldProcess({
        cid,
        uid,
        isMain,
        isDeleted: !!deleted,
      })
    ) {
      return hookData;
    }

    // Ignore edits: NodeBB includes an 'isNew' flag in some versions;
    // if not available, you can infer from existing data. Here we assume
    // filter:post.save is for new posts only; adjust if needed.
    if (post.edited || post.editor || post.isEdited) {
      return hookData;
    }

    const payload = {
      event: 'post.save',
      tid,
      pid,
      cid,
      uid,
      username: post.username || post.user?.username,
      content,
      isMain,
      timestamp: Date.now(),
      baseUrl: nconf.get('url'),
    };

    await sendToFlowPrompt('post.save', payload);

    return hookData;
  } catch (err) {
    winston.error(`[${PLUGIN_ID}] onPostSave error: ${err.message}`, err);
    return hookData;
  }
};

module.exports = Plugin;
