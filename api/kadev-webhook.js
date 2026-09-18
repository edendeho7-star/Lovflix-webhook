// redeploy avec les variables d'environnement


import admin from "firebase-admin";
import crypto from "crypto";

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
    }),
  });
}
const db = admin.firestore();

export const config = { api: { bodyParser: false } };

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function isValidSignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;
  // Tolère un préfixe "sha256=" ou "sha512=", des espaces et les majuscules
  const received = String(signatureHeader).trim().replace(/^(sha256|sha512)=/i, "").toLowerCase();
  // 128 caractères hexadécimaux = HMAC-SHA512 (cas de Kadev Pay), 64 = HMAC-SHA256
  const algo = received.length === 128 ? "sha512" : "sha256";
  const expected = crypto.createHmac(algo, secret).update(rawBody).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));
  } catch (e) {
    return false;
  }
}

// Prix payé (en F) -> minutes de crédit. À garder identique à CREDIT_PACKS dans l'app.
const MINUTES_BY_PRICE = { 5: 5 * 60, 10: 12 * 60, 20: 25 * 60 };

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).send("Method not allowed");
    return;
  }

  const rawBody = await getRawBody(req);
  const signature = req.headers["x-kadevpay-signature"];

  if (!isValidSignature(rawBody, signature, process.env.KADEV_WEBHOOK_SECRET)) {
    // Diagnostic : aucune valeur secrète n'est affichée
    console.error("Signature invalide", {
      headerPresent: !!signature,
      headerPreview: signature
        ? String(signature).slice(0, 12) + "… (longueur " + String(signature).length + ")"
        : null,
      secretDefined: !!process.env.KADEV_WEBHOOK_SECRET,
      headersSignature: Object.keys(req.headers).filter((h) => /sig|kadev|hook/i.test(h)),
    });
    res.status(401).send("Invalid signature");
    return;
  }

  let event;
  try {
    event = JSON.parse(rawBody.toString("utf8"));
  } catch (e) {
    res.status(400).send("bad json");
    return;
  }

  const status = event.status || event.event || "";
  const isSuccess = /success/i.test(String(status));
  if (!isSuccess) {
    res.status(200).send("ignored");
    return;
  }

  const data = event.data || {};
  const metadata = event.metadata || data.metadata || {};

  // Diagnostic : structure de l'événement, sans aucune valeur secrète
  console.log("Événement Kadev :", {
    keys: Object.keys(event),
    dataKeys: Object.keys(data),
    metadataKeys: Object.keys(metadata),
  });

  // 1) Métadonnées personnalisées de l'app si Kadev les transmet
  let deviceId = metadata.device_id;
  let minutes = Number(metadata.minutes);

  // 2) Sinon repli : le numéro de téléphone (= identifiant du compte) et le montant payé
  if (!deviceId) {
    const phoneRaw = metadata.phone_number || event.phone_number || data.phone_number || event.phone || data.phone || "";
    const digits = String(phoneRaw).replace(/\D/g, "");
    deviceId = digits.length >= 10 ? digits.slice(-10) : "";
  }
  if (!Number.isFinite(minutes) || minutes <= 0) {
    const amount = Number(
      metadata.paystack_charged_amount != null ? metadata.paystack_charged_amount
      : event.amount != null ? event.amount
      : data.amount
    );
    minutes = MINUTES_BY_PRICE[amount];
  }

  if (!deviceId || !Number.isFinite(minutes) || minutes <= 0) {
    console.error("Impossible de déterminer le compte ou les minutes :", { deviceId, minutes, metadata });
    res.status(400).send("missing or invalid metadata");
    return;
  }

  const reference =
    event.reference || data.reference ||
    event.transaction_id || data.transaction_id ||
    event.id || data.id ||
    metadata.order_id || null;

  try {
    const creditRef = db.collection("credits").doc(deviceId);

    if (reference) {
      const eventRef = db.collection("processed_payments").doc(reference);
      const already = await eventRef.get();
      if (already.exists) {
        res.status(200).send("already processed");
        return;
      }
    }

    await db.runTransaction(async (t) => {
      const doc = await t.get(creditRef);
      const current = doc.exists ? Math.max(0, Number(doc.data().minutes_remaining) || 0) : 0;
      t.set(
        creditRef,
        { minutes_remaining: current + minutes, updated_at: admin.firestore.FieldValue.serverTimestamp() },
        { merge: true }
      );
      if (reference) {
        t.set(db.collection("processed_payments").doc(reference), {
          device_id: deviceId,
          minutes_added: minutes,
          processed_at: admin.firestore.FieldValue.serverTimestamp(),
        });
      }
    });

    console.log(`Crédit ajouté : ${minutes} min pour l'appareil ${deviceId} (réf ${reference || "n/a"})`);
    res.status(200).send("ok");
  } catch (e) {
    console.error("Erreur lors du crédit :", e);
    res.status(500).send("internal error");
  }
}
