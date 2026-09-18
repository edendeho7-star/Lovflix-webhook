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
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signatureHeader));
  } catch (e) {
    return false;
  }
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).send("Method not allowed");
    return;
  }

  const rawBody = await getRawBody(req);
  const signature = req.headers["x-kadevpay-signature"];

  if (!isValidSignature(rawBody, signature, process.env.KADEV_WEBHOOK_SECRET)) {
    console.error("Signature webhook invalide ou absente");
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

  const metadata = event.metadata || (event.data && event.data.metadata) || {};
  const deviceId = metadata.device_id;
  const minutes = Number(metadata.minutes);

  if (!deviceId || !Number.isFinite(minutes) || minutes <= 0) {
    console.error("Metadata manquante ou invalide sur le webhook :", metadata);
    res.status(400).send("missing or invalid metadata");
    return;
  }

  const reference = event.reference || (event.data && event.data.reference) || null;

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
