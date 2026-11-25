package com.siteguard.app.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Encrypted rolling baseline store used to compare passive observations across runs. */
class LocalAssetDriftStore(context: Context, private val maxAssets: Int = 50) {
    private val prefs = context.getSharedPreferences("siteguard_asset_drift_v1", Context.MODE_PRIVATE)
    private val cipher = LocalDataCipher("siteguard.asset.drift.v1")
    private val key = "asset_snapshots_encrypted"

    init { require(maxAssets in 1..200) }

    @Synchronized
    fun compareAndUpdate(current: AssetSnapshotV1): AssetDriftV1? {
        require(current.assetId.isNotBlank() && current.assetId.length <= 253)
        require(current.canonicalFacts.size <= 200)
        val snapshots = readSnapshots().toMutableMap()
        val previous = snapshots[current.assetId]
        val drift = previous?.let { AssetDriftDetectorV1.compare(it, current) }
        snapshots[current.assetId] = current
        val compact = snapshots.entries.sortedByDescending { it.value.capturedAtEpochMs }.take(maxAssets).associate { it.toPair() }
        persist(compact)
        return drift
    }

    @Synchronized fun latest(assetId: String): AssetSnapshotV1? = readSnapshots()[assetId]
    @Synchronized fun clear() { prefs.edit().remove(key).apply() }

    private fun persist(snapshots: Map<String, AssetSnapshotV1>) {
        val json = JSONObject().put("schema", 1).put("snapshots", JSONArray().apply {
            snapshots.values.forEach { snapshot -> put(JSONObject().apply {
                put("asset_id", snapshot.assetId); put("captured_at", snapshot.capturedAtEpochMs)
                put("facts", JSONObject(snapshot.canonicalFacts))
            }) }
        }).toString()
        require(json.length <= 1_000_000) { "حجم baseline تغییرات از یک مگابایت بیشتر است." }
        prefs.edit().putString(key, cipher.encrypt(json)).apply()
    }

    private fun readSnapshots(): Map<String, AssetSnapshotV1> {
        val encrypted = prefs.getString(key, null) ?: return emptyMap()
        val plain = cipher.decrypt(encrypted) ?: return emptyMap()
        return runCatching {
            val root = JSONObject(plain)
            require(root.optInt("schema") == 1)
            val array = root.optJSONArray("snapshots") ?: JSONArray()
            buildMap {
                for (index in 0 until array.length()) {
                    val row = array.optJSONObject(index) ?: continue
                    val factsJson = row.optJSONObject("facts") ?: JSONObject()
                    val facts = buildMap {
                        val keys = factsJson.keys()
                        while (keys.hasNext()) {
                            val factKey = keys.next()
                            put(factKey, factsJson.optString(factKey).take(2_000))
                        }
                    }
                    val id = row.optString("asset_id")
                    if (id.isNotBlank()) put(id, AssetSnapshotV1(id, facts, row.optLong("captured_at")))
                }
            }
        }.getOrDefault(emptyMap())
    }
}
