package com.siteguard.app.core

import android.content.Context

/** Persists [AuthorizationBudget] counters (ids, counts and timestamps only) so a process restart cannot reset them. */
class SharedPrefsAuthorizationBudgetStore(context: Context) : AuthorizationBudget.Store {
    private val prefs = context.applicationContext.getSharedPreferences("siteguard_authorization_budget", Context.MODE_PRIVATE)
    override fun load(): String? = prefs.getString("state", null)
    override fun save(json: String) { prefs.edit().putString("state", json).apply() }
}
