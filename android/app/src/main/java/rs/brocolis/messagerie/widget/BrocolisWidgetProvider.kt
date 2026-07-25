package rs.brocolis.messagerie.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import rs.brocolis.messagerie.MainActivity
import rs.brocolis.messagerie.R
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.store.BrocolisKeyStore

/**
 * Widget d'écran d'accueil : montre d'un coup d'œil si Brocolis est actif et le
 * nombre de clés. Équivalent (RemoteViews) du widget iOS `BrocolisStatusWidget`.
 * Tap → ouvre l'app.
 */
class BrocolisWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        // Le store est déjà initialisé par BrocolisApplication ; on s'en assure.
        BrocolisKeyStore.init(context)
        for (id in ids) manager.updateAppWidget(id, buildViews(context))
    }

    companion object {
        /** Force le rafraîchissement de tous les widgets (à appeler après un
         *  changement d'état, comme `WidgetCenter.reloadAllTimelines()` sur iOS). */
        fun refresh(context: Context) {
            val manager = AppWidgetManager.getInstance(context)
            val ids = manager.getAppWidgetIds(ComponentName(context, BrocolisWidgetProvider::class.java))
            for (id in ids) manager.updateAppWidget(id, buildViews(context))
        }

        private fun buildViews(context: Context): RemoteViews {
            val active = BrocolisKeyStore.isActive
            val count = BrocolisKeyStore.keys.size
            val views = RemoteViews(context.packageName, R.layout.widget_status)
            views.setTextViewText(
                R.id.widget_status,
                if (active) loc("Actif", "Active", "Activo") else loc("En pause", "Paused", "En pausa")
            )
            views.setTextViewText(
                R.id.widget_keys,
                loc("$count clé(s)", "$count key(s)", "$count clave(s)")
            )
            val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            val pending = PendingIntent.getActivity(
                context, 0, Intent(context, MainActivity::class.java), flags
            )
            views.setOnClickPendingIntent(R.id.widget_root, pending)
            return views
        }
    }
}
