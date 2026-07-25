package rs.brocolis.messagerie

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeOut
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import rs.brocolis.messagerie.ui.ChatScreen
import rs.brocolis.messagerie.ui.ConversationScreen
import rs.brocolis.messagerie.ui.MessagingHomeScreen
import rs.brocolis.messagerie.ui.PairingScreen
import rs.brocolis.messagerie.ui.RootScreen
import rs.brocolis.messagerie.ui.SplashScreen
import rs.brocolis.messagerie.ui.theme.BrocolisTheme

/**
 * Activité unique (FragmentActivity pour BiometricPrompt) : héberge la navigation
 * Compose et la page de garde/chargement au démarrage.
 */
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { BrocolisTheme { BrocolisRoot() } }
    }
}

@Composable
private fun BrocolisRoot() {
    var showSplash by remember { mutableStateOf(true) }
    LaunchedEffect(Unit) {
        kotlinx.coroutines.delay(1600)
        showSplash = false
    }

    Box(Modifier.fillMaxSize()) {
        AppNavHost()
        // La page de garde couvre l'app puis s'efface en fondu.
        AnimatedVisibility(visible = showSplash, exit = fadeOut(tween(450))) {
            SplashScreen()
        }
    }
}

@Composable
private fun AppNavHost() {
    val nav = rememberNavController()
    NavHost(navController = nav, startDestination = "root") {
        composable("root") {
            RootScreen(
                onOpenMessaging = { nav.navigate("messaging") },
                onOpenConversation = { nav.navigate("conversation") },
                onOpenPairing = { nav.navigate("pairing") }
            )
        }
        composable("messaging") {
            MessagingHomeScreen(
                onOpenChat = { keyId -> nav.navigate("chat/$keyId") },
                onBack = { nav.popBackStack() }
            )
        }
        composable("chat/{keyId}") { entry ->
            ChatScreen(
                keyId = entry.arguments?.getString("keyId") ?: "",
                onBack = { nav.popBackStack() }
            )
        }
        composable("conversation") {
            ConversationScreen(onBack = { nav.popBackStack() })
        }
        composable("pairing") {
            PairingScreen(onBack = { nav.popBackStack() })
        }
    }
}
