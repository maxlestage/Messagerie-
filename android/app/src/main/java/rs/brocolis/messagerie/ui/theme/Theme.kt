@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package rs.brocolis.messagerie.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TopAppBarColors
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Couleurs de la marque Brocolis (mêmes valeurs que l'app iOS).
val BrocoliGreen = Color(0xFF2F9E4A)      // 47,158,74
val BrocoliGreenDark = Color(0xFF238C3E)
val BrocoliBg = Color(0xFFE8F5DB)         // 232,245,219 — LE fond Brocolis
val BrocoliDeepGreen = Color(0xFF226030)  // 34,96,48
val BrocoliBubbleTop = Color(0xFF3DAE54)
val BrocoliBubbleBottom = Color(0xFF248C45)

// Fond Brocolis partout : `background` = vert pâle de la marque ; les cartes
// restent blanches (`surface`) pour le contraste. Les Scaffold utilisent
// `background` par défaut, donc tous les écrans deviennent verts.
private val LightColors = lightColorScheme(
    primary = BrocoliGreen,
    onPrimary = Color.White,
    primaryContainer = BrocoliBg,
    onPrimaryContainer = BrocoliDeepGreen,
    secondary = BrocoliGreenDark,
    background = BrocoliBg,
    onBackground = BrocoliDeepGreen,
    // Cartes un cran PLUS FONCÉES que le fond (vert doux au lieu de blanc pur).
    surface = Color(0xFFDCEFD0),
    onSurface = Color(0xFF16241C),
    surfaceVariant = Color(0xFFCFE7BE),   // bulles reçues, encore un peu plus vertes
    onSurfaceVariant = Color(0xFF3B5443),
)

private val DarkColors = darkColorScheme(
    primary = BrocoliGreen,
    onPrimary = Color.White,
    primaryContainer = BrocoliGreenDark,
    secondary = Color(0xFF7CC98C),
    background = Color(0xFF0F2818),        // vert Brocolis foncé
    onBackground = BrocoliBg,
    surface = Color(0xFF15311F),
    onSurface = Color(0xFFE8F5DB),
)

@Composable
fun BrocolisTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content
    )
}

/**
 * Barres du haut TRANSPARENTES : elles laissent voir le fond Brocolis du
 * Scaffold, pour que le vert couvre tout l'écran (barre comprise).
 */
@Composable
fun brocolisTopBarColors(): TopAppBarColors = TopAppBarDefaults.topAppBarColors(
    containerColor = Color.Transparent,
    scrolledContainerColor = Color.Transparent,
    titleContentColor = BrocoliDeepGreen,
    navigationIconContentColor = BrocoliGreen,
    actionIconContentColor = BrocoliGreen,
)
