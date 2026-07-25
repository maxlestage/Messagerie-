package rs.brocolis.messagerie.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Couleurs de la marque Brocolis (mêmes valeurs que l'app iOS).
val BrocoliGreen = Color(0xFF2F9E4A)      // 47,158,74
val BrocoliGreenDark = Color(0xFF238C3E)
val BrocoliBg = Color(0xFFE8F5DB)         // 232,245,219
val BrocoliDeepGreen = Color(0xFF226030)  // 34,96,48
val BrocoliBubbleTop = Color(0xFF3DAE54)
val BrocoliBubbleBottom = Color(0xFF248C45)

private val LightColors = lightColorScheme(
    primary = BrocoliGreen,
    onPrimary = Color.White,
    primaryContainer = BrocoliBg,
    onPrimaryContainer = BrocoliDeepGreen,
    secondary = BrocoliGreenDark,
    background = Color(0xFFF7FBF1),
    surface = Color.White,
)

private val DarkColors = darkColorScheme(
    primary = BrocoliGreen,
    onPrimary = Color.White,
    primaryContainer = BrocoliGreenDark,
    secondary = Color(0xFF7CC98C),
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
