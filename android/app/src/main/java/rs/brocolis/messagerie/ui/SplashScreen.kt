package rs.brocolis.messagerie.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import rs.brocolis.messagerie.R
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.ui.theme.BrocoliDeepGreen
import rs.brocolis.messagerie.ui.theme.BrocoliGreen

/**
 * Page de GARDE + page de CHARGEMENT : le logo brocoli (repris de l'icône) sur
 * le fond vert de la marque, le nom, une accroche et un indicateur de chargement.
 * Miroir Android de Brocolis/BrocolisSplashView.swift.
 */
@Composable
fun SplashScreen() {
    var appeared by remember { mutableStateOf(false) }
    var showLoader by remember { mutableStateOf(false) }

    val scale by animateFloatAsState(if (appeared) 1f else 0.82f, tween(550), label = "scale")
    val contentAlpha by animateFloatAsState(if (appeared) 1f else 0f, tween(450), label = "alpha")
    val loaderAlpha by animateFloatAsState(if (showLoader) 1f else 0f, tween(400), label = "loader")
    val barFill by animateFloatAsState(if (showLoader) 1f else 0f, tween(1200), label = "bar")

    LaunchedEffect(Unit) {
        appeared = true
        kotlinx.coroutines.delay(500)
        showLoader = true
    }

    val bg = Brush.verticalGradient(listOf(Color_EEF8E2, Color_DCEFD0))

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(bg),
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Spacer(Modifier.weight(1f))

            Image(
                painter = painterResource(R.drawable.brocolis_logo),
                contentDescription = "Brocolis",
                modifier = Modifier
                    .size(132.dp)
                    .scale(scale)
                    .alpha(contentAlpha)
                    .clip(RoundedCornerShape(30.dp))
            )

            Spacer(Modifier.size(22.dp))

            Text(
                text = "Brocolis",
                fontSize = 40.sp,
                fontWeight = FontWeight.Bold,
                color = BrocoliDeepGreen,
                modifier = Modifier.alpha(contentAlpha)
            )
            Spacer(Modifier.size(8.dp))
            Text(
                text = loc(
                    "Messagerie chiffrée de bout en bout",
                    "End-to-end encrypted messaging",
                    "Mensajería cifrada de extremo a extremo"
                ),
                fontSize = 15.sp,
                color = BrocoliDeepGreen.copy(alpha = 0.75f),
                textAlign = TextAlign.Center,
                modifier = Modifier.alpha(contentAlpha).padding(horizontal = 32.dp)
            )

            Spacer(Modifier.weight(1f))

            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.alpha(loaderAlpha).padding(bottom = 44.dp)
            ) {
                // Barre de progression qui se remplit pendant la page de garde.
                Box(
                    Modifier
                        .width(220.dp).height(8.dp)
                        .clip(RoundedCornerShape(4.dp))
                        .background(BrocoliGreen.copy(alpha = 0.18f))
                ) {
                    Box(
                        Modifier
                            .fillMaxHeight()
                            .fillMaxWidth(barFill)
                            .clip(RoundedCornerShape(4.dp))
                            .background(Brush.horizontalGradient(listOf(BrocoliGreen, BrocoliDeepGreen)))
                    )
                }
                Spacer(Modifier.size(10.dp))
                Text(
                    text = loc("Chargement…", "Loading…", "Cargando…"),
                    fontSize = 13.sp,
                    color = BrocoliDeepGreen.copy(alpha = 0.6f)
                )
            }
        }
    }
}

private val Color_EEF8E2 = androidx.compose.ui.graphics.Color(0xFFEEF8E2)
private val Color_DCEFD0 = androidx.compose.ui.graphics.Color(0xFFDCEFD0)
