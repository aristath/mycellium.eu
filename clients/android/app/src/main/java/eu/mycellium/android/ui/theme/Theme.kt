package eu.mycellium.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.Typography
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

val Canvas = Color(0xFF0E1219)
val Sidebar = Color(0xFF121720)
val Surface = Color(0xFF191F2B)
val SurfaceRaised = Color(0xFF202836)
val Border = Color(0xFF303A4A)
val Text = Color(0xFFEFF3F0)
val Muted = Color(0xFF919CAA)
val Moss = Color(0xFF76B89A)
val Spore = Color(0xFFE2B769)
val Danger = Color(0xFFE87979)

private val Colors = darkColorScheme(
    primary = Moss,
    onPrimary = Canvas,
    primaryContainer = Color(0xFF243D34),
    onPrimaryContainer = Text,
    secondary = Spore,
    onSecondary = Canvas,
    background = Canvas,
    onBackground = Text,
    surface = Surface,
    onSurface = Text,
    surfaceVariant = SurfaceRaised,
    onSurfaceVariant = Muted,
    outline = Border,
    error = Danger,
    onError = Canvas,
)

private val Type = Typography(
    displaySmall = androidx.compose.ui.text.TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Light,
        fontSize = 38.sp,
        lineHeight = 44.sp,
        letterSpacing = (-0.6).sp,
    ),
    headlineMedium = androidx.compose.ui.text.TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Light,
        fontSize = 28.sp,
        lineHeight = 34.sp,
    ),
    titleLarge = androidx.compose.ui.text.TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 21.sp,
        lineHeight = 27.sp,
    ),
    titleMedium = androidx.compose.ui.text.TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 16.sp,
        lineHeight = 22.sp,
    ),
    bodyLarge = androidx.compose.ui.text.TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyMedium = androidx.compose.ui.text.TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    labelSmall = androidx.compose.ui.text.TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.5.sp,
    ),
)

@Composable
fun MycelliumTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = Colors, typography = Type, content = content)
}
