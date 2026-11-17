package app.velox.vpn.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Deep AMOLED-friendly Obsidian + Emerald/Cyan palette (saves OLED battery & looks razor-sharp)
val BgObsidian = Color(0xFF080C12)
val SurfaceCard = Color(0xFF101722)
val SurfaceElevated = Color(0xFF162030)
val SurfaceStroke = Color(0xFF223047)
val EmeraldPrimary = Color(0xFF00E5A0)
val EmeraldDim = Color(0xFF0D352B)
val CyanAccent = Color(0xFF28C4F8)
val CyanDim = Color(0xFF0E2D42)
val AmberWarn = Color(0xFFFFB74D)
val AmberDim = Color(0xFF382810)
val CoralError = Color(0xFFFF6B6B)
val TextHigh = Color(0xFFF1F5FA)
val TextMedium = Color(0xFF96A5BC)
val TextLow = Color(0xFF63738B)

private val VeloxColorScheme = darkColorScheme(
    primary = EmeraldPrimary,
    onPrimary = Color(0xFF002116),
    primaryContainer = EmeraldDim,
    onPrimaryContainer = EmeraldPrimary,
    secondary = CyanAccent,
    onSecondary = Color(0xFF001F2A),
    secondaryContainer = CyanDim,
    onSecondaryContainer = CyanAccent,
    tertiary = AmberWarn,
    background = BgObsidian,
    onBackground = TextHigh,
    surface = SurfaceCard,
    onSurface = TextHigh,
    surfaceVariant = SurfaceElevated,
    onSurfaceVariant = TextMedium,
    outline = SurfaceStroke,
    error = CoralError,
)

private val VeloxTypography = Typography(
    headlineSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 22.sp,
        lineHeight = 28.sp,
        letterSpacing = (-0.3).sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        lineHeight = 22.sp,
    ),
    titleSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
        lineHeight = 19.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 17.sp,
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp,
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 14.sp,
    ),
)

@Composable
fun VeloxTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = VeloxColorScheme,
        typography = VeloxTypography,
        content = content,
    )
}
