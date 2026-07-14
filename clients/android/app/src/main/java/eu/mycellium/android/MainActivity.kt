package eu.mycellium.android

import android.graphics.Color
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.SystemBarStyle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import eu.mycellium.android.ui.MycelliumRoot
import eu.mycellium.android.ui.theme.MycelliumTheme

class MainActivity : ComponentActivity() {
    private val model: MessengerViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
        )
        setContent {
            MycelliumTheme {
                MycelliumRoot(model)
            }
        }
        handleLoginLink(intent?.data)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleLoginLink(intent.data)
        intent.data = null
        setIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        model.onForeground()
    }

    private fun handleLoginLink(uri: Uri?) {
        if (uri?.scheme == "mycellium" && uri.host == "login") {
            model.confirmLoginLink(uri.toString())
            intent?.data = null
        }
    }
}
