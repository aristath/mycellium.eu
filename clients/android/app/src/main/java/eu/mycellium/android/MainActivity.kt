package eu.mycellium.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.mycellium.android.ui.AppRoot
import eu.mycellium.android.ui.theme.MyceliumTheme

/**
 * The single Activity. Hosts all Compose screens; the [MessengerViewModel] owns
 * every SDK interaction. Foreground `sync()` on resume is wired inside [AppRoot]
 * via a lifecycle observer on the same ViewModel instance.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyceliumTheme {
                val vm: MessengerViewModel = viewModel()
                val state by vm.uiState.collectAsStateWithLifecycle()
                Scaffold(modifier = Modifier.fillMaxSize()) { inner ->
                    AppRoot(
                        state = state,
                        vm = vm,
                        modifier = Modifier.padding(inner),
                    )
                }
            }
        }
    }
}
