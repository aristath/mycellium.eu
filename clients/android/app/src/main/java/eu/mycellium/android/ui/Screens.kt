package eu.mycellium.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import eu.mycellium.android.MessengerViewModel
import eu.mycellium.android.Screen
import eu.mycellium.android.UiState
import eu.mycellium.android.OnboardingStage
import uniffi.mycellium_sdk.Contact
import uniffi.mycellium_sdk.Conversation
import uniffi.mycellium_sdk.DeliveryState
import uniffi.mycellium_sdk.Message

/**
 * Top-level router. Picks a screen from [UiState.screen], overlays a busy
 * spinner and an error dialog, and wires ON_RESUME to a foreground `sync()`.
 */
@Composable
fun AppRoot(state: UiState, vm: MessengerViewModel, modifier: Modifier = Modifier) {
    // Foreground receive: sync when the app resumes.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) vm.onResume()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    Column(modifier = modifier.fillMaxSize()) {
        when (state.screen) {
            Screen.LOADING -> LoadingScreen()
            Screen.SETUP -> SetupScreen(state, vm)
            Screen.ONBOARDING -> OnboardingScreen(state, vm)
            Screen.CONVERSATIONS -> ConversationsScreen(state, vm)
            Screen.THREAD -> ThreadScreen(state, vm)
            Screen.CONTACTS -> ContactsScreen(state, vm)
        }
    }

    if (state.busy && state.screen != Screen.LOADING) {
        Surface(color = MaterialTheme.colorScheme.scrim.copy(alpha = 0.15f)) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) { CircularProgressIndicator() }
        }
    }

    state.error?.let { message ->
        AlertDialog(
            onDismissRequest = vm::dismissError,
            confirmButton = { TextButton(onClick = vm::dismissError) { Text("Dismiss") } },
            title = { Text("Notice") },
            text = { Text(message) },
        )
    }

    state.safetyNumber?.let { (peer, number) ->
        AlertDialog(
            onDismissRequest = vm::clearSafetyNumber,
            confirmButton = { TextButton(onClick = vm::clearSafetyNumber) { Text("Close") } },
            title = { Text("Safety number — $peer") },
            text = { Text("Compare this out of band with $peer:\n\n$number") },
        )
    }
}

@Composable
private fun LoadingScreen() {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) { CircularProgressIndicator() }
}

// ---- Setup --------------------------------------------------------------

@Composable
private fun SetupScreen(state: UiState, vm: MessengerViewModel) {
    var dir by remember { mutableStateOf(state.dirUrl) }
    var queue by remember { mutableStateOf(state.queueUrl) }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Server setup", style = MaterialTheme.typography.headlineSmall)
        OutlinedTextField(
            value = dir, onValueChange = { dir = it },
            label = { Text("Directory URL") }, singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = queue, onValueChange = { queue = it },
            label = { Text("Queue URL") }, singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(onClick = { vm.saveSetup(dir, queue) }, modifier = Modifier.fillMaxWidth()) {
            Text("Continue")
        }
    }
}

// ---- Onboarding ---------------------------------------------------------

@Composable
private fun OnboardingScreen(state: UiState, vm: MessengerViewModel) {
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Create your account", style = MaterialTheme.typography.headlineSmall)
        when (state.onboarding.stage) {
            OnboardingStage.DETAILS -> {
                OutlinedTextField(
                    value = state.onboarding.handle,
                    onValueChange = { vm.updateOnboarding(handle = it) },
                    label = { Text("Handle") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = state.onboarding.email,
                    onValueChange = { vm.updateOnboarding(email = it) },
                    label = { Text("Email") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = { vm.startEmailVerification() },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Send verification code") }
            }
            OnboardingStage.CODE -> {
                var code by remember { mutableStateOf("") }
                Text("Enter the code sent to ${state.onboarding.email}.")
                state.onboarding.devCode?.let {
                    Text(
                        "Dev mode code: $it",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
                OutlinedTextField(
                    value = code, onValueChange = { code = it },
                    label = { Text("Verification code") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = { vm.confirmAndRegister(code) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Confirm & register") }
            }
        }
    }
}

// ---- Conversations ------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConversationsScreen(state: UiState, vm: MessengerViewModel) {
    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("Conversations") },
            actions = {
                TextButton(onClick = vm::syncNow) { Text("Sync") }
                TextButton(onClick = vm::openContacts) { Text("Contacts") }
            },
        )
        if (state.conversations.isEmpty()) {
            Column(
                Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) { Text("No conversations yet.") }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(state.conversations, key = { it.peer }) { convo ->
                    ConversationRow(convo) { vm.openThread(convo.peer) }
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun ConversationRow(convo: Conversation, onClick: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(16.dp),
    ) {
        val title = convo.displayName.ifEmpty { convo.peer }
        Text(title, style = MaterialTheme.typography.titleMedium)
        Text(
            convo.lastPreview,
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

// ---- Thread -------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ThreadScreen(state: UiState, vm: MessengerViewModel) {
    var draft by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text(state.openPeer ?: "Thread") },
            navigationIcon = {
                TextButton(onClick = vm::back) { Text("Back") }
            },
            actions = {
                state.openPeer?.let { peer ->
                    TextButton(onClick = { vm.showSafetyNumber(peer) }) { Text("Verify") }
                }
            },
        )
        LazyColumn(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 12.dp)) {
            items(state.thread, key = { it.id }) { msg -> MessageRow(msg) }
        }
        HorizontalDivider()
        Row(
            Modifier.fillMaxWidth().padding(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = draft, onValueChange = { draft = it },
                label = { Text("Message") },
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                vm.sendText(draft)
                draft = ""
            }) { Text("Send") }
        }
    }
}

@Composable
private fun MessageRow(msg: Message) {
    val align = if (msg.fromMe) Alignment.End else Alignment.Start
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalAlignment = align) {
        Text(msg.text, style = MaterialTheme.typography.bodyLarge)
        if (msg.fromMe) {
            Text(deliveryLabel(msg.delivery), style = MaterialTheme.typography.labelSmall)
        }
    }
}

private fun deliveryLabel(state: DeliveryState): String = when (state) {
    DeliveryState.SENT -> "Sent"
    DeliveryState.QUEUED -> "Queued…"
    DeliveryState.DELIVERED -> "Delivered"
    DeliveryState.FAILED -> "Failed"
}

// ---- Contacts -----------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ContactsScreen(state: UiState, vm: MessengerViewModel) {
    var nickname by remember { mutableStateOf("") }
    var handle by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("Contacts") },
            navigationIcon = {
                TextButton(onClick = vm::back) { Text("Back") }
            },
        )
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = nickname, onValueChange = { nickname = it },
                label = { Text("Nickname") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = handle, onValueChange = { handle = it },
                label = { Text("Handle") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = {
                vm.addContact(nickname, handle)
                nickname = ""; handle = ""
            }, modifier = Modifier.fillMaxWidth()) { Text("Add contact") }
        }
        HorizontalDivider()
        LazyColumn(Modifier.fillMaxSize()) {
            items(state.contacts, key = { it.handle }) { contact ->
                ContactRow(contact) { vm.showSafetyNumber(contact.handle) }
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun ContactRow(contact: Contact, onVerify: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(contact.nickname, style = MaterialTheme.typography.titleMedium)
            Text(
                "${contact.handle} · ${contact.trust.name.lowercase()}",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        TextButton(onClick = onVerify) { Text("Safety number") }
    }
}
